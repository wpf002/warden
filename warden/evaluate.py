"""Eval harness. The yardstick every later phase is measured against.

A labeled case is a directory:

    data/eval/<case>/events.jsonl     raw log lines, same shapes ingest accepts
    data/eval/<case>/expected.json    what should fire and what an analyst would do

`expected.json`:

    {
      "name": "brute force on the VPN gateway",
      "alerts": [
        {"rule": "brute_force",
         "match": {"source_ip": "203.0.113.42"},
         "label": "true_positive",
         "expect_actions": {"block_ip": "execute", "lock_user": "approve"}}
      ]
    }

Reported metrics:
  * detection precision / recall / F1, per rule and overall
  * risk-score calibration: Brier score of risk/100 against the TP/FP label
  * action-decision agreement: guardrail verdict vs the analyst's expected verdict
  * retrieval hit rate: did the detection's own playbook land in the top 3 chunks

Nothing here executes an action. Guardrails are evaluated, not applied.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from . import guardrails
from .config import settings
from .detect import detect
from .ingest import load_file
from .knowledge import KnowledgeBase
from .llm import get_analyzer
from .models import Alert

MATCH_KEYS = ("source_ip", "user", "host", "geo")


# ---------------------------------------------------------------- fixtures
@dataclass
class ExpectedAlert:
    rule: str
    match: dict = field(default_factory=dict)
    label: str | None = None                 # true_positive | false_positive
    expect_actions: dict[str, str] = field(default_factory=dict)
    risk_min: int | None = None
    risk_max: int | None = None
    note: str = ""

    def key(self) -> str:
        return f"{self.rule}|" + "|".join(f"{k}={self.match[k]}" for k in sorted(self.match))

    def matches(self, alert: Alert) -> bool:
        if alert.rule != self.rule:
            return False
        for k, v in self.match.items():
            if k == "source_ip" and v not in alert.all_ips():
                return False
            if k == "user" and v not in alert.users:
                return False
            if k == "host" and v not in alert.hosts:
                return False
            if k == "geo" and v != alert.geo:
                return False
            if k not in MATCH_KEYS and str(alert.detail.get(k)) != str(v):
                return False
        return True


@dataclass
class ExpectedIncident:
    rules: list[str]
    label: str | None = None
    expect_actions: dict[str, str] = field(default_factory=dict)
    risk_min: int | None = None
    risk_max: int | None = None
    note: str = ""

    def key(self) -> str:
        return "incident:" + "+".join(sorted(self.rules))


@dataclass
class EvalCase:
    name: str
    events_file: Path
    expected: list[ExpectedAlert]
    description: str = ""
    incidents: list[ExpectedIncident] = field(default_factory=list)
    history_file: Path | None = None
    iocs: list[dict] = field(default_factory=list)       # intel table contents for this case

    def ioc_lookup(self, values) -> dict:
        vals = set(values)
        out: dict[str, list[dict]] = {}
        for i in self.iocs:
            if i["value"] in vals:
                out.setdefault(i["value"], []).append(i)
        return out

    @classmethod
    def load(cls, d: Path) -> "EvalCase":
        spec = json.loads((d / "expected.json").read_text())
        events = (d / spec.get("events", "events.jsonl")).resolve()
        if not events.exists():
            raise FileNotFoundError(f"{d.name}: events file {events} missing"
                                    + (" - run scripts/fetch_real_samples.py" if "real" in str(events) else ""))
        hist = (d / spec["history"]).resolve() if spec.get("history") else None
        return cls(
            name=spec.get("name", d.name),
            description=spec.get("description", ""),
            events_file=events,
            expected=[ExpectedAlert(**e) for e in spec.get("alerts", [])],
            incidents=[ExpectedIncident(**i) for i in spec.get("incidents", [])],
            history_file=hist,
            iocs=spec.get("iocs", []),
        )


def discover(root: Path | None = None) -> list[EvalCase]:
    root = root or settings.eval_dir
    if not root.exists():
        return []
    return [EvalCase.load(d) for d in sorted(root.iterdir()) if (d / "expected.json").exists()]


# ---------------------------------------------------------------- scoring
@dataclass
class Counts:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else 0.0


@dataclass
class Report:
    per_rule: dict[str, Counts] = field(default_factory=dict)
    brier_terms: list[float] = field(default_factory=list)
    action_agree: int = 0
    action_total: int = 0
    unexpected_executes: list[str] = field(default_factory=list)
    retrieval_hits: int = 0
    retrieval_total: int = 0
    risk_violations: list[str] = field(default_factory=list)
    misses: list[str] = field(default_factory=list)
    spurious: list[str] = field(default_factory=list)
    disagreements: list[str] = field(default_factory=list)
    incidents_expected: int = 0
    incidents_merged: int = 0
    unmerged: list[str] = field(default_factory=list)
    cost_usd: float = 0.0
    llm_calls: int = 0

    def counts(self, rule: str) -> Counts:
        return self.per_rule.setdefault(rule, Counts())

    @property
    def overall(self) -> Counts:
        t = Counts()
        for c in self.per_rule.values():
            t.tp += c.tp
            t.fp += c.fp
            t.fn += c.fn
        return t

    @property
    def brier(self) -> float | None:
        """Mean squared error of risk/100 read as P(true positive). Lower is better; 0.25 = coin flip."""
        return sum(self.brier_terms) / len(self.brier_terms) if self.brier_terms else None

    @property
    def action_agreement(self) -> float | None:
        return self.action_agree / self.action_total if self.action_total else None

    @property
    def merge_rate(self) -> float | None:
        return self.incidents_merged / self.incidents_expected if self.incidents_expected else None

    @property
    def retrieval_hit_rate(self) -> float | None:
        return self.retrieval_hits / self.retrieval_total if self.retrieval_total else None

    def to_dict(self) -> dict:
        return {
            "per_rule": {r: {"tp": c.tp, "fp": c.fp, "fn": c.fn, "precision": round(c.precision, 4),
                             "recall": round(c.recall, 4), "f1": round(c.f1, 4)}
                         for r, c in sorted(self.per_rule.items())},
            "overall": {"tp": self.overall.tp, "fp": self.overall.fp, "fn": self.overall.fn,
                        "precision": round(self.overall.precision, 4), "recall": round(self.overall.recall, 4),
                        "f1": round(self.overall.f1, 4)},
            "brier": round(self.brier, 4) if self.brier is not None else None,
            "action_agreement": round(self.action_agreement, 4) if self.action_agreement is not None else None,
            "retrieval_hit_rate": round(self.retrieval_hit_rate, 4) if self.retrieval_hit_rate is not None else None,
            "incident_merge_rate": round(self.merge_rate, 4) if self.merge_rate is not None else None,
            "llm_calls": self.llm_calls, "cost_usd": round(self.cost_usd, 4),
            "unexpected_executes": self.unexpected_executes,
            "unmerged": self.unmerged,
            "disagreements": self.disagreements,
            "risk_violations": self.risk_violations,
            "missed": self.misses,
            "spurious": self.spurious,
        }


def run(cases: list[EvalCase] | None = None, kb: KnowledgeBase | None = None, analyzer=None,
        with_llm: bool = True, only: list[str] | None = None, k: int = 5) -> Report:
    from .correlate import correlate

    cases = cases if cases is not None else discover()
    rep = Report()
    if with_llm:
        if kb is None:   # a caller-supplied KB is the caller's to keep in sync
            kb = KnowledgeBase()
            kb.sync()
        analyzer = analyzer or get_analyzer()

    for case in cases:
        prior = load_file(case.history_file) if case.history_file else None
        alerts = detect(load_file(case.events_file), only=only, prior=prior, ioc_lookup=case.ioc_lookup)
        subjects = correlate(alerts)
        owner = {m.id: s for s in subjects for m in (s.members or [s])}
        unmatched = list(alerts)
        matched: dict[str, tuple[ExpectedAlert, Alert]] = {}

        # ---- detection
        for exp in case.expected:
            hit = next((a for a in unmatched if exp.matches(a)), None)
            c = rep.counts(exp.rule)
            if hit is None:
                c.fn += 1
                rep.misses.append(f"{case.name}: {exp.key()}")
                continue
            c.tp += 1
            unmatched.remove(hit)
            matched[hit.id] = (exp, hit)
        for a in unmatched:
            rep.counts(a.rule).fp += 1
            rep.spurious.append(f"{case.name}: {a.rule} {a.source_ip or ','.join(a.users)}")

        # ---- correlation
        inc_subject: dict[int, Alert] = {}
        for n, ei in enumerate(case.incidents):
            rep.incidents_expected += 1
            hit = next((s for s in subjects if s.is_incident and set(ei.rules) <= set(s.rules())), None)
            if hit:
                rep.incidents_merged += 1
                inc_subject[n] = hit
            else:
                got = sorted({s.id: s.rules() for s in subjects}.values(), key=len, reverse=True)[:3]
                rep.unmerged.append(f"{case.name}: wanted {'+'.join(ei.rules)}, got {got}")

        if not with_llm:
            continue

        # ---- analysis, once per subject that carries a labeled expectation
        judged: dict[str, tuple] = {}
        for n, sub in inc_subject.items():
            ei = case.incidents[n]
            judged[sub.id] = (sub, ei.label, ei.expect_actions, ei.risk_min, ei.risk_max, ei.key())
        for aid, (exp, alert) in matched.items():
            sub = owner[aid]
            if sub.id in judged:
                continue
            if sub.is_incident:
                # an incident nobody wrote an expectation for: score it on its members' labels only
                labels = [matched[m.id][0].label for m in sub.members if m.id in matched]
                label = "true_positive" if "true_positive" in labels else (labels[0] if labels else None)
                judged[sub.id] = (sub, label, {}, None, None, f"incident:{'+'.join(sub.rules())}")
            else:
                judged[sub.id] = (sub, exp.label, exp.expect_actions, exp.risk_min, exp.risk_max, exp.key())
        for sub, label, acts, rmin, rmax, key in judged.values():
            _score_subject(rep, case, sub, label, acts, rmin, rmax, key, kb, analyzer, k)

    return rep


def _score_subject(rep: Report, case: EvalCase, sub: Alert, label, expect_actions: dict, risk_min, risk_max,
                   key: str, kb: KnowledgeBase, analyzer, k: int) -> None:
    docs = kb.retrieve_for_alert(sub, k=k)
    if sub.playbooks():
        rep.retrieval_total += 1
        rep.retrieval_hits += any(d["doc"] in sub.playbooks() for d in docs[:3])

    analysis = analyzer.analyze(sub, docs)
    rep.llm_calls += 1
    rep.cost_usd += (getattr(analyzer, "last_usage", {}) or {}).get("cost_usd") or 0.0

    if label in ("true_positive", "false_positive"):
        y = 1.0 if label == "true_positive" else 0.0
        rep.brier_terms.append((analysis.risk_score / 100.0 - y) ** 2)
    if risk_min is not None and analysis.risk_score < risk_min:
        rep.risk_violations.append(f"{case.name}: {key} risk {analysis.risk_score} < {risk_min}")
    if risk_max is not None and analysis.risk_score > risk_max:
        rep.risk_violations.append(f"{case.name}: {key} risk {analysis.risk_score} > {risk_max}")

    verdicts: dict[str, str] = {}
    for d in guardrails.evaluate(sub, analysis):
        # the most permissive outcome per action type is what the analyst would have seen happen
        rank = {"deny": 0, "approve": 1, "execute": 2}
        prev = verdicts.get(d.action.action)
        if prev is None or rank[d.verdict] > rank[prev]:
            verdicts[d.action.action] = d.verdict
    for action, want in expect_actions.items():
        rep.action_total += 1
        got = verdicts.get(action, "absent")
        rep.action_agree += got == want
        if got != want:
            rep.disagreements.append(f"{case.name}: {key} {action} wanted {want}, got {got}")
    for action, got in verdicts.items():
        if got == "execute" and action not in expect_actions and expect_actions:
            rep.unexpected_executes.append(f"{case.name}: {key} executed unexpected {action}")


# ---------------------------------------------------------------- output
def format_report(rep: Report, cases: list[EvalCase]) -> str:
    def pct(x: float | None) -> str:
        return "  n/a" if x is None else f"{x:5.3f}"

    lines = [f"cases: {len(cases)}  ({', '.join(c.name for c in cases)})", ""]
    lines.append(f"{'detection':<22}{'tp':>4}{'fp':>4}{'fn':>4}{'prec':>8}{'recall':>8}{'f1':>8}")
    lines.append("-" * 58)
    for rule, c in sorted(rep.per_rule.items()):
        lines.append(f"{rule:<22}{c.tp:>4}{c.fp:>4}{c.fn:>4}{c.precision:>8.3f}{c.recall:>8.3f}{c.f1:>8.3f}")
    o = rep.overall
    lines.append("-" * 58)
    lines.append(f"{'ALL':<22}{o.tp:>4}{o.fp:>4}{o.fn:>4}{o.precision:>8.3f}{o.recall:>8.3f}{o.f1:>8.3f}")
    lines += [
        "",
        f"risk calibration (Brier, lower better)  {pct(rep.brier)}   [0.25 = uninformative]",
        f"action agreement with analyst           {pct(rep.action_agreement)}   ({rep.action_agree}/{rep.action_total})",
        f"retrieval hit rate (playbook in top 3)  {pct(rep.retrieval_hit_rate)}   ({rep.retrieval_hits}/{rep.retrieval_total})",
        f"incidents merged as one                 {pct(rep.merge_rate)}   ({rep.incidents_merged}/{rep.incidents_expected})",
    ]
    if rep.llm_calls:
        lines.append(f"model calls {rep.llm_calls}, cost ${rep.cost_usd:.4f}")
    for label, items in (("MISSED", rep.misses), ("SPURIOUS", rep.spurious),
                         ("UNEXPECTED EXECUTE", rep.unexpected_executes), ("RISK", rep.risk_violations),
                         ("UNMERGED", rep.unmerged), ("DISAGREE", rep.disagreements)):
        for it in items:
            lines.append(f"  {label:<20} {it}")
    return "\n".join(lines)
