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
class EvalCase:
    name: str
    events_file: Path
    expected: list[ExpectedAlert]
    description: str = ""

    @classmethod
    def load(cls, d: Path) -> "EvalCase":
        spec = json.loads((d / "expected.json").read_text())
        events = (d / spec.get("events", "events.jsonl")).resolve()
        if not events.exists():
            raise FileNotFoundError(f"{d.name}: events file {events} missing"
                                    + (" - run scripts/fetch_real_samples.py" if "real" in str(events) else ""))
        return cls(
            name=spec.get("name", d.name),
            description=spec.get("description", ""),
            events_file=events,
            expected=[ExpectedAlert(**e) for e in spec.get("alerts", [])],
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
            "unexpected_executes": self.unexpected_executes,
            "risk_violations": self.risk_violations,
            "missed": self.misses,
            "spurious": self.spurious,
        }


def run(cases: list[EvalCase] | None = None, kb: KnowledgeBase | None = None, analyzer=None,
        with_llm: bool = True, only: list[str] | None = None, k: int = 5) -> Report:
    cases = cases if cases is not None else discover()
    rep = Report()
    if with_llm:
        kb = kb or KnowledgeBase()
        if kb.col.count() == 0:
            kb.index_dir()
        analyzer = analyzer or get_analyzer()

    for case in cases:
        alerts = detect(load_file(case.events_file), only=only)
        unmatched = list(alerts)

        for exp in case.expected:
            hit = next((a for a in unmatched if exp.matches(a)), None)
            c = rep.counts(exp.rule)
            if hit is None:
                c.fn += 1
                rep.misses.append(f"{case.name}: {exp.key()}")
                continue
            c.tp += 1
            unmatched.remove(hit)
            if with_llm:
                _score_llm(rep, case, exp, hit, kb, analyzer, k)

        for a in unmatched:
            rep.counts(a.rule).fp += 1
            rep.spurious.append(f"{case.name}: {a.rule} {a.source_ip or ','.join(a.users)}")

    return rep


def _score_llm(rep: Report, case: EvalCase, exp: ExpectedAlert, alert: Alert,
               kb: KnowledgeBase, analyzer, k: int) -> None:
    docs = kb.retrieve_for_alert(alert, k=k)
    if alert.playbook:
        rep.retrieval_total += 1
        rep.retrieval_hits += any(d["doc"] == alert.playbook for d in docs[:3])

    analysis = analyzer.analyze(alert, docs)

    if exp.label in ("true_positive", "false_positive"):
        y = 1.0 if exp.label == "true_positive" else 0.0
        rep.brier_terms.append((analysis.risk_score / 100.0 - y) ** 2)
    if exp.risk_min is not None and analysis.risk_score < exp.risk_min:
        rep.risk_violations.append(f"{case.name}: {exp.key()} risk {analysis.risk_score} < {exp.risk_min}")
    if exp.risk_max is not None and analysis.risk_score > exp.risk_max:
        rep.risk_violations.append(f"{case.name}: {exp.key()} risk {analysis.risk_score} > {exp.risk_max}")

    verdicts: dict[str, str] = {}
    for d in guardrails.evaluate(alert, analysis):
        verdicts.setdefault(d.action.action, d.verdict)   # first verdict per action type
    for action, want in exp.expect_actions.items():
        rep.action_total += 1
        rep.action_agree += verdicts.get(action, "absent") == want
    for action, got in verdicts.items():
        if got == "execute" and action not in exp.expect_actions:
            rep.unexpected_executes.append(f"{case.name}: {exp.key()} executed unexpected {action}")


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
    ]
    for label, items in (("MISSED", rep.misses), ("SPURIOUS", rep.spurious),
                         ("UNEXPECTED EXECUTE", rep.unexpected_executes), ("RISK", rep.risk_violations)):
        for it in items:
            lines.append(f"  {label:<20} {it}")
    return "\n".join(lines)
