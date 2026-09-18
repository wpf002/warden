"""Detection health: how often each rule fires, how often analysts call it a false
positive, and how that is trending. Feeds three places:

  * the dashboard's detection-health view
  * the analysis prompt, as the rule's track record (a prior the model can weigh)
  * guardrails, which raise a noisy rule's auto-execute threshold (policy in code)
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from . import db
from .config import settings

FP_REASONS = {
    "known_scanner": "authorised scanner or pentest",
    "change_window": "approved change inside a change window",
    "service_account": "service account behaving as designed",
    "travel": "user confirmed travel or VPN",
    "test_activity": "test or lab activity",
    "misconfiguration": "misconfigured system, not an attacker",
    "duplicate": "duplicate of another case",
    "other": "other (see note)",
}


@dataclass
class RuleStats:
    rule: str
    fired: int = 0
    tp: int = 0
    fp: int = 0
    open: int = 0
    last_fired: datetime | None = None
    fp_reasons: dict[str, int] = field(default_factory=dict)
    weekly: list[dict] = field(default_factory=list)   # [{week, fired, tp, fp}], oldest first

    @property
    def verdicts(self) -> int:
        return self.tp + self.fp

    @property
    def fp_rate(self) -> float | None:
        return self.fp / self.verdicts if self.verdicts else None

    def as_prior(self) -> dict:
        return {"rule": self.rule, "fired_30d": self.fired, "analyst_verdicts_30d": self.verdicts,
                "false_positive_rate_30d": round(self.fp_rate, 2) if self.fp_rate is not None else None,
                "top_false_positive_reasons": sorted(self.fp_reasons, key=lambda r: -self.fp_reasons[r])[:3]}


def detection_stats(store, days: int = 30, weeks: int = 8) -> dict[str, RuleStats]:
    """Per-rule stats over incidents too: an incident's verdict counts for every member rule."""
    now = datetime.now(timezone.utc)
    since = now - timedelta(days=max(days, weeks * 7))
    # windowed on when the case was last touched (created or given a verdict), not on event time
    q = select(db.cases.c.doc, db.cases.c.updated).where(db.cases.c.tenant == store.tenant, db.cases.c.updated >= since)
    out: dict[str, RuleStats] = {}
    buckets: dict[str, dict[int, dict]] = defaultdict(lambda: defaultdict(lambda: {"fired": 0, "tp": 0, "fp": 0}))
    with store.engine.connect() as c:
        for doc, ts in c.execute(q):
            ts = ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
            alert = doc["alert"]
            rules = [m["rule"] for m in alert.get("members", [])] or [alert["rule"]]
            verdict = doc.get("analyst_verdict")
            reason = doc.get("analyst_reason") or ""
            week = min(weeks - 1, int((now - ts).days // 7))
            for r in rules:
                s = out.setdefault(r, RuleStats(r))
                b = buckets[r][week]
                b["fired"] += 1
                if (now - ts).days <= days:
                    s.fired += 1
                    s.last_fired = max(filter(None, [s.last_fired, ts]))
                    if verdict == "true_positive":
                        s.tp += 1
                    elif verdict == "false_positive":
                        s.fp += 1
                        if reason:
                            s.fp_reasons[reason] = s.fp_reasons.get(reason, 0) + 1
                    elif doc.get("status") != "closed":
                        s.open += 1
                if verdict == "true_positive":
                    b["tp"] += 1
                elif verdict == "false_positive":
                    b["fp"] += 1
    for r, s in out.items():
        s.weekly = [{"weeks_ago": w, **buckets[r][w]} for w in range(weeks - 1, -1, -1)]
    return out


def threshold_bump(stats: RuleStats | None) -> int:
    """Extra risk a noisy rule must clear before anything auto-executes. Zero until the
    rule has enough verdicts to be judged; up to +20 for a rule that is always wrong."""
    if stats is None or stats.verdicts < settings.fp_prior_min_verdicts or stats.fp_rate is None:
        return 0
    return round(20 * stats.fp_rate)
