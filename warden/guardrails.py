"""Policy SEC-012 in code. The model recommends; this decides."""
from __future__ import annotations

from .config import settings
from .models import Alert, Analysis, RecommendedAction

AUTOMATABLE = {"block_ip", "create_ticket", "notify", "generate_report"}
NO_OP = {"no_action"}


class Decision:
    def __init__(self, action: RecommendedAction, verdict: str, why: str):
        self.action, self.verdict, self.why = action, verdict, why   # verdict: execute | approve | deny

    def log_line(self) -> str:
        return f"{self.verdict.upper():8} {self.action.action}({self.action.target}): {self.why}"


def evaluate(alert: Alert, analysis: Analysis, bump: int = 0) -> list[Decision]:
    """`bump` raises the auto-execute threshold for rules analysts keep marking FP (stats.threshold_bump)."""
    out: list[Decision] = []
    for a in analysis.recommended_actions:
        if a.action in NO_OP:
            out.append(Decision(a, "deny", "no-op"))
            continue
        if a.action == "block_ip" and a.target in settings.ip_safelist:
            out.append(Decision(a, "deny", "target is on infrastructure safelist (SEC-012 §3)"))
            continue
        if a.action == "block_ip" and a.target not in alert.all_ips():
            out.append(Decision(a, "deny", "model proposed an IP not in the alert evidence"))
            continue
        if a.action == "lock_user" and a.target not in alert.users:
            out.append(Decision(a, "deny", "model proposed a user not in the alert evidence"))
            continue
        if a.action in settings.human_approval_actions:
            out.append(Decision(a, "approve", "requires analyst approval (SEC-012 §2)"))
            continue
        if a.action not in AUTOMATABLE:
            out.append(Decision(a, "approve", "action not on automation allowlist"))
            continue
        # cheap, reversible, always-on actions run regardless of risk
        if a.action in {"create_ticket", "notify", "generate_report"}:
            out.append(Decision(a, "execute", "low-impact action, always allowed"))
            continue
        if analysis.false_positive_likelihood == "high":
            out.append(Decision(a, "approve", "model flagged high false-positive likelihood"))
            continue
        threshold = settings.rule_thresholds.get(alert.rule, settings.auto_action_min_risk) + bump
        why = f"{alert.rule} threshold" + (f", +{bump} for its false-positive record" if bump else "")
        if analysis.risk_score >= threshold:
            out.append(Decision(a, "execute", f"risk {analysis.risk_score} >= {threshold} ({why})"))
        else:
            out.append(Decision(a, "approve", f"risk {analysis.risk_score} < {threshold} ({why})"))
    return out
