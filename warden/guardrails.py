"""Policy SEC-012 in code. The model recommends; this decides."""
from __future__ import annotations

from .config import settings
from .models import Alert, Analysis, RecommendedAction

LOW_IMPACT = {"create_ticket", "notify", "generate_report"}
NO_OP = {"no_action"}


def _automatable(action: str) -> tuple[bool, str]:
    """Auto-execution needs the action on the allowlist AND a connector that can undo it."""
    from . import connectors
    if action in LOW_IMPACT:
        return True, ""
    if action not in settings.auto_actions:
        return False, "action not on automation allowlist"
    if not connectors.can_rollback(action):
        return False, f"connector for {action} has no rollback, so it cannot auto-execute"
    return True, ""


def _is_anomaly(a: Alert) -> bool:
    return a.rule.startswith("anomaly.")


def _rule_evidenced(alert: Alert, action: RecommendedAction) -> bool:
    """True when a deterministic rule (not a statistical anomaly) names the action's target.
    ROADMAP Phase 5: anomaly-sourced alerts never auto-execute."""
    members = [m for m in (alert.members or [alert]) if not _is_anomaly(m)]
    if not members:
        return False
    t = action.target
    return any(t in m.all_ips() or t in m.users or t in m.hosts or t in _principals(m) for m in members)


def _host_tier(alert: Alert, host: str) -> str:
    """Tier of the host being isolated, not of the incident: an incident is crown-jewel if
    any step touched the DC, but isolating the phished laptop is still routine."""
    from .ingest import enrich_asset
    tier = enrich_asset(host)
    if tier != "unknown":
        return tier
    owners = [m for m in (alert.members or [alert]) if host in m.hosts]
    return "crown_jewel" if any(m.asset_tier == "crown_jewel" for m in owners) else "unknown"


def _principals(alert: Alert) -> set[str]:
    out = set(alert.users)
    for m in [alert, *alert.members]:
        for k in ("principal", "member", "created_by"):
            if m.detail.get(k):
                out.add(str(m.detail[k]))
    return out


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
        if a.action == "isolate_host" and a.target not in alert.hosts:
            out.append(Decision(a, "deny", "model proposed a host not in the alert evidence"))
            continue
        if a.action == "disable_access_key" and a.target not in _principals(alert):
            out.append(Decision(a, "deny", "model proposed a principal not in the alert evidence"))
            continue
        if a.action in settings.human_approval_actions:
            out.append(Decision(a, "approve", "requires analyst approval (SEC-012 §2)"))
            continue
        if a.action not in LOW_IMPACT and not _rule_evidenced(alert, a):
            out.append(Decision(a, "approve", "only an anomaly supports this target; anomaly-sourced actions need an analyst"))
            continue
        ok, why_not = _automatable(a.action)
        if not ok:
            out.append(Decision(a, "approve", why_not))
            continue
        if a.action == "isolate_host" and _host_tier(alert, a.target) == "crown_jewel":
            out.append(Decision(a, "approve", "crown-jewel hosts are never auto-isolated (RP-004)"))
            continue
        # cheap, reversible, always-on actions run regardless of risk
        if a.action in LOW_IMPACT:
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
