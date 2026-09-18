"""Policy SEC-012 in code. The model recommends; this decides."""
from __future__ import annotations

from .config import settings
from .models import Alert, Analysis, RecommendedAction

LOW_IMPACT = {"create_ticket", "notify", "generate_report"}
NO_OP = {"no_action"}


def _automatable(action: str, pol) -> tuple[bool, str]:
    """Auto-execution needs the action on the allowlist AND a connector that can undo it."""
    from . import connectors
    if action in LOW_IMPACT:
        return True, ""
    if action not in pol.auto_actions:
        return False, "action not on automation allowlist"
    if not connectors.can_rollback(action):
        return False, f"connector for {action} has no rollback, so it cannot auto-execute"
    return True, ""


OTHER_CASE = __import__("re").compile(r"^(ALT|INC|CASE|PROP)-\S+$", __import__("re").I)
SUSPICIOUS_TARGET = __import__("re").compile(r"[:/@\\]|\s{2,}|https?", __import__("re").I)


def _normalize(a: RecommendedAction, alert: Alert, pol, case_ids: set[str]) -> RecommendedAction:
    """Tickets always describe this case and notifications only go to configured channels,
    so a model's free-text target ("SOC team", "Incident 42") is mapped onto the case id or
    the default channel. Anything shaped like an address, a URL, or another case's id is
    left as written so the checks below deny it."""
    t = (a.target or "").strip()
    if a.action == "create_ticket" and t not in case_ids and not OTHER_CASE.match(t) and not SUSPICIOUS_TARGET.search(t):
        return RecommendedAction(action=a.action, target=alert.id, reason=a.reason)
    if a.action == "notify" and t not in pol.notify_targets and not SUSPICIOUS_TARGET.search(t):
        default = "soc" if "soc" in pol.notify_targets else sorted(pol.notify_targets)[0]
        return RecommendedAction(action=a.action, target=default, reason=a.reason)
    return a


# Playbook rules encoded as policy: containment these playbooks say must never be automatic.
APPROVAL_ONLY = {
    "impossible_travel": {"block_ip"},      # PB-007: one of the two addresses is the real user
    "new_geo_login": {"block_ip"},          # PB-010: travel and VPNs; context, not containment
}


def _naming(alert: Alert, target: str) -> list[Alert]:
    return [m for m in (alert.members or [alert])
            if target in m.all_ips() or target in m.hosts or target in m.users]


def _playbook_forbids_auto(alert: Alert, a: RecommendedAction) -> bool:
    """True when every alert that names the target comes from a rule whose playbook says
    this containment waits for a person. Another rule naming the same target lifts it."""
    names = _naming(alert, a.target)
    return bool(names) and all(a.action in APPROVAL_ONLY.get(m.rule, set()) for m in names)


def _has_cloud_evidence(alert: Alert) -> bool:
    from .detections import REGISTRY, load_all
    load_all()
    return any("cloud" in getattr(REGISTRY.get(m.rule), "event_kinds", ()) for m in (alert.members or [alert]))


def _internal(ip: str) -> bool:
    from .detections._network import is_internal
    return is_internal(ip)


def _host_is_actor(alert: Alert, host: str) -> bool:
    """Auto-isolation needs an endpoint or network detection that names this host as where
    the activity ran. Identity alerts carry the server that logged the event (a DC, a VPN
    gateway), which is the victim, not the machine to cut off."""
    from .correlate import _host_scoped
    return any(host in m.hosts and _host_scoped(m.rule) for m in (alert.members or [alert]))


def canonical_ip(v: str) -> str | None:
    """The one spelling of an address guardrails accept. Rejects CIDRs, padding, leading
    zeros, and IPv4-mapped IPv6 - all ways to smuggle a safelisted address past a string match."""
    import ipaddress
    if not isinstance(v, str) or v != v.strip() or "/" in v:
        return None
    try:
        a = ipaddress.ip_address(v)
    except ValueError:
        return None
    if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped:
        return str(a.ipv4_mapped)
    return str(a)


def _safelisted(ip: str, safelist) -> bool:
    import ipaddress
    a = ipaddress.ip_address(ip)
    for entry in safelist:
        try:
            if a in ipaddress.ip_network(entry.strip(), strict=False):
                return True
        except ValueError:
            continue
    return False


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


def evaluate(alert: Alert, analysis: Analysis, bump: int = 0, policy=None, verified: bool | None = None) -> list[Decision]:
    """`bump` raises the auto-execute threshold for rules analysts keep marking FP (stats.threshold_bump).
    `policy` is the tenant's guardrail policy (tenancy.policy); defaults to the global settings."""
    from .tenancy import policy as _policy
    pol = policy or _policy()
    out: list[Decision] = []
    ticketed, notified, seen = False, set(), set()
    case_ids = {alert.id, *(m.id for m in alert.members)}
    recs = [_normalize(a, alert, pol, case_ids) for a in analysis.recommended_actions]
    for a in recs:
        if (a.action, a.target) in seen:
            out.append(Decision(a, "deny", "duplicate of an earlier recommendation"))
            continue
        seen.add((a.action, a.target))
        if a.action == "create_ticket" and ticketed:
            out.append(Decision(a, "deny", "one ticket per case"))
            continue
        if a.action == "notify" and (a.target or "soc") in notified:
            out.append(Decision(a, "deny", "channel already notified for this case"))
            continue
        if a.action in NO_OP:
            out.append(Decision(a, "deny", "no-op"))
            continue
        if a.action == "block_ip":
            canon = canonical_ip(a.target)
            if canon is None:
                out.append(Decision(a, "deny", "block target is not a single canonical IP address"))
                continue
            if canon != a.target:
                out.append(Decision(a, "deny", f"block target {a.target!r} is not written canonically ({canon})"))
                continue
            if _safelisted(canon, pol.ip_safelist):
                out.append(Decision(a, "deny", "target is on infrastructure safelist (SEC-012 §3)"))
                continue
            if _internal(canon):
                out.append(Decision(a, "deny", "internal address: contain the machine with isolate_host, not a perimeter block (RP-001)"))
                continue
        if a.action not in LOW_IMPACT and verified is False:
            out.append(Decision(a, "approve", "analysis failed entity verification; a human checks it first"))
            continue
        if a.action == "block_ip" and a.target not in alert.all_ips():
            out.append(Decision(a, "deny", "model proposed an IP not in the alert evidence"))
            continue
        if a.action == "notify" and a.target and a.target not in pol.notify_targets:
            out.append(Decision(a, "deny", f"notify target {a.target!r} is not an approved channel"))
            continue
        if a.action == "create_ticket" and a.target and a.target not in case_ids:
            out.append(Decision(a, "deny", "ticket must reference this case"))
            continue
        if a.action == "lock_user" and a.target not in alert.users:
            out.append(Decision(a, "deny", "model proposed a user not in the alert evidence"))
            continue
        if a.action == "isolate_host" and a.target not in alert.hosts:
            out.append(Decision(a, "deny", "model proposed a host not in the alert evidence"))
            continue
        if a.action == "disable_access_key" and not _has_cloud_evidence(alert):
            out.append(Decision(a, "deny", "access keys are cloud credentials; no cloud evidence in this case"))
            continue
        if a.action in ("block_ip", "isolate_host") and _playbook_forbids_auto(alert, a):
            out.append(Decision(a, "approve", f"playbook for {', '.join(sorted({m.rule for m in _naming(alert, a.target)}))} forbids automatic {a.action}"))
            continue
        if a.action == "disable_access_key" and a.target not in _principals(alert):
            out.append(Decision(a, "deny", "model proposed a principal not in the alert evidence"))
            continue
        if a.action in pol.human_approval_actions:
            out.append(Decision(a, "approve", "requires analyst approval (SEC-012 §2)"))
            continue
        if a.action not in LOW_IMPACT and not _rule_evidenced(alert, a):
            out.append(Decision(a, "approve", "only an anomaly supports this target; anomaly-sourced actions need an analyst"))
            continue
        ok, why_not = _automatable(a.action, pol)
        if not ok:
            out.append(Decision(a, "approve", why_not))
            continue
        if a.action == "isolate_host" and not _host_is_actor(alert, a.target):
            out.append(Decision(a, "approve", "no endpoint or network rule names this host as the actor; it may only be where activity was logged"))
            continue
        if a.action == "isolate_host" and _host_tier(alert, a.target) == "crown_jewel":
            out.append(Decision(a, "approve", "crown-jewel hosts are never auto-isolated (RP-004)"))
            continue
        # cheap, reversible, always-on actions run regardless of risk
        if a.action in LOW_IMPACT:
            if a.action == "create_ticket":
                ticketed = True
            if a.action == "notify":
                notified.add(a.target or "soc")
            out.append(Decision(a, "execute", "low-impact action, always allowed"))
            continue
        if analysis.false_positive_likelihood == "high":
            out.append(Decision(a, "approve", "model flagged high false-positive likelihood"))
            continue
        threshold = pol.threshold(alert.rule) + bump
        why = f"{alert.rule} threshold" + (f", +{bump} for its false-positive record" if bump else "")
        if analysis.risk_score >= threshold:
            out.append(Decision(a, "execute", f"risk {analysis.risk_score} >= {threshold} ({why})"))
        else:
            out.append(Decision(a, "approve", f"risk {analysis.risk_score} < {threshold} ({why})"))
    return out
