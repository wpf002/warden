"""Correlation. Stage 4.5, between detection and analysis.

Alerts that share an entity - a user or a source IP - and sit close in time are one
attack, not four. They merge into an incident: an `Alert` with rule "incident" whose
`members` are the original alerts and whose evidence is the combined timeline. The
analyzer, guardrails, and dashboard all take incidents through the same path as alerts.

    spray -> success -> new MFA factor -> admin group add   ==>   one incident

Deterministic, like detection. The model never decides what belongs together.
"""
from __future__ import annotations

import hashlib
from collections import Counter

from .config import settings
from .detections._identity import norm_user
from .models import Alert

TIER = {"crown_jewel": 2, "standard": 1}
MAX_KEYED_USERS = 10   # alerts naming more users than this link by IP only
# For these rules the listed users are the *targets* of a wide attack, not people whose
# accounts were taken. Only the accounts that actually succeeded link them to anything.
WIDE_TARGET_RULES = {"password_spray", "credential_stuffing", "lockout_storm"}


def pivot_users(a: Alert) -> list[str]:
    if a.rule in WIDE_TARGET_RULES:
        return list(a.detail.get("succeeded_users") or [])
    return a.users if len(a.users) <= MAX_KEYED_USERS else []


SYSTEM_USERS = {"system", "local service", "network service", "localsystem", "anonymous logon", "-", ""}
HOST_KINDS = {"process", "file", "network"}


def _host_scoped(rule: str) -> bool:
    """Endpoint and network alerts are about a machine; a shared host links them. Identity
    alerts name hosts too (the DC, the VPN gateway) but those are shared by everyone."""
    from .detections import REGISTRY, load_all
    load_all()
    d = REGISTRY.get(rule)
    return bool(d and set(d.event_kinds) & HOST_KINDS and "auth" not in d.event_kinds)


def _keys(a: Alert) -> set[str]:
    keys = {f"ip:{ip}" for ip in a.all_ips() if ip and ip not in settings.ip_safelist}
    keys |= {f"user:{norm_user(u)}" for u in pivot_users(a)
             if norm_user(u) not in SYSTEM_USERS and not u.endswith("$")}
    if _host_scoped(a.rule):
        keys |= {f"host:{h.lower()}" for h in a.hosts if h}
    return keys


def _close(a: Alert, b: Alert, gap: int) -> bool:
    lo = max(a.first_seen, b.first_seen)
    hi = min(a.last_seen, b.last_seen)
    return (lo - hi).total_seconds() <= gap


def correlate(alerts: list[Alert], window_sec: int | None = None) -> list[Alert]:
    """Return the analysis subjects: every alert that correlates with nothing stands
    alone; every connected group of two or more becomes one incident."""
    gap = window_sec if window_sec is not None else settings.correlation_window_sec
    alerts = sorted(alerts, key=lambda a: a.first_seen)
    parent = list(range(len(alerts)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    keys = [_keys(a) for a in alerts]
    for i in range(len(alerts)):
        for j in range(i + 1, len(alerts)):
            if keys[i] & keys[j] and _close(alerts[i], alerts[j], gap):
                parent[find(i)] = find(j)

    groups: dict[int, list[Alert]] = {}
    for i, a in enumerate(alerts):
        groups.setdefault(find(i), []).append(a)
    out = [g[0] if len(g) == 1 else build_incident(g) for g in groups.values()]
    return sorted(out, key=lambda a: a.ts)


STAGE = {  # rough kill-chain order, used to title the chain
    "suspicious_parent_child": 2, "lolbin_abuse": 2, "encoded_powershell": 2, "intel_ioc_match": 3, "beaconing": 3,
    "dns_tunneling": 3, "credential_dumping": 4, "persistence_mechanism": 4, "security_tool_tamper": 4,
    "log_clearing": 4, "edr_alert": 4, "lateral_movement_fanout": 5, "port_scan": 3, "data_exfiltration": 6,
    "ransomware_precursor": 6, "mass_file_encryption": 7, "mailbox_forwarding_rule": 4, "iam_admin_grant": 5,
    "new_access_key": 5, "public_bucket": 6, "cloud_logging_disabled": 4, "unusual_region": 5,
    "console_login_no_mfa": 3,
    "credential_stuffing": 1, "password_spray": 1, "brute_force": 1, "lockout_storm": 1, "mfa_fatigue": 2,
    "impossible_travel": 3, "new_geo_login": 3, "dormant_account": 3, "session_anomaly": 3,
    "service_account_interactive": 3, "mfa_method_change": 4, "password_reset_abuse": 4,
    "account_create_then_privilege": 5, "privileged_group_add": 5,
}


def build_incident(members: list[Alert]) -> Alert:
    members = sorted(members, key=lambda a: (a.first_seen, STAGE.get(a.rule, 9)))
    ips = Counter(ip for m in members for ip in ([m.source_ip] if m.source_ip else []))
    users = list(dict.fromkeys(u for m in members for u in m.users))
    chain = list(dict.fromkeys(m.rule for m in members))
    mitre = list(dict.fromkeys(t for m in members for t in m.mitre))
    focus = Counter(norm_user(u) for m in members for u in pivot_users(m)
                    if norm_user(u) not in SYSTEM_USERS and not u.endswith("$")).most_common(1)
    if not focus:
        focus = Counter(h for m in members for h in m.hosts).most_common(1)
    who = focus[0][0] if focus else (ips.most_common(1)[0][0] if ips else "?")
    timeline = sorted(({**e, "alert": m.id, "rule": m.rule} for m in members for e in m.evidence),
                      key=lambda e: e.get("ts", ""))
    iid = "INC-" + hashlib.sha1("|".join(sorted(m.id for m in members)).encode()).hexdigest()[:8].upper()
    return Alert(
        id=iid, ts=max(m.ts for m in members), rule="incident",
        title=f"{who}: " + " -> ".join(r.replace("_", " ") for r in chain),
        mitre=mitre, playbook=members[0].playbook,
        source_ip=ips.most_common(1)[0][0] if ips else "",
        related_ips=sorted({ip for m in members for ip in m.all_ips()} - {ips.most_common(1)[0][0] if ips else ""}),
        users=users[:25], hosts=sorted({h for m in members for h in m.hosts}),
        geo=members[-1].geo, asset_tier=max((m.asset_tier for m in members), key=lambda t: TIER.get(t, 0)),
        first_seen=min(m.first_seen for m in members), last_seen=max(m.last_seen for m in members),
        window_sec=int((max(m.last_seen for m in members) - min(m.first_seen for m in members)).total_seconds()),
        failed_attempts=sum(m.failed_attempts for m in members),
        success_after_failures=any(m.success_after_failures for m in members),
        detail={"chain": chain, "alert_count": len(members), "focus": who},
        evidence=timeline[:80], members=members,
    )
