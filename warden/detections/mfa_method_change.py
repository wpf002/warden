"""T1556.006 Modify Authentication Process: Multi-Factor Authentication.

A new MFA factor enrolled shortly after a suspicious sign-in is the attacker making the
takeover stick. "Suspicious" here means the same account had failures, MFA denials, or
a login from an unfamiliar country in the preceding hour.
"""
from __future__ import annotations

from datetime import timedelta

from ..events import AuthEvent, Event, IdentityChangeEvent
from ..models import Alert
from . import Detection, register
from ._identity import norm_user


@register
class MFAMethodChange(Detection):
    id = "mfa_method_change"
    name = "MFA factor enrolled after a suspicious sign-in"
    mitre = ["T1556.006"]
    event_kinds = ("auth", "identity")
    window_sec = 3600
    playbook = "playbook-mfa-method-change"
    needs_history = True

    def run(self, events: list[Event]) -> list[Alert]:
        window = timedelta(seconds=self.window_sec)
        auths = [e for e in events if isinstance(e, AuthEvent)]
        known_geo: dict[str, set[str]] = {}
        for e in self.prior:
            if isinstance(e, AuthEvent) and e.event_type == "login_success" and e.geo:
                known_geo.setdefault(norm_user(e.user), set()).add(e.geo)
        out: list[Alert] = []
        for ch in (e for e in events if isinstance(e, IdentityChangeEvent) and e.change_type == "mfa_enrolled"):
            u = norm_user(ch.target_user or ch.user)
            before = [e for e in auths if norm_user(e.user) == u and ch.ts - window <= e.ts <= ch.ts]
            reasons = []
            fails = [e for e in before if e.event_type in ("login_failure", "mfa_denied", "mfa_timeout", "lockout")]
            if fails:
                reasons.append(f"{len(fails)} failed/denied authentications in the prior hour")
            wins = [e for e in before if e.event_type in ("login_success", "mfa_success")]
            odd_geo = [e for e in wins if e.geo and e.geo != "internal" and known_geo.get(u) and e.geo not in known_geo[u]]
            if odd_geo:
                reasons.append(f"sign-in from unfamiliar {odd_geo[-1].geo}")
            if not reasons or not wins:
                continue
            src = wins[-1]
            out.append(self.new_alert(
                key=f"{u}|{ch.ts.isoformat()}", first_seen=before[0].ts, ts=ch.ts,
                title=f"New MFA factor for {ch.target_user or ch.user} {int((ch.ts - src.ts).total_seconds() // 60)} min "
                      f"after a suspicious sign-in",
                source_ip=src.source_ip, related_ips=sorted({e.source_ip for e in before if e.source_ip} - {src.source_ip}),
                users=[ch.target_user or ch.user], hosts=[src.host] if src.host else [], geo=src.geo,
                asset_tier=src.asset_tier, last_seen=ch.ts, success_after_failures=bool(fails),
                detail={"reasons": reasons, "enrolled_by": ch.user, "minutes_after_login":
                        round((ch.ts - src.ts).total_seconds() / 60, 1)},
                evidence=[{"ts": e.ts.isoformat(), "user": e.user, "host": e.host, "type": e.event_type} for e in before[-15:]]
                         + [{"ts": ch.ts.isoformat(), "user": ch.target_user, "host": ch.host, "type": "mfa_enrolled"}],
            ))
        return out
