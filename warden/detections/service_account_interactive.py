"""T1078.002 Valid Accounts: Domain Accounts. A service account used for an interactive
or RDP logon. Service accounts authenticate as services; a human typing its password at
a console means the credential left the vault."""
from __future__ import annotations

from ..events import AuthEvent
from ..models import Alert
from . import Detection, register
from ._identity import INTERACTIVE, is_service_account


@register
class ServiceAccountInteractive(Detection):
    id = "service_account_interactive"
    name = "Service account used interactively"
    mitre = ["T1078.002"]
    event_kinds = ("auth",)
    window_sec = 0
    playbook = "playbook-service-account-interactive"

    def run(self, events: list[AuthEvent]) -> list[Alert]:
        out: list[Alert] = []
        seen: set[tuple] = set()
        for e in events:
            if e.event_type != "login_success" or e.logon_type not in INTERACTIVE or not is_service_account(e.user):
                continue
            if e.user.endswith("$"):
                continue   # machine accounts log on as interactive during boot; out of scope here
            k = (e.user, e.host, e.source_ip, e.ts.replace(minute=0, second=0, microsecond=0))
            if k in seen:
                continue
            seen.add(k)
            out.append(self.new_alert(
                key=f"{e.user}|{e.host}|{e.source_ip}", first_seen=e.ts, ts=e.ts,
                title=f"Service account {e.user} {e.logon_type.replace('_', ' ')} logon on {e.host or 'unknown host'}",
                source_ip=e.source_ip, users=[e.user], hosts=[e.host] if e.host else [], geo=e.geo,
                asset_tier=e.asset_tier, last_seen=e.ts,
                detail={"logon_type": e.logon_type, "user_agent": e.user_agent},
                evidence=[{"ts": e.ts.isoformat(), "user": e.user, "host": e.host, "type": f"logon {e.logon_type}"}],
            ))
        return out
