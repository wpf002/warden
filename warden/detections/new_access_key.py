"""T1098.001 Additional Cloud Credentials: an access key created for someone else, or
for a user that has been idle. Both are how attackers get credentials that outlive the
session they stole."""
from __future__ import annotations

from ..config import settings
from ..events import CloudAuditEvent
from ..models import Alert
from . import Detection, register
from ._cloud import cloud_alert, params


@register
class NewAccessKey(Detection):
    id = "new_access_key"
    name = "Access key created for another or idle user"
    mitre = ["T1098.001"]
    event_kinds = ("cloud",)
    window_sec = 0
    playbook = "playbook-new-access-key"
    needs_history = True

    def run(self, events: list[CloudAuditEvent]) -> list[Alert]:
        last: dict[str, object] = {}
        for e in self.prior:
            if e.user and (e.user not in last or e.ts > last[e.user]):
                last[e.user] = e.ts
        out = []
        for e in sorted(events, key=lambda e: e.ts):
            if e.api_call != "CreateAccessKey" or e.outcome == "failure":
                continue
            target = params(e).get("userName") or e.user
            idle = (e.ts - last[target]).days if target in last else None
            if target != e.user or (idle is not None and idle >= settings.dormant_days):
                out.append(cloud_alert(self, e, f"Access key created for {target} by {e.user}"
                                       + (f" after {idle} idle days" if idle and idle >= settings.dormant_days else ""),
                                       principal=target, created_by=e.user, idle_days=idle))
            if e.user:
                last[e.user] = e.ts
        return out
