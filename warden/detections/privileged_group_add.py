"""T1098 Account Manipulation / T1078.004: an account added to a privileged group or
admin role (Domain Admins, Global Administrator, Okta Super Admins, ...). Higher weight
outside the sanctioned change window."""
from __future__ import annotations

from ..events import IdentityChangeEvent
from ..models import Alert
from . import Detection, register
from ._identity import in_change_window, is_privileged_group


@register
class PrivilegedGroupAdd(Detection):
    id = "privileged_group_add"
    name = "Account added to a privileged group"
    mitre = ["T1098", "T1078.004"]
    event_kinds = ("identity",)
    window_sec = 0
    playbook = "playbook-privileged-group-add"

    def run(self, events: list[IdentityChangeEvent]) -> list[Alert]:
        out: list[Alert] = []
        for e in events:
            if e.change_type != "group_add" or not is_privileged_group(e.group):
                continue
            inside = in_change_window(e.ts)
            out.append(self.new_alert(
                key=f"{e.target_user}|{e.group}|{e.ts.isoformat()}", first_seen=e.ts, ts=e.ts,
                title=f"{e.target_user or '?'} added to {e.group} by {e.user or 'unknown'}"
                      + ("" if inside else " outside the change window"),
                source_ip=e.source_ip, users=[u for u in (e.target_user, e.user) if u],
                hosts=[e.host] if e.host else [], geo=e.geo, asset_tier="crown_jewel", last_seen=e.ts,
                detail={"group": e.group, "member": e.target_user, "added_by": e.user,
                        "in_change_window": inside, "source": e.source},
                evidence=[{"ts": e.ts.isoformat(), "user": e.user, "host": e.host,
                           "type": f"group_add {e.target_user} -> {e.group}"}],
            ))
        return out
