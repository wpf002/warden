"""T1136 Create Account, then T1098: a brand-new account gets admin rights within
minutes. Legitimate onboarding rarely grants privilege on day one; persistence does."""
from __future__ import annotations

from datetime import timedelta

from ..events import IdentityChangeEvent
from ..models import Alert
from . import Detection, register
from ._identity import is_privileged_group, norm_user


@register
class AccountCreateThenPrivilege(Detection):
    id = "account_create_then_privilege"
    name = "New account granted privilege"
    mitre = ["T1136", "T1098"]
    event_kinds = ("identity",)
    window_sec = 3600
    playbook = "playbook-account-create-then-privilege"

    def run(self, events: list[IdentityChangeEvent]) -> list[Alert]:
        window = timedelta(seconds=self.window_sec)
        created = [e for e in events if e.change_type == "account_created"]
        adds = [e for e in events if e.change_type == "group_add" and is_privileged_group(e.group)]
        out: list[Alert] = []
        for c in created:
            who = norm_user(c.target_user)
            hit = next((a for a in adds if norm_user(a.target_user) == who and c.ts <= a.ts <= c.ts + window), None)
            if not hit:
                continue
            out.append(self.new_alert(
                key=f"{who}|{c.ts.isoformat()}", first_seen=c.ts, ts=hit.ts,
                title=f"New account {c.target_user} added to {hit.group} "
                      f"{int((hit.ts - c.ts).total_seconds() // 60)} min after creation",
                source_ip=hit.source_ip or c.source_ip, users=sorted({c.target_user, c.user, hit.user} - {""}),
                hosts=sorted({c.host, hit.host} - {""}), geo=c.geo, asset_tier="crown_jewel", last_seen=hit.ts,
                detail={"created_by": c.user, "granted_by": hit.user, "group": hit.group,
                        "minutes_to_privilege": round((hit.ts - c.ts).total_seconds() / 60, 1)},
                evidence=[{"ts": c.ts.isoformat(), "user": c.user, "host": c.host, "type": f"account_created {c.target_user}"},
                          {"ts": hit.ts.isoformat(), "user": hit.user, "host": hit.host, "type": f"group_add -> {hit.group}"}],
            ))
        return out
