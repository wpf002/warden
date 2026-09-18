"""T1110 Brute Force: account lockouts across many users in a short window. Usually the
tail of a spray that overshot the lockout threshold, sometimes a deliberate denial of
service against the directory."""
from __future__ import annotations

from collections import Counter
from datetime import timedelta

from ..config import settings
from ..events import AuthEvent
from ..models import Alert
from . import Detection, register


@register
class LockoutStorm(Detection):
    id = "lockout_storm"
    name = "Mass account lockouts"
    mitre = ["T1110"]
    event_kinds = ("auth",)
    window_sec = 900
    playbook = "playbook-lockout-storm"

    def run(self, events: list[AuthEvent]) -> list[Alert]:
        window = timedelta(seconds=self.window_sec)
        locks = sorted((e for e in events if e.event_type == "lockout"), key=lambda e: e.ts)
        out: list[Alert] = []
        i = 0
        while i < len(locks):
            j = i
            while j + 1 < len(locks) and locks[j + 1].ts - locks[i].ts <= window:
                j += 1
            burst = locks[i:j + 1]
            users = {e.user for e in burst}
            if len(users) < settings.lockout_storm_users:
                i += 1
                continue
            ips = Counter(e.source_ip for e in burst if e.source_ip)
            top = ips.most_common(1)[0][0] if ips else ""
            out.append(self.new_alert(
                key=f"{burst[0].ts.isoformat()}", first_seen=burst[0].ts, ts=burst[-1].ts,
                title=f"{len(users)} accounts locked out in {int((burst[-1].ts - burst[0].ts).total_seconds() // 60) + 1} min",
                source_ip=top, related_ips=sorted(ips)[:50], users=sorted(users),
                hosts=sorted({e.host for e in burst if e.host}), geo=burst[0].geo, last_seen=burst[-1].ts,
                failed_attempts=len(burst),
                detail={"locked_accounts": len(users), "source_ips": len(ips), "top_source_share":
                        round(ips[top] / len(burst), 2) if top else 0},
                evidence=[{"ts": e.ts.isoformat(), "user": e.user, "host": e.host, "type": "lockout"} for e in burst[:25]],
            ))
            i = j + 1
        return out
