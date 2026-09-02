"""T1110.003 Brute Force: Password Spraying.

Failures from one source IP spread thinly across many accounts. Low per-account
volume is the point: it stays under lockout thresholds.
"""
from __future__ import annotations

from ..config import settings
from ..events import AuthEvent
from ..models import Alert
from . import Detection, register
from ._burst import evidence, failure_bursts, is_spray, success_after, top_asset_tier


@register
class PasswordSpray(Detection):
    id = "password_spray"
    name = "Password spray across accounts"
    mitre = ["T1110.003"]
    event_kinds = ("auth",)
    playbook = "playbook-password-spray"

    def run(self, events: list[AuthEvent], threshold: int | None = None, window_sec: int | None = None) -> list[Alert]:
        threshold = threshold or settings.bf_threshold
        window_sec = window_sec or settings.bf_window_sec
        out: list[Alert] = []
        for ip, burst, evs in failure_bursts(events, threshold, window_sec):
            if not is_spray(burst):
                continue
            users = sorted({e.user for e in burst})
            last = burst[-1].ts
            hit = success_after(evs, set(users), last, window_sec)
            out.append(self.new_alert(
                key=ip, first_seen=burst[0].ts, ts=last,
                title=f"Password spray from {ip}" + (" followed by SUCCESSFUL login" if hit else ""),
                source_ip=ip, users=users, hosts=sorted({e.host for e in burst if e.host}),
                geo=burst[0].geo, asset_tier=top_asset_tier(burst),
                last_seen=last, window_sec=window_sec,
                failed_attempts=len(burst), success_after_failures=hit,
                detail={"distinct_users": len(users),
                        "attempts_per_user": round(len(burst) / len(users), 2)},
                evidence=evidence(burst),
            ))
        return out
