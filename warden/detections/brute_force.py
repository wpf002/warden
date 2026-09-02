"""T1110.001 Brute Force: Password Guessing.

Many failures from one source IP against a small number of accounts, inside a window.
"""
from __future__ import annotations

from ..config import settings
from ..events import AuthEvent
from ..models import Alert
from . import Detection, register
from ._burst import evidence, failure_bursts, is_spray, success_after, top_asset_tier


@register
class BruteForce(Detection):
    id = "brute_force"
    name = "Brute force login attempts"
    mitre = ["T1110.001"]
    event_kinds = ("auth",)
    playbook = "playbook-brute-force"

    @property
    def threshold(self) -> int:
        return settings.bf_threshold

    def run(self, events: list[AuthEvent], threshold: int | None = None, window_sec: int | None = None) -> list[Alert]:
        threshold = threshold or settings.bf_threshold
        window_sec = window_sec or settings.bf_window_sec
        out: list[Alert] = []
        for ip, burst, evs in failure_bursts(events, threshold, window_sec):
            if is_spray(burst):
                continue
            users = sorted({e.user for e in burst})
            last = burst[-1].ts
            hit = success_after(evs, set(users), last, window_sec)
            out.append(self.new_alert(
                key=ip, first_seen=burst[0].ts, ts=last,
                title=f"Brute force from {ip}" + (" followed by SUCCESSFUL login" if hit else ""),
                source_ip=ip, users=users, hosts=sorted({e.host for e in burst if e.host}),
                geo=burst[0].geo, asset_tier=top_asset_tier(burst),
                last_seen=last, window_sec=window_sec,
                failed_attempts=len(burst), success_after_failures=hit,
                detail={"distinct_users": len(users), "attempts_per_min": round(len(burst) / max(1, (last - burst[0].ts).total_seconds() / 60), 1)},
                evidence=evidence(burst),
            ))
        return out
