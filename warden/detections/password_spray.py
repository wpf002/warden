"""T1110.003 Brute Force: Password Spraying.

One source trying one or two passwords against many accounts. Low per-account volume
is the point: it stays under lockout thresholds. So the trigger is the number of
distinct accounts failing from one IP inside the window, not the raw failure count.

Tuned on a real Kerberos spray (EVTX-ATTACK-SAMPLES kerberos_pwd_spray_4771): nine
accounts in 20 ms, then a success. A total-failure threshold of 10 misses it.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from ..config import settings
from ..events import AuthEvent
from ..models import Alert
from . import Detection, register
from ._burst import evidence, top_asset_tier


@register
class PasswordSpray(Detection):
    id = "password_spray"
    name = "Password spray across accounts"
    mitre = ["T1110.003"]
    event_kinds = ("auth",)
    playbook = "playbook-password-spray"

    def run(self, events: list[AuthEvent], min_users: int | None = None, window_sec: int | None = None,
            threshold: int | None = None) -> list[Alert]:
        # `threshold` is accepted for the v0.1 call signature; spray keys on distinct users.
        min_users = min_users or settings.spray_min_users
        window_sec = window_sec or settings.bf_window_sec
        window = timedelta(seconds=window_sec)

        by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
        for e in events:
            if e.source_ip:
                by_ip[e.source_ip].append(e)

        out: list[Alert] = []
        for ip, evs in by_ip.items():
            evs.sort(key=lambda e: e.ts)
            fails = [e for e in evs if e.event_type == "login_failure"]
            i = 0
            while i < len(fails):
                j = i
                while j + 1 < len(fails) and fails[j + 1].ts - fails[i].ts <= window:
                    j += 1
                burst = fails[i:j + 1]
                failed_users = {e.user for e in burst}
                # a grind on one or two accounts is brute force, not spray
                if len(failed_users) < min_users or len(burst) / len(failed_users) > settings.spray_max_per_user:
                    i += 1
                    continue
                first, last = burst[0].ts, burst[-1].ts
                wins = [e for e in evs if e.event_type == "login_success" and first <= e.ts <= last + window]
                won = sorted({e.user for e in wins})
                users = sorted(failed_users | set(won))
                out.append(self.new_alert(
                    key=ip, first_seen=first, ts=last,
                    title=f"Password spray from {ip} across {len(failed_users)} accounts"
                          + (f", SUCCESS for {', '.join(won)}" if won else ""),
                    source_ip=ip, users=users, hosts=sorted({e.host for e in burst if e.host}),
                    geo=burst[0].geo, asset_tier=top_asset_tier(burst),
                    last_seen=last, window_sec=window_sec,
                    failed_attempts=len(burst), success_after_failures=bool(won),
                    detail={"distinct_users": len(failed_users),
                            "attempts_per_user": round(len(burst) / len(failed_users), 2),
                            "succeeded_users": won,
                            "duration_sec": round((last - first).total_seconds(), 3),
                            "failure_reasons": sorted({e.outcome_reason for e in burst if e.outcome_reason})[:5]},
                    evidence=evidence(burst) + [{"ts": e.ts.isoformat(), "user": e.user, "host": e.host,
                                                 "type": "login_success"} for e in wins[:5]],
                ))
                i = j + 1
        return out
