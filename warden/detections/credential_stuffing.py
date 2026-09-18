"""T1110.004 Brute Force: Credential Stuffing.

Leaked username/password pairs replayed from a botnet or proxy pool: many accounts,
many source IPs, only a handful of attempts per IP. Per-IP rules never see it. The tell
is the shared tooling - one user agent, or one /24, across the whole wave.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import timedelta

from ..config import settings
from ..events import AuthEvent
from ..models import Alert
from . import Detection, register
from ._burst import evidence, top_asset_tier


def _net24(ip: str) -> str:
    return ".".join(ip.split(".")[:3]) if ip.count(".") == 3 else ip


@register
class CredentialStuffing(Detection):
    id = "credential_stuffing"
    name = "Credential stuffing from a distributed source"
    mitre = ["T1110.004"]
    event_kinds = ("auth",)
    window_sec = 900
    playbook = "playbook-credential-stuffing"

    def run(self, events: list[AuthEvent]) -> list[Alert]:
        window = timedelta(seconds=self.window_sec)
        fails = sorted((e for e in events if e.event_type == "login_failure" and e.source_ip), key=lambda e: e.ts)
        # group by shared tooling: user agent if present, else /24
        groups: dict[str, list[AuthEvent]] = defaultdict(list)
        for e in fails:
            groups[f"ua:{e.user_agent}" if e.user_agent else f"net:{_net24(e.source_ip)}"].append(e)

        out: list[Alert] = []
        for key, evs in groups.items():
            i = 0
            while i < len(evs):
                j = i
                while j + 1 < len(evs) and evs[j + 1].ts - evs[i].ts <= window:
                    j += 1
                burst = evs[i:j + 1]
                ips = Counter(e.source_ip for e in burst)
                users = {e.user for e in burst}
                if (len(users) < settings.stuffing_min_users or len(ips) < settings.stuffing_min_ips
                        or max(ips.values()) > settings.bf_threshold):
                    i += 1
                    continue
                first, last = burst[0].ts, burst[-1].ts
                wins = [e for e in events if e.event_type == "login_success" and e.source_ip in ips
                        and first <= e.ts <= last + window]
                won = sorted({e.user for e in wins})
                top_ip = ips.most_common(1)[0][0]
                out.append(self.new_alert(
                    key=key, first_seen=first, ts=last,
                    title=f"Credential stuffing: {len(users)} accounts from {len(ips)} IPs sharing "
                          + ("a user agent" if key.startswith("ua:") else f"{_net24(top_ip)}.0/24")
                          + (f", SUCCESS for {', '.join(won)}" if won else ""),
                    source_ip=top_ip, related_ips=sorted(ips)[:50], users=sorted(users | set(won)),
                    hosts=sorted({e.host for e in burst if e.host}), geo=burst[0].geo,
                    asset_tier=top_asset_tier(burst), last_seen=last,
                    failed_attempts=len(burst), success_after_failures=bool(won),
                    detail={"distinct_users": len(users), "distinct_ips": len(ips),
                            "max_attempts_per_ip": max(ips.values()), "shared": key[:120],
                            "succeeded_users": won},
                    evidence=evidence(burst),
                ))
                i = j + 1
        return out
