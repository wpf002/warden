"""T1078 Valid Accounts: two successful logins for one user from places a human
could not travel between in the elapsed time.

Deterministic: the speed a body would need is arithmetic, not judgement. Tuning is two
numbers - the speed ceiling and a minimum distance so adjacent-country noise stays quiet.
"""
from __future__ import annotations

from collections import defaultdict

from ..config import settings
from ..events import AuthEvent
from ..geo import INTERNAL, distance_km, required_kmh
from ..models import Alert
from . import Detection, register


@register
class ImpossibleTravel(Detection):
    id = "impossible_travel"
    name = "Impossible travel between successful logins"
    mitre = ["T1078"]
    event_kinds = ("auth",)
    window_sec = 86400
    playbook = "playbook-impossible-travel"

    def run(self, events: list[AuthEvent], max_kmh: int | None = None, min_km: int | None = None) -> list[Alert]:
        max_kmh = max_kmh or settings.travel_max_kmh
        min_km = min_km or settings.travel_min_km

        by_user: dict[str, list[AuthEvent]] = defaultdict(list)
        for e in events:
            if e.event_type == "login_success" and e.geo and e.geo != INTERNAL:
                by_user[e.user].append(e)

        out: list[Alert] = []
        for user, evs in by_user.items():
            evs.sort(key=lambda e: e.ts)
            for prev, cur in zip(evs, evs[1:]):
                if prev.geo == cur.geo:
                    continue
                km = distance_km(prev.geo, cur.geo)
                seconds = (cur.ts - prev.ts).total_seconds()
                kmh = required_kmh(prev.geo, cur.geo, seconds)
                if km is None or kmh is None or km < min_km or kmh <= max_kmh:
                    continue
                out.append(self.new_alert(
                    key=f"{user}|{prev.source_ip}|{cur.source_ip}", first_seen=prev.ts, ts=cur.ts,
                    title=f"Impossible travel for {user}: {prev.geo} to {cur.geo} in "
                          f"{seconds / 60:.0f} min ({kmh:,.0f} km/h implied)",
                    source_ip=cur.source_ip, related_ips=[prev.source_ip], users=[user],
                    hosts=sorted({h for h in (prev.host, cur.host) if h}),
                    geo=cur.geo, asset_tier=cur.asset_tier,
                    last_seen=cur.ts, window_sec=int(seconds),
                    success_after_failures=True,   # both legs are successful logins
                    detail={"from_geo": prev.geo, "to_geo": cur.geo, "distance_km": round(km),
                            "elapsed_sec": int(seconds), "implied_kmh": round(kmh),
                            "max_plausible_kmh": max_kmh,
                            "from_ip": prev.source_ip, "to_ip": cur.source_ip,
                            "user_agent_changed": prev.user_agent != cur.user_agent},
                    evidence=[{"ts": e.ts.isoformat(), "user": e.user, "host": e.host,
                               "type": f"login_success from {e.geo} ({e.source_ip})"} for e in (prev, cur)],
                ))
        return out
