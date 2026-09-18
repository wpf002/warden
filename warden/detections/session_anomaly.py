"""T1550.004 Use Alternate Authentication Material: Web Session Cookie. One session id
presented from a second IP and a different user agent mid-session: the cookie was
stolen and replayed. An IP change alone happens on mobile networks; both together don't."""
from __future__ import annotations

from collections import defaultdict

from ..events import AuthEvent
from ..models import Alert
from . import Detection, register
from ._identity import device_fingerprint


@register
class SessionAnomaly(Detection):
    id = "session_anomaly"
    name = "Session reused from a new IP and client"
    mitre = ["T1550.004"]
    event_kinds = ("auth",)
    window_sec = 43200
    playbook = "playbook-session-anomaly"

    def run(self, events: list[AuthEvent]) -> list[Alert]:
        by_sid: dict[str, list[AuthEvent]] = defaultdict(list)
        for e in events:
            if e.session_id and e.source_ip:
                by_sid[e.session_id].append(e)
        out: list[Alert] = []
        for sid, evs in by_sid.items():
            evs.sort(key=lambda e: e.ts)
            origin = evs[0]
            ofp = device_fingerprint(origin)
            for e in evs[1:]:
                if e.source_ip != origin.source_ip and ofp and device_fingerprint(e) and device_fingerprint(e) != ofp \
                        and (e.ts - origin.ts).total_seconds() <= self.window_sec:
                    out.append(self.new_alert(
                        key=sid, first_seen=origin.ts, ts=e.ts,
                        title=f"Session for {origin.user} replayed from {e.source_ip} with a different client",
                        source_ip=e.source_ip, related_ips=[origin.source_ip], users=[origin.user],
                        hosts=sorted({origin.host, e.host} - {""}), geo=e.geo, asset_tier=e.asset_tier,
                        last_seen=e.ts, success_after_failures=True,
                        detail={"session_id": sid[:64], "origin_ip": origin.source_ip, "origin_client": ofp,
                                "replay_client": device_fingerprint(e), "origin_geo": origin.geo},
                        evidence=[{"ts": x.ts.isoformat(), "user": x.user, "host": x.host,
                                   "type": f"{x.event_type} {x.source_ip} {device_fingerprint(x)}"} for x in (origin, e)],
                    ))
                    break
        return out
