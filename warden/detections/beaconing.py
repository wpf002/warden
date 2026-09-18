"""T1071 Application Layer Protocol: a host calling the same external destination on a
steady clock. Implants check in at fixed intervals with a little jitter; people and most
software do not. Scored on the coefficient of variation of the gaps between connections."""
from __future__ import annotations

import statistics
from collections import defaultdict

from ..config import settings
from ..events import NetworkEvent
from ..models import Alert
from . import Detection, register
from ._network import is_internal, src


@register
class Beaconing(Detection):
    id = "beaconing"
    name = "Periodic outbound beaconing"
    mitre = ["T1071", "T1573"]
    event_kinds = ("network",)
    window_sec = 86400
    playbook = "playbook-beaconing"

    def run(self, events: list[NetworkEvent]) -> list[Alert]:
        pairs: dict[tuple[str, str], list[NetworkEvent]] = defaultdict(list)
        for e in events:
            if e.protocol == "dns" or not e.dest_ip or is_internal(e.dest_ip):
                continue
            pairs[(src(e), e.dest_ip)].append(e)
        out = []
        for (s, dst), evs in pairs.items():
            if len(evs) < settings.beacon_min_connections:
                continue
            evs.sort(key=lambda e: e.ts)
            gaps = [(b.ts - a.ts).total_seconds() for a, b in zip(evs, evs[1:])]
            mean = statistics.mean(gaps)
            if mean < 10:
                continue            # sub-10s gaps are a session, not a check-in
            cv = statistics.pstdev(gaps) / mean
            if cv > settings.beacon_max_cv:
                continue
            out.append(self.new_alert(
                key=f"{s}|{dst}", first_seen=evs[0].ts, ts=evs[-1].ts,
                title=f"{s} beaconing to {dst}:{evs[0].dest_port} every {mean:.0f}s (jitter {cv:.0%})",
                source_ip=evs[0].source_ip, related_ips=[dst], users=sorted({e.user for e in evs if e.user}),
                hosts=[evs[0].host] if evs[0].host else [], geo=evs[0].geo, last_seen=evs[-1].ts,
                window_sec=int((evs[-1].ts - evs[0].ts).total_seconds()),
                detail={"destination": dst, "port": evs[0].dest_port, "connections": len(evs),
                        "interval_sec": round(mean, 1), "jitter_cv": round(cv, 3),
                        "process": evs[0].process_name, "domain": evs[0].domain},
                evidence=[{"ts": e.ts.isoformat(), "user": e.user, "host": e.host,
                           "type": f"connect {e.dest_ip}:{e.dest_port} {e.bytes_out}B out"} for e in evs[:15]],
            ))
        return out
