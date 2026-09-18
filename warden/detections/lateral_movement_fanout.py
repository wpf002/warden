"""T1021 Remote Services: one internal host opening SMB, RDP, WinRM, RPC, or SSH to many
internal hosts in a few minutes. Admin tools do this on a schedule; worms and operators
do it all at once."""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from ..config import settings
from ..events import NetworkEvent
from ..models import Alert
from . import Detection, register
from ._network import is_internal, src

PORTS = {445: "T1021.002", 3389: "T1021.001", 5985: "T1021.006", 5986: "T1021.006", 135: "T1021.003", 22: "T1021.004"}


@register
class LateralMovementFanout(Detection):
    id = "lateral_movement_fanout"
    name = "Remote-service fan-out to many hosts"
    mitre = ["T1021"]
    event_kinds = ("network",)
    window_sec = 600
    playbook = "playbook-lateral-movement"

    def run(self, events: list[NetworkEvent]) -> list[Alert]:
        window = timedelta(seconds=self.window_sec)
        by_src: dict[str, list[NetworkEvent]] = defaultdict(list)
        for e in events:
            if e.dest_port in PORTS and is_internal(e.dest_ip) and (not e.source_ip or is_internal(e.source_ip)):
                by_src[src(e)].append(e)
        out = []
        for s, evs in by_src.items():
            evs.sort(key=lambda e: e.ts)
            i = 0
            while i < len(evs):
                j = i
                while j + 1 < len(evs) and evs[j + 1].ts - evs[i].ts <= window:
                    j += 1
                burst = evs[i:j + 1]
                targets = {e.dest_ip for e in burst}
                if len(targets) >= settings.lateral_min_hosts:
                    ports = sorted({e.dest_port for e in burst})
                    out.append(self.new_alert(
                        key=f"{s}|{burst[0].ts.isoformat()}", first_seen=burst[0].ts, ts=burst[-1].ts,
                        title=f"{s} reached {len(targets)} hosts over {', '.join(map(str, ports))} in "
                              f"{int((burst[-1].ts - burst[0].ts).total_seconds() // 60) + 1} min",
                        source_ip=burst[0].source_ip, related_ips=sorted(targets)[:50],
                        users=sorted({e.user for e in burst if e.user}), hosts=[burst[0].host] if burst[0].host else [],
                        last_seen=burst[-1].ts, asset_tier=burst[0].asset_tier,
                        detail={"targets": len(targets), "ports": ports, "process": burst[0].process_name},
                        evidence=[{"ts": e.ts.isoformat(), "user": e.user, "host": e.host,
                                   "type": f"connect {e.dest_ip}:{e.dest_port}"} for e in burst[:20]],
                    ))
                    out[-1].mitre = sorted({PORTS[p] for p in ports})
                    i = j + 1
                else:
                    i += 1
        return out
