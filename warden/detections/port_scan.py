"""T1046 Network Service Discovery: one source probing many ports on a host (vertical)
or one port across many hosts (horizontal)."""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from ..config import settings
from ..events import NetworkEvent
from ..models import Alert
from . import Detection, register


@register
class PortScan(Detection):
    id = "port_scan"
    name = "Port scan"
    mitre = ["T1046"]
    event_kinds = ("network",)
    window_sec = 300
    playbook = "playbook-port-scan"

    def run(self, events: list[NetworkEvent]) -> list[Alert]:
        window = timedelta(seconds=self.window_sec)
        by_src: dict[str, list[NetworkEvent]] = defaultdict(list)
        for e in events:
            if e.source_ip and e.dest_ip and e.protocol != "dns":
                by_src[e.source_ip].append(e)
        out = []
        n = settings.scan_min_targets
        for s, evs in by_src.items():
            evs.sort(key=lambda e: e.ts)
            first, last = evs[0].ts, evs[-1].ts
            if last - first > window * 12:   # long-lived talkers are not scans; look inside a window
                evs = [e for e in evs if e.ts - first <= window]
            vertical: dict[str, set[int]] = defaultdict(set)
            horizontal: dict[int, set[str]] = defaultdict(set)
            for e in evs:
                vertical[e.dest_ip].add(e.dest_port)
                horizontal[e.dest_port].add(e.dest_ip)
            v = max(vertical.items(), key=lambda kv: len(kv[1]))
            h = max(horizontal.items(), key=lambda kv: len(kv[1]))
            if len(v[1]) < n and len(h[1]) < n:
                continue
            kind = "vertical" if len(v[1]) >= len(h[1]) else "horizontal"
            title = (f"{s} probed {len(v[1])} ports on {v[0]}" if kind == "vertical"
                     else f"{s} probed port {h[0]} on {len(h[1])} hosts")
            blocked = sum(1 for e in evs if e.action == "blocked" or (not e.bytes_in and not e.bytes_out))
            out.append(self.new_alert(
                key=f"{s}|{kind}|{first.isoformat()}", first_seen=first, ts=evs[-1].ts, title=title,
                source_ip=s, related_ips=[v[0]] if kind == "vertical" else sorted(h[1])[:50],
                hosts=sorted({e.host for e in evs if e.host})[:5], geo=evs[0].geo, last_seen=evs[-1].ts,
                detail={"scan": kind, "ports": len(v[1]), "hosts": len(h[1]), "no_response_share": round(blocked / len(evs), 2)},
                evidence=[{"ts": e.ts.isoformat(), "user": e.user, "host": e.host,
                           "type": f"{e.action or 'conn'} {e.dest_ip}:{e.dest_port}"} for e in evs[:20]],
            ))
        return out
