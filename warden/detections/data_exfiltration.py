"""T1048 / T1041 Exfiltration: a large outbound transfer from one host to an external
destination it has not talked to before."""
from __future__ import annotations

from collections import defaultdict

from ..config import settings
from ..events import NetworkEvent
from ..models import Alert
from . import Detection, register
from ._network import is_internal, src


@register
class DataExfiltration(Detection):
    id = "data_exfiltration"
    name = "Large upload to a new external destination"
    mitre = ["T1048", "T1041", "T1567"]
    event_kinds = ("network",)
    window_sec = 3600
    playbook = "playbook-data-exfiltration"
    needs_history = True

    def run(self, events: list[NetworkEvent]) -> list[Alert]:
        seen = {(src(e), e.dest_ip) for e in self.prior if e.kind == "network"}
        totals: dict[tuple[str, str], list[NetworkEvent]] = defaultdict(list)
        for e in events:
            if e.dest_ip and not is_internal(e.dest_ip) and e.bytes_out:
                totals[(src(e), e.dest_ip)].append(e)
        out = []
        for (s, dst), evs in totals.items():
            sent = sum(e.bytes_out for e in evs)
            new = (s, dst) not in seen
            if sent < settings.exfil_bytes or not new:
                continue
            evs.sort(key=lambda e: e.ts)
            out.append(self.new_alert(
                key=f"{s}|{dst}", first_seen=evs[0].ts, ts=evs[-1].ts,
                title=f"{s} sent {sent / 1e6:,.0f} MB to new destination {dst}" + (f" ({evs[0].domain})" if evs[0].domain else ""),
                source_ip=evs[0].source_ip, related_ips=[dst], hosts=[evs[0].host] if evs[0].host else [],
                users=sorted({e.user for e in evs if e.user}), last_seen=evs[-1].ts, asset_tier=evs[0].asset_tier,
                detail={"destination": dst, "bytes_out": sent, "connections": len(evs), "domain": evs[0].domain,
                        "port": evs[0].dest_port, "process": evs[0].process_name, "new_destination": new},
                evidence=[{"ts": e.ts.isoformat(), "user": e.user, "host": e.host,
                           "type": f"upload {e.bytes_out / 1e6:.1f}MB to {dst}:{e.dest_port}"} for e in evs[:15]],
            ))
        return out
