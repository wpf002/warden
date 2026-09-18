"""T1071.004 DNS: data smuggled in query names. Many unique, long, high-entropy
subdomains under one parent domain, or a flood of TXT lookups."""
from __future__ import annotations

import statistics
from collections import defaultdict

from ..config import settings
from ..events import NetworkEvent
from ..models import Alert
from . import Detection, register
from ._network import entropy, parent_domain, src


@register
class DnsTunneling(Detection):
    id = "dns_tunneling"
    name = "DNS tunneling"
    mitre = ["T1071.004", "T1048.003"]
    event_kinds = ("network",)
    window_sec = 3600
    playbook = "playbook-dns-tunneling"

    def run(self, events: list[NetworkEvent]) -> list[Alert]:
        groups: dict[tuple[str, str], list[NetworkEvent]] = defaultdict(list)
        for e in events:
            if e.domain and (e.protocol == "dns" or e.dns_type or e.dest_port == 53):
                groups[(src(e), parent_domain(e.domain))].append(e)
        out = []
        for (s, parent), evs in groups.items():
            subs = {e.domain.lower()[: -len(parent) - 1] for e in evs if e.domain.lower().endswith("." + parent)}
            txt = sum(1 for e in evs if e.dns_type.upper() == "TXT")
            if not subs and txt < settings.dns_txt_min:
                continue
            avg_len = statistics.mean(len(x) for x in subs) if subs else 0
            avg_ent = statistics.mean(entropy(x.replace(".", "")) for x in subs) if subs else 0
            tunnel = len(subs) >= settings.dns_min_unique and avg_len >= 20 and avg_ent >= 3.5
            if not (tunnel or txt >= settings.dns_txt_min):
                continue
            evs.sort(key=lambda e: e.ts)
            out.append(self.new_alert(
                key=f"{s}|{parent}", first_seen=evs[0].ts, ts=evs[-1].ts,
                title=f"{s} sent {len(subs)} encoded-looking lookups under {parent}"
                      + (f" and {txt} TXT queries" if txt else ""),
                source_ip=evs[0].source_ip, hosts=[evs[0].host] if evs[0].host else [], last_seen=evs[-1].ts,
                users=sorted({e.user for e in evs if e.user}),
                detail={"parent_domain": parent, "unique_subdomains": len(subs), "avg_label_len": round(avg_len, 1),
                        "avg_entropy": round(avg_ent, 2), "txt_queries": txt, "sample": sorted(subs)[:5]},
                evidence=[{"ts": e.ts.isoformat(), "user": e.user, "host": e.host, "type": f"dns {e.dns_type} {e.domain}"}
                          for e in evs[:15]],
            ))
        return out
