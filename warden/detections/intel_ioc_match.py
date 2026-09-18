"""Traffic to or from an indicator in the intel table: a Feodo-listed C2 IP, an OTX
domain. Exact matching against the `iocs` table; confidence below 60 (Tor exits) is
context, not an alert."""
from __future__ import annotations

from ..events import Event
from ..models import Alert
from . import Detection, register


@register
class IntelIocMatch(Detection):
    id = "intel_ioc_match"
    name = "Connection to a known-bad indicator"
    mitre = ["T1071", "T1105"]
    event_kinds = ("network", "auth")
    window_sec = 0
    playbook = "playbook-intel-ioc-match"
    min_confidence = 60

    def run(self, events: list[Event]) -> list[Alert]:
        values = {v for e in events for v in (getattr(e, "dest_ip", ""), e.source_ip, getattr(e, "domain", "")) if v}
        hits = {v: [h for h in hs if (h.get("confidence") or 0) >= self.min_confidence]
                for v, hs in self.ioc_lookup(values).items()}
        hits = {v: hs for v, hs in hits.items() if hs}
        out, done = [], set()
        for e in sorted(events, key=lambda e: e.ts):
            for v in (getattr(e, "dest_ip", ""), getattr(e, "domain", ""), e.source_ip):
                if v in hits and (e.host or e.source_ip, v) not in done:
                    done.add((e.host or e.source_ip, v))
                    h = hits[v][0]
                    tags = h.get("tags") or {}
                    out.append(self.new_alert(
                        key=f"{e.host or e.source_ip}|{v}", first_seen=e.ts, ts=e.ts,
                        title=f"{e.host or e.source_ip} contacted {v}, listed by {h['source']}"
                              + (f" ({tags.get('malware')})" if tags.get("malware") else ""),
                        source_ip=e.source_ip, related_ips=[v] if v != e.source_ip and v[0].isdigit() else [],
                        users=[e.user] if e.user else [], hosts=[e.host] if e.host else [], geo=e.geo,
                        last_seen=e.ts, detail={"indicator": v, "matches": hits[v], "event_kind": e.kind},
                        evidence=[{"ts": e.ts.isoformat(), "user": e.user, "host": e.host,
                                   "type": f"{e.kind} involving {v}"}],
                    ))
        return out
