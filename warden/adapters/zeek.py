"""Zeek conn.log and dns.log in JSON (LogAscii::use_json=T). The standard sensor output
for network rules: beaconing, scans, fan-out, exfil volume, DNS tunneling."""
from __future__ import annotations

from pathlib import Path
from typing import Iterator

from ..events import Event, NetworkEvent
from ._util import iter_json_records, parse_ts

NAME = "zeek"
QTYPES = {1: "A", 5: "CNAME", 15: "MX", 16: "TXT", 28: "AAAA"}


def sniff(head: str, path: Path) -> bool:
    return '"id.orig_h"' in head


def parse(path: Path) -> Iterator[Event]:
    for r in iter_json_records(path):
        common = dict(ts=parse_ts(r["ts"]), source="zeek", source_ip=r.get("id.orig_h", ""),
                      dest_ip=r.get("id.resp_h", ""), dest_port=int(r.get("id.resp_p") or 0),
                      source_port=int(r.get("id.orig_p") or 0), raw=r)
        if "query" in r:
            yield NetworkEvent(**common, protocol="dns", domain=r.get("query") or "",
                               dns_type=r.get("qtype_name") or QTYPES.get(r.get("qtype"), ""), action="allowed")
        else:
            state = r.get("conn_state", "")
            yield NetworkEvent(**common, protocol=r.get("proto", ""), domain=r.get("server_name", "") or "",
                               bytes_out=int(r.get("orig_bytes") or 0), bytes_in=int(r.get("resp_bytes") or 0),
                               action="blocked" if state in ("REJ", "S0", "RSTOS0", "RSTRH", "SH") else "allowed")
