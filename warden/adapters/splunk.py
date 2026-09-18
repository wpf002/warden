"""Splunk. Reads the NDJSON that `/services/search/jobs/export?output_mode=json` streams,
or a saved-search JSON export. Each result is routed on its `_raw`: Windows XML goes
to the Windows adapter, sshd lines to the sshd adapter, anything else is field-mapped.

The HEC receiver (live push from Splunk forwarders) lives in the API, see warden/api.py.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from ..events import Event
from . import generic, sshd, windows
from ._util import iter_json_records

NAME = "splunk"


def sniff(head: str, path: Path) -> bool:
    return '"result"' in head and ('"_raw"' in head or '"_time"' in head)


def from_result(r: dict) -> Event | None:
    raw = r.get("_raw", "")
    if isinstance(raw, str) and "schemas.microsoft.com/win/2004/08/events/event" in raw:
        eid, sysd, data = windows._parse_xml(raw)
        return windows.to_event(eid, sysd, data)
    if isinstance(raw, str) and "sshd[" in raw:
        return sshd.parse_line(raw)
    rec = dict(r)
    rec.setdefault("ts", r.get("_time"))
    rec.setdefault("source", r.get("sourcetype", "splunk"))
    if isinstance(raw, str) and raw.startswith("{"):
        try:
            rec = {**json.loads(raw), **{k: v for k, v in rec.items() if not k.startswith("_")}}
            rec.setdefault("ts", r.get("_time"))
        except json.JSONDecodeError:
            pass
    return generic.to_event(rec)


def parse(path: Path) -> Iterator[Event]:
    for rec in iter_json_records(path):
        r = rec.get("result", rec)
        ev = from_result(r)
        if ev is not None:
            yield ev
