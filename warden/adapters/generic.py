"""Warden's own JSON shape (what gen-logs writes) and the fallback for flat JSON exports.
`kind` picks the Event subclass; v0.1 records without it are auth events."""
from __future__ import annotations

from pathlib import Path
from typing import Iterator

from ..events import Event, parse_event
from ._util import iter_json_records, parse_ts

NAME = "generic"


def sniff(head: str, path: Path) -> bool:
    return head.lstrip().startswith(("{", "["))


def to_event(rec: dict) -> Event | None:
    if "ts" not in rec:
        return None
    # keep a source-provided raw record (CloudTrail requestParameters, M365 Parameters); else the row itself
    rec = {**rec, "ts": parse_ts(rec["ts"]), "raw": rec["raw"] if isinstance(rec.get("raw"), dict) else rec}
    try:
        return parse_event(rec)
    except Exception:  # noqa: BLE001 - one bad row must not kill the file
        return None


def parse(path: Path) -> Iterator[Event]:
    for rec in iter_json_records(path):
        ev = to_event(rec)
        if ev is not None:
            yield ev
