"""Source adapters. One module per log source, each turning raw records into Events.

    load(path)                 autodetect the format
    load(path, fmt="okta")     force it

Each adapter module exposes:
    NAME      registry key
    sniff(head: str, path) -> bool      cheap detection from the first few KB
    parse(path) -> Iterator[Event]
"""
from __future__ import annotations

import importlib
import pkgutil
from pathlib import Path
from types import ModuleType
from typing import Iterator

from ..events import Event

_ADAPTERS: dict[str, ModuleType] = {}
# sniff order matters: specific formats before the generic JSON fallback
ORDER = ["splunk", "windows", "okta", "entra", "cloudtrail", "o365", "zeek", "elastic", "sshd", "generic"]


def adapters() -> dict[str, ModuleType]:
    if not _ADAPTERS:
        for mod in pkgutil.iter_modules([str(Path(__file__).parent)]):
            if not mod.name.startswith("_"):
                m = importlib.import_module(f"{__name__}.{mod.name}")
                _ADAPTERS[m.NAME] = m
    return _ADAPTERS


def detect_format(path: Path) -> str:
    path = Path(path)
    if path.suffix.lower() == ".evtx":
        return "windows"
    head = path.read_bytes()[:8192].decode("utf-8", "replace")
    if not head.strip():
        return "generic"
    reg = adapters()
    for name in ORDER:
        if name in reg and reg[name].sniff(head, path):
            return name
    raise ValueError(f"could not detect log format of {path}; pass fmt= one of {sorted(reg)}")


def iter_events(path: Path, fmt: str | None = None) -> Iterator[Event]:
    fmt = fmt or detect_format(path)
    try:
        mod = adapters()[fmt]
    except KeyError:
        raise KeyError(f"unknown format {fmt!r}; have {sorted(adapters())}") from None
    yield from mod.parse(Path(path))
