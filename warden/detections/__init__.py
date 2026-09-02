"""Detection registry.

Adding a detection means adding a file in this package with a `Detection` subclass
decorated with `@register`. The pipeline iterates the registry; nothing else changes.

Detections are deterministic. The LLM never decides whether something is an alert.
"""
from __future__ import annotations

import hashlib
import importlib
import pkgutil
from datetime import datetime
from pathlib import Path

from ..config import settings
from ..events import Event
from ..models import Alert

REGISTRY: dict[str, "Detection"] = {}


def alert_id(rule: str, key: str, first_seen: datetime) -> str:
    """Stable id: same burst on the same entity yields the same id across runs."""
    return "ALT-" + hashlib.sha1(f"{rule}|{key}|{first_seen.isoformat()}".encode()).hexdigest()[:8].upper()


class Detection:
    """One rule. Subclasses set the class attributes and implement `run`."""

    id: str = ""
    name: str = ""
    mitre: list[str] = []
    event_kinds: tuple[str, ...] = ("auth",)
    window_sec: int = 300
    playbook: str = ""               # knowledge base doc id, e.g. "playbook-brute-force"
    enabled: bool = True

    def run(self, events: list[Event]) -> list[Alert]:  # pragma: no cover - interface
        raise NotImplementedError

    # helpers available to every detection
    def _select(self, events: list[Event]) -> list[Event]:
        return [e for e in events if e.kind in self.event_kinds]

    def new_alert(self, key: str, first_seen: datetime, **kw) -> Alert:
        kw.setdefault("window_sec", self.window_sec)
        return Alert(
            id=alert_id(self.id, key, first_seen),
            rule=self.id,
            mitre=list(self.mitre),
            playbook=self.playbook,
            first_seen=first_seen,
            **kw,
        )

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"<Detection {self.id} {self.mitre}>"


def register(cls: type[Detection]) -> type[Detection]:
    if not cls.id:
        raise ValueError(f"{cls.__name__} needs an id")
    if cls.id in REGISTRY:
        raise ValueError(f"duplicate detection id {cls.id}")
    REGISTRY[cls.id] = cls()
    return cls


def load_all() -> dict[str, Detection]:
    """Import every module in this package so decorators fire. Idempotent."""
    for mod in pkgutil.iter_modules([str(Path(__file__).parent)]):
        if not mod.name.startswith("_"):
            importlib.import_module(f"{__name__}.{mod.name}")
    return REGISTRY


def active(only: list[str] | None = None) -> list[Detection]:
    """Detections to run: explicit `only`, else WARDEN_DETECTIONS, else all enabled."""
    load_all()
    names = only or settings.detections or None
    if names:
        missing = [n for n in names if n not in REGISTRY]
        if missing:
            raise KeyError(f"unknown detection(s): {', '.join(missing)}; have {sorted(REGISTRY)}")
        return [REGISTRY[n] for n in names]
    return [d for d in REGISTRY.values() if d.enabled]


def run_all(events: list[Event], only: list[str] | None = None) -> list[Alert]:
    alerts: list[Alert] = []
    for det in active(only):
        alerts.extend(det.run(det._select(events)))
    alerts.sort(key=lambda a: (a.ts, a.rule, a.id))
    return alerts
