"""Response connectors. Phase 4.

Each connector implements one or more actions against a real product, with:
    execute(target, alert) -> Receipt     what was done, with enough detail to undo it
    rollback(receipt)      -> Receipt     undo it
    dry_run                                 when true, validate and describe, change nothing

WARDEN_CONNECTORS maps actions to connectors, e.g.
    block_ip=aws_nacl,lock_user=okta,isolate_host=crowdstrike,notify=slack,create_ticket=jira

Anything unmapped uses the `mock` connector, which records what it would have done.
Real connectors run in dry-run mode unless WARDEN_LIVE_ACTIONS=1.

Guardrails consult `can_rollback(action)`: an action whose connector cannot undo itself
is never auto-executed, whatever the risk score (ROADMAP Phase 4).
"""
from __future__ import annotations

import importlib
import pkgutil
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..config import settings

_REGISTRY: dict[str, type["Connector"]] = {}


@dataclass
class Receipt:
    connector: str
    action: str
    target: str
    ok: bool
    detail: str
    dry_run: bool = False
    undo: dict[str, Any] = field(default_factory=dict)     # what rollback needs
    ts: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def as_dict(self) -> dict:
        return asdict(self)


class Connector:
    name = ""
    actions: tuple[str, ...] = ()
    supports_rollback = False

    def __init__(self, dry_run: bool | None = None, **opts):
        self.dry_run = (not settings.live_actions) if dry_run is None else dry_run
        self.opts = opts

    def execute(self, action: str, target: str, alert) -> Receipt:  # pragma: no cover - interface
        raise NotImplementedError

    def rollback(self, receipt: Receipt) -> Receipt:
        return Receipt(self.name, receipt.action, receipt.target, False, f"{self.name} cannot roll back {receipt.action}")

    def _dry(self, action: str, target: str, what: str, undo: dict | None = None) -> Receipt:
        return Receipt(self.name, action, target, True, f"[dry-run] would {what}", dry_run=True, undo=undo or {})


def register(cls: type[Connector]) -> type[Connector]:
    _REGISTRY[cls.name] = cls
    return cls


_LOADED = False


def _load() -> dict[str, type[Connector]]:
    global _LOADED
    if not _LOADED:
        for mod in pkgutil.iter_modules([str(Path(__file__).parent)]):
            if not mod.name.startswith("_"):
                importlib.import_module(f"{__name__}.{mod.name}")
        _LOADED = True
    return _REGISTRY


def mapping() -> dict[str, str]:
    out = {}
    for pair in filter(None, (p.strip() for p in settings.connectors.split(","))):
        action, _, name = pair.partition("=")
        out[action.strip()] = name.strip()
    return out


_INSTANCES: dict[str, Connector] = {}


def for_action(action: str) -> Connector:
    name = mapping().get(action, "mock")
    reg = _load()
    if name not in reg:
        raise KeyError(f"unknown connector {name!r} for {action}; have {sorted(reg)}")
    if name not in _INSTANCES:
        _INSTANCES[name] = reg[name]()
    conn = _INSTANCES[name]
    if action not in conn.actions:
        raise ValueError(f"connector {name} does not implement {action}")
    return conn


def reset() -> None:
    """Drop cached instances (tests, or after changing WARDEN_CONNECTORS)."""
    _INSTANCES.clear()


def can_rollback(action: str) -> bool:
    try:
        return for_action(action).supports_rollback
    except (KeyError, ValueError):
        return False


def available() -> dict[str, tuple[str, ...]]:
    return {n: c.actions for n, c in sorted(_load().items())}
