"""Detection entry point.

Rules themselves live in `warden/detections/` and register themselves. This module is
the thin front door the pipeline and the CLI call, plus a back-compat shim for the
single-function API v0.1 shipped with.

Detection stays deterministic. The LLM never decides whether something IS an alert,
only how to explain and respond to one. Keep it that way.
"""
from __future__ import annotations

from .detections import REGISTRY, active, alert_id, load_all, run_all  # noqa: F401
from .events import Event
from .models import Alert


def detect(events: list[Event], only: list[str] | None = None, prior: list[Event] | None = None,
           ioc_lookup=None, suppressed_features: set | None = None, profiles: dict | None = None) -> list[Alert]:
    """Run every enabled detection over the events it declares an appetite for."""
    return run_all(events, only=only, prior=prior, ioc_lookup=ioc_lookup,
                   suppressed_features=suppressed_features, profiles=profiles)


def detect_brute_force(events, threshold: int | None = None, window_sec: int | None = None) -> list[Alert]:
    """Back-compat: the T1110 family only, with the old positional tuning knobs."""
    load_all()
    out = []
    for name in ("brute_force", "password_spray"):
        out.extend(REGISTRY[name].run(REGISTRY[name]._select(events), threshold=threshold, window_sec=window_sec))
    out.sort(key=lambda a: a.ts)
    return out
