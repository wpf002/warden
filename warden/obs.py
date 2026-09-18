"""Observability. Phase 7.

    logs     WARDEN_LOG_FORMAT=json gives one JSON object per line with trace ids
    metrics  Prometheus counters and histograms per pipeline stage, served at /metrics
    traces   span("name") records timed spans under the current trace (a case id, or a run
             id); each case carries its own span list, and every span is logged

Nothing here is required: without prometheus_client the metrics are no-ops.
"""
from __future__ import annotations

import contextvars
import json
import logging
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone

from .config import settings

log = logging.getLogger("warden")
_trace: contextvars.ContextVar[str] = contextvars.ContextVar("warden_trace", default="")
_spans: contextvars.ContextVar[list | None] = contextvars.ContextVar("warden_spans", default=None)


class JsonFormatter(logging.Formatter):
    def format(self, r: logging.LogRecord) -> str:
        d = {"ts": datetime.fromtimestamp(r.created, timezone.utc).isoformat(), "level": r.levelname.lower(),
             "logger": r.name, "msg": r.getMessage(), "trace_id": _trace.get() or None}
        d.update(getattr(r, "fields", {}) or {})
        if r.exc_info:
            d["exc"] = self.formatException(r.exc_info)
        return json.dumps({k: v for k, v in d.items() if v is not None}, default=str)


def setup_logging() -> None:
    h = logging.StreamHandler()
    h.setFormatter(JsonFormatter() if settings.log_format == "json" else logging.Formatter("%(levelname)s %(name)s %(message)s"))
    root = logging.getLogger("warden")
    root.handlers[:] = [h]
    root.setLevel(settings.log_level.upper())
    root.propagate = False


def event(msg: str, **fields) -> None:
    log.info(msg, extra={"fields": fields})


# ---------------------------------------------------------------- metrics
try:
    from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Counter, Histogram, generate_latest

    REGISTRY = CollectorRegistry(auto_describe=True)
    EVENTS = Counter("warden_events_ingested_total", "Events ingested", ["kind", "source"], registry=REGISTRY)
    INGEST_LAG = Histogram("warden_ingest_lag_seconds", "Event time to ingest time", registry=REGISTRY,
                           buckets=(1, 5, 30, 60, 300, 900, 3600, 21600, 86400, float("inf")))
    STAGE = Histogram("warden_stage_seconds", "Pipeline stage duration", ["stage"], registry=REGISTRY)
    RULE = Histogram("warden_detection_seconds", "Per-rule detection time", ["rule"], registry=REGISTRY,
                     buckets=(0.001, 0.005, 0.02, 0.1, 0.5, 2, 10, float("inf")))
    ALERTS = Counter("warden_alerts_total", "Alerts raised", ["rule"], registry=REGISTRY)
    LLM_SECONDS = Histogram("warden_llm_seconds", "Model call latency", ["model", "stage"], registry=REGISTRY,
                            buckets=(0.5, 1, 2, 5, 10, 20, 40, 80, 160, float("inf")))
    LLM_COST = Counter("warden_llm_cost_usd_total", "Model spend", ["model"], registry=REGISTRY)
    LLM_TOKENS = Counter("warden_llm_tokens_total", "Model tokens", ["model", "direction"], registry=REGISTRY)
    ACTIONS = Counter("warden_actions_total", "Response actions by outcome", ["action", "status"], registry=REGISTRY)
    CASES = Counter("warden_cases_total", "Cases written", ["kind"], registry=REGISTRY)

    def render() -> tuple[bytes, str]:
        return generate_latest(REGISTRY), CONTENT_TYPE_LATEST
except ImportError:  # pragma: no cover
    class _Noop:
        def labels(self, *a, **k):
            return self

        def inc(self, *a, **k):
            pass

        def observe(self, *a, **k):
            pass

    EVENTS = INGEST_LAG = STAGE = RULE = ALERTS = LLM_SECONDS = LLM_COST = LLM_TOKENS = ACTIONS = CASES = _Noop()

    def render() -> tuple[bytes, str]:
        return b"# prometheus_client not installed\n", "text/plain"


# ---------------------------------------------------------------- traces
def new_trace(trace_id: str | None = None) -> contextvars.Token:
    return _trace.set(trace_id or uuid.uuid4().hex[:16])


def current_trace() -> str:
    return _trace.get()


@contextmanager
def collect_spans():
    """Collect the spans recorded inside this block (the agent keeps them on the case)."""
    buf: list = []
    tok = _spans.set(buf)
    try:
        yield buf
    finally:
        _spans.reset(tok)


@contextmanager
def span(name: str, **attrs):
    t0 = time.perf_counter()
    start = datetime.now(timezone.utc)
    err = None
    try:
        yield
    except Exception as e:
        err = f"{type(e).__name__}: {e}"
        raise
    finally:
        ms = round((time.perf_counter() - t0) * 1000, 2)
        STAGE.labels(name).observe(ms / 1000)
        rec = {"span": name, "ms": ms, "start": start.isoformat(), **attrs}
        if err:
            rec["error"] = err
        buf = _spans.get()
        if buf is not None:
            buf.append(rec)
        log.debug("span", extra={"fields": rec})
