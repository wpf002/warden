"""End-to-end: logs -> alerts -> agent -> cases."""
from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from .agent import run_alert
from .config import settings
from .correlate import correlate
from .detect import detect
from .ingest import load_file
from .knowledge import KnowledgeBase
from .llm import get_analyzer
from .models import Case
from .store import CaseStore


def run(log_file: Path | None = None, kb: KnowledgeBase | None = None, analyzer=None,
        store: CaseStore | None = None, rerun: bool = False, only: list[str] | None = None,
        fmt: str | None = None, events=None) -> list[Case]:
    if kb is None:
        kb = KnowledgeBase()
        kb.sync()
    analyzer = analyzer or get_analyzer()
    store = store or CaseStore()

    if events is None:
        events = load_file(log_file or settings.log_file, fmt=fmt)
    prior = []
    if events:
        start = min(e.ts for e in events)
        prior = store.events(since=start - timedelta(days=settings.history_days), until=start)
    store.add_events(events)
    alerts = detect(events, only=only, prior=prior)
    subjects = correlate(alerts)
    cases: list[Case] = []
    for subject in subjects:
        if store.exists(subject.id) and not rerun:
            cases.append(store.get(subject.id))
            continue
        cases.append(run_alert(subject, kb, analyzer, store))
    return cases


def run_stored(since=None, until=None, **kw) -> list[Case]:
    """Detect over events already in the database (HEC pushes, earlier imports)."""
    store = kw.pop("store", None) or CaseStore()
    return run(events=store.events(since=since, until=until), store=store, **kw)
