"""End-to-end: logs -> alerts -> agent -> cases."""
from __future__ import annotations

from pathlib import Path

from .agent import run_alert
from .config import settings
from .detect import detect
from .ingest import load_file
from .knowledge import KnowledgeBase
from .llm import get_analyzer
from .models import Case
from .store import CaseStore


def run(log_file: Path | None = None, kb: KnowledgeBase | None = None, analyzer=None,
        store: CaseStore | None = None, rerun: bool = False, only: list[str] | None = None,
        fmt: str | None = None, events=None) -> list[Case]:
    kb = kb or KnowledgeBase()
    if kb.col.count() == 0:
        kb.index_dir()
    analyzer = analyzer or get_analyzer()
    store = store or CaseStore()

    if events is None:
        events = load_file(log_file or settings.log_file, fmt=fmt)
    store.add_events(events)
    alerts = detect(events, only=only)
    cases: list[Case] = []
    for alert in alerts:
        if store.exists(alert.id) and not rerun:
            cases.append(store.get(alert.id))
            continue
        cases.append(run_alert(alert, kb, analyzer, store))
    return cases


def run_stored(since=None, until=None, **kw) -> list[Case]:
    """Detect over events already in the database (HEC pushes, earlier imports)."""
    store = kw.pop("store", None) or CaseStore()
    return run(events=store.events(since=since, until=until), store=store, **kw)
