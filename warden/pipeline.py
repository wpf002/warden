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
        store: CaseStore | None = None, rerun: bool = False, only: list[str] | None = None) -> list[Case]:
    kb = kb or KnowledgeBase()
    if kb.col.count() == 0:
        kb.index_dir()
    analyzer = analyzer or get_analyzer()
    store = store or CaseStore()

    events = load_file(log_file or settings.log_file)
    alerts = detect(events, only=only)
    cases: list[Case] = []
    for alert in alerts:
        if store.exists(alert.id) and not rerun:
            cases.append(store.get(alert.id))
            continue
        cases.append(run_alert(alert, kb, analyzer, store))
    return cases
