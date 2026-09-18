"""End-to-end: logs -> alerts -> agent -> cases."""
from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from .agent import run_alert
from .config import settings
from . import intel
from .correlate import correlate
from .stats import detection_stats
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
        kb.record_snapshot(store.engine if store else None)
    analyzer = analyzer or get_analyzer()
    store = store or CaseStore()

    if events is None:
        events = load_file(log_file or settings.log_file, fmt=fmt)
    prior = []
    if events:
        start = min(e.ts for e in events)
        prior = store.events(since=start - timedelta(days=settings.history_days), until=start)
    store.add_events(events)
    alerts = intel.enrich(detect(events, only=only, prior=prior), store.engine)
    subjects = correlate(alerts)
    stats = detection_stats(store)
    exclusions = store.exclusions()
    cases: list[Case] = []
    for subject in subjects:
        if store.exists(subject.id) and not rerun:
            cases.append(store.get(subject.id))
            continue
        ex = suppressed_by(subject, exclusions)
        if ex:
            store.exclusion_hit(ex["id"])
            case = Case(alert=subject, status="closed", suppressed_by=ex["id"],
                        incident_id=subject.id if subject.is_incident else None,
                        guardrail_log=[f"SUPPRESSED by exclusion #{ex['id']}: {ex['rule']} {ex['field']}={ex['value']} "
                                       f"({ex['reason']}, set by {ex['created_by']}). No analysis, no actions."])
            store.save(case)
            cases.append(case)
            continue
        cases.append(run_alert(subject, kb, analyzer, store, stats))
    return cases


def run_stored(since=None, until=None, **kw) -> list[Case]:
    """Detect over events already in the database (HEC pushes, earlier imports)."""
    store = kw.pop("store", None) or CaseStore()
    return run(events=store.events(since=since, until=until), store=store, **kw)


def suppressed_by(subject, exclusions: list[dict]) -> dict | None:
    """An exclusion mutes an alert when rule and entity match. An incident is muted only
    when every member is: one excluded step inside a bigger chain still gets analyzed."""
    from .detections._identity import norm_user

    def hit(a) -> dict | None:
        for ex in exclusions:
            if ex["rule"] != a.rule:
                continue
            if ex["field"] == "user" and norm_user(ex["value"]) in {norm_user(u) for u in a.users}:
                return ex
            if ex["field"] == "source_ip" and ex["value"] in a.all_ips():
                return ex
            if ex["field"] == "host" and ex["value"] in a.hosts:
                return ex
        return None

    hits = [hit(m) for m in (subject.members or [subject])]
    return hits[0] if hits and all(hits) else None
