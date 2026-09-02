"""Stage 8. Analyst verdicts close the loop: approve/deny pending actions, mark TP/FP,
and write the outcome back into the knowledge base so the next similar alert retrieves it."""
from __future__ import annotations

from datetime import datetime, timezone

from . import actions
from .config import settings
from .knowledge import KnowledgeBase
from .models import Case, RecommendedAction
from .store import CaseStore


def approve_action(case: Case, idx: int, store: CaseStore) -> Case:
    a = case.actions[idx]
    if a.status == "pending_approval":
        case.actions[idx] = actions.execute(case.alert, RecommendedAction(action=a.action, target=a.target))
        case.guardrail_log.append(f"APPROVED {a.action}({a.target}) by analyst")
    _refresh_status(case)
    store.save(case)
    return case


def deny_action(case: Case, idx: int, store: CaseStore) -> Case:
    a = case.actions[idx]
    if a.status == "pending_approval":
        a.status = "denied"
        a.detail = "denied by analyst"
        case.guardrail_log.append(f"DENIED   {a.action}({a.target}) by analyst")
    _refresh_status(case)
    store.save(case)
    return case


def record_verdict(case: Case, verdict: str, note: str, store: CaseStore, kb: KnowledgeBase) -> Case:
    case.analyst_verdict = verdict  # type: ignore[assignment]
    case.analyst_note = note
    case.status = "closed"
    store.save(case)

    # Write a learned case. This is the "update knowledge base" arrow in the diagram.
    a = case.alert
    text = (
        f"# Learned case {a.id} ({verdict.replace('_', ' ')})\n\n"
        f"Rule {a.rule}: {a.failed_attempts} failures from {a.source_ip} (geo {a.geo}) against "
        f"{', '.join(a.users)} on {', '.join(a.hosts) or 'unknown host'}"
        + (", followed by a successful login" if a.success_after_failures else "") + ".\n"
        f"Analyst verdict: {verdict.replace('_', ' ')}. "
        + (f"Note: {note}\n" if note else "\n")
        + (f"Model said risk {case.analysis.risk_score}, severity {case.analysis.severity}.\n" if case.analysis else "")
        + f"Recorded {datetime.now(timezone.utc).date().isoformat()}.\n"
    )
    doc_id = f"learned-{a.id.lower()}"
    settings.knowledge_dir.mkdir(parents=True, exist_ok=True)
    (settings.knowledge_dir / f"{doc_id}.md").write_text(text)
    kb.add_learned_case(doc_id, text)
    return case


def _refresh_status(case: Case) -> None:
    if case.status != "closed":
        case.status = "awaiting_approval" if any(x.status == "pending_approval" for x in case.actions) else "open"
