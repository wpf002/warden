"""JSON API for the web console (and anything else). Mounted at /api/v1 by dashboard.py.

Every route resolves the caller (auth.current_user), scopes storage to the caller's tenant,
and checks the role the action needs. The console is a static single-page app that only
talks to this API.
"""
from __future__ import annotations

import time
from functools import lru_cache
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from . import feedback
from .auth import User, require
from .config import settings
from .store import CaseStore

router = APIRouter(prefix="/api/v1")


@lru_cache(maxsize=64)
def store_for(tenant: str) -> CaseStore:
    return CaseStore(tenant=tenant)


@lru_cache(maxsize=64)
def kb_for(tenant: str):
    from .knowledge import KnowledgeBase
    kb = KnowledgeBase(tenant=tenant)
    kb.sync()
    return kb


def _store(user: User) -> CaseStore:
    from . import dashboard
    # the default tenant shares the dashboard's store object (tests swap it)
    return dashboard.store if user.tenant == dashboard.store.tenant else store_for(user.tenant)


# ---------------------------------------------------------------- summaries
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def summary(c) -> dict:
    a, an = c.alert, c.analysis
    return {
        "id": a.id, "title": a.title, "ts": a.ts, "first_seen": a.first_seen, "last_seen": a.last_seen,
        "rules": a.rules(), "is_incident": a.is_incident, "mitre": a.mitre[:8],
        "severity": an.severity if an else None, "risk": an.risk_score if an else None,
        "fp_likelihood": an.false_positive_likelihood if an else None,
        "status": c.status, "verdict": c.analyst_verdict, "suppressed": c.suppressed_by is not None,
        "users": a.users[:6], "hosts": a.hosts[:6], "ips": sorted(a.all_ips())[:6], "asset_tier": a.asset_tier,
        "pending": sum(x.status == "pending_approval" for x in c.actions),
        "executed": sum(x.status == "executed" for x in c.actions),
        "sources": sorted({m.detail.get("source", "") or "rule" for m in (a.members or [a])}),
    }


@router.get("/me")
def me(user: User = Depends(require("viewer"))):
    return {"name": user.name, "role": user.role, "tenant": user.tenant, "auth_mode": settings.auth_mode}


@router.get("/overview")
def overview(user: User = Depends(require("viewer"))):
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import func, select

    from . import db
    st = _store(user)
    cases = st.all(limit=2000)
    open_ = [c for c in cases if c.status != "closed"]
    now = datetime.now(timezone.utc)
    with st.engine.connect() as conn:
        cost = conn.execute(select(func.coalesce(func.sum(db.llm_calls.c.cost_usd), 0.0)).where(
            db.llm_calls.c.tenant == st.tenant, db.llm_calls.c.ts >= now - timedelta(days=1))).scalar()
        calls = conn.execute(select(func.count()).where(
            db.llm_calls.c.tenant == st.tenant, db.llm_calls.c.ts >= now - timedelta(days=1))).scalar()
    by_sev: dict = {}
    for c in open_:
        k = c.analysis.severity if c.analysis else "unscored"
        by_sev[k] = by_sev.get(k, 0) + 1
    acts = [x for c in cases for x in c.actions]
    return {
        "open": len(open_), "awaiting_approval": sum(c.status == "awaiting_approval" for c in cases),
        "incidents_open": sum(c.alert.is_incident for c in open_), "by_severity": by_sev,
        "verdicts": {"true_positive": sum(c.analyst_verdict == "true_positive" for c in cases),
                     "false_positive": sum(c.analyst_verdict == "false_positive" for c in cases)},
        "actions": {s: sum(x.status == s for x in acts) for s in ("executed", "pending_approval", "denied", "failed", "rolled_back")},
        "model_calls_24h": calls, "model_cost_24h": round(float(cost or 0), 4),
        "suppressed": sum(c.suppressed_by is not None for c in cases),
    }


@router.get("/cases")
def cases(status: Optional[str] = None, q: Optional[str] = None, rule: Optional[str] = None, limit: int = 200,
          user: User = Depends(require("viewer"))):
    out = [summary(c) for c in _store(user).all(status=status if status in ("open", "awaiting_approval", "closed") else None,
                                                limit=2000)]
    if status == "active":
        out = [c for c in out if c["status"] != "closed"]
    if rule:
        out = [c for c in out if rule in c["rules"]]
    if q:
        ql = q.lower()
        out = [c for c in out if ql in " ".join([c["id"], c["title"], *c["users"], *c["hosts"], *c["ips"], *c["rules"]]).lower()]
    out.sort(key=lambda c: (c["status"] == "closed", SEV_ORDER.get(c["severity"] or "", 9), -(c["risk"] or 0)))
    return out[:limit]


@router.get("/cases/{case_id}")
def case(case_id: str, user: User = Depends(require("viewer"))):
    c = _store(user).get(case_id)
    if not c:
        raise HTTPException(404, "no such case")
    d = c.model_dump(mode="json")
    d["summary"] = summary(c)
    d["llm_calls"] = [{k: v for k, v in r.items() if k in ("ts", "model", "prompt_version", "kb_snapshot", "input_tokens",
                                                           "output_tokens", "cost_usd", "latency_ms", "error")}
                      for r in _store(user).llm_calls(case_id)]
    return d


class VerdictIn(BaseModel):
    verdict: str
    note: str = ""
    reason: str = ""
    suppress: bool = False


@router.post("/cases/{case_id}/verdict")
def verdict(case_id: str, body: VerdictIn, user: User = Depends(require("analyst"))):
    st = _store(user)
    c = st.get(case_id) or _404()
    try:
        feedback.record_verdict(c, body.verdict, body.note, st, kb_for(user.tenant), actor=user.name,
                                reason=body.reason, suppress=body.suppress)
    except ValueError as e:
        raise HTTPException(422, str(e)) from None
    return case(case_id, user)


@router.post("/cases/{case_id}/actions/{idx}/{op}")
def action(case_id: str, idx: int, op: str, user: User = Depends(require("analyst"))):
    st = _store(user)
    c = st.get(case_id) or _404()
    if not 0 <= idx < len(c.actions):
        raise HTTPException(404, "no such action")
    fn = {"approve": feedback.approve_action, "deny": feedback.deny_action, "rollback": feedback.rollback_action}.get(op)
    if not fn:
        raise HTTPException(404, "unknown operation")
    try:
        fn(c, idx, st, actor=user.name)
    except ValueError as e:
        raise HTTPException(422, str(e)) from None
    return case(case_id, user)


@router.get("/detections")
def detections(user: User = Depends(require("viewer"))):
    from .detect import load_all
    from .stats import detection_stats, threshold_bump
    st = detection_stats(_store(user))
    out = []
    for d in sorted(load_all().values(), key=lambda d: d.id):
        s = st.get(d.id)
        out.append({"id": d.id, "name": d.name, "mitre": d.mitre, "event_kinds": list(d.event_kinds),
                    "playbook": d.playbook, "fired": s.fired if s else 0, "tp": s.tp if s else 0, "fp": s.fp if s else 0,
                    "fp_rate": s.fp_rate if s else None, "threshold_bump": threshold_bump(s),
                    "fp_reasons": s.fp_reasons if s else {}, "weekly": s.weekly if s else [],
                    "last_fired": s.last_fired if s else None,
                    "domain": "anomaly" if d.id.startswith("anomaly.") else
                    "identity" if set(d.event_kinds) & {"auth", "identity"} and "process" not in d.event_kinds else
                    "cloud" if "cloud" in d.event_kinds else "network" if "network" in d.event_kinds else "endpoint"})
    return out


@router.get("/kb")
def kb_docs(kind: Optional[str] = None, user: User = Depends(require("viewer"))):
    from .tenancy import knowledge_dirs
    docs = []
    for scope, d in knowledge_dirs(user.tenant):
        for f in sorted(d.glob("*.md")):
            k = f.stem.split("-")[0]
            if kind and k != kind:
                continue
            first = f.read_text().splitlines()[0].lstrip("# ").strip() if f.stat().st_size else f.stem
            docs.append({"doc": f.stem, "kind": k, "title": first, "scope": scope, "bytes": f.stat().st_size})
    return docs


@router.get("/kb/search")
def kb_search(q: str, k: int = 8, user: User = Depends(require("viewer"))):
    return kb_for(user.tenant).retrieve(q, k)


@router.get("/kb/{doc}")
def kb_doc(doc: str, user: User = Depends(require("viewer"))):
    from .tenancy import knowledge_dirs
    for scope, d in reversed(knowledge_dirs(user.tenant)):     # tenant copy wins
        f = d / f"{doc}.md"
        if f.exists() and f.resolve().parent == d.resolve():
            return {"doc": doc, "scope": scope, "text": f.read_text()}
    if doc.startswith("attack-"):
        f = settings.attack_dir / f"{doc[7:]}.md"
        if f.exists() and f.resolve().parent == settings.attack_dir.resolve():
            return {"doc": doc, "scope": "attack", "text": f.read_text()}
    raise HTTPException(404, "no such document")


@router.get("/proposals")
def proposals_list(user: User = Depends(require("viewer"))):
    from . import proposals
    return [{k: v for k, v in p.items() if k not in ("files",)} for p in proposals.list_proposals(_store(user).engine)]


@router.get("/proposals/{pid}")
def proposal(pid: str, user: User = Depends(require("viewer"))):
    from . import proposals
    return proposals.get(pid, _store(user).engine) or _404()


class ReviewIn(BaseModel):
    decision: str
    note: str = ""


@router.post("/proposals/{pid}/review")
def proposal_review(pid: str, body: ReviewIn, user: User = Depends(require("admin"))):
    from . import proposals
    try:
        return proposals.review(pid, body.decision, user.name, body.note, store=_store(user))
    except (KeyError, ValueError) as e:
        raise HTTPException(422, str(e)) from None


@router.get("/audit")
def audit(limit: int = 300, user: User = Depends(require("viewer"))):
    return _store(user).audit_log(limit)


@router.get("/exclusions")
def exclusions(user: User = Depends(require("viewer"))):
    return _store(user).exclusions()


@router.post("/exclusions/{ex_id}/expire")
def expire(ex_id: int, user: User = Depends(require("analyst"))):
    _store(user).expire_exclusion(ex_id, user.name)
    return {"ok": True}


@router.get("/eval/history")
def eval_history(user: User = Depends(require("viewer"))):
    from sqlalchemy import select

    from . import db
    with _store(user).engine.connect() as c:
        rows = c.execute(select(db.eval_runs).order_by(db.eval_runs.c.ts)).all()
    return [dict(r._mapping) for r in rows]


@router.get("/connectors")
def connectors_view(user: User = Depends(require("viewer"))):
    from . import connectors
    from .tenancy import policy
    pol = policy(user.tenant)
    mapping = {a: n for a, n in (p.split("=") for p in pol.connectors.split(",") if "=" in p)}
    acts = ["block_ip", "lock_user", "isolate_host", "disable_access_key", "notify", "create_ticket"]
    return {"live": settings.live_actions, "available": connectors.available(),
            "actions": [{"action": a, "connector": mapping.get(a, "mock"), "can_rollback": connectors.can_rollback(a),
                         "auto": a in pol.auto_actions or a in ("notify", "create_ticket")} for a in acts]}


@router.post("/run")
def run_now(user: User = Depends(require("analyst"))):
    from .llm import get_analyzer
    from .pipeline import run_stored
    t0 = time.monotonic()
    cases_ = run_stored(store=_store(user), kb=kb_for(user.tenant), analyzer=get_analyzer())
    return {"cases": len(cases_), "seconds": round(time.monotonic() - t0, 2)}


def _404():
    raise HTTPException(404, "not found")
