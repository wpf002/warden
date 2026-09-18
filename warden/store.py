"""Case persistence behind the v0.1 `CaseStore` interface, now on SQL (see db.py).

`CaseStore(path)` keeps working for tests and scripts: it opens a SQLite file inside
that directory. With no path it uses WARDEN_DATABASE_URL, or data/state/warden.db.
"""
from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import delete, insert, select, update

from . import db
from .config import settings
from .models import Case


class CaseStore:
    def __init__(self, path: Path | None = None, tenant: str | None = None):
        self.engine = db.engine_for_dir(Path(path)) if path else db.engine()
        self.tenant = tenant or settings.tenant

    # ---------------------------------------------------------------- cases
    def save(self, case: Case) -> None:
        a = case.alert
        row = dict(tenant=self.tenant, ts=a.ts, rule=a.rule, status=case.status, verdict=case.analyst_verdict,
                   risk=case.analysis.risk_score if case.analysis else None, incident_id=case.incident_id,
                   doc=json.loads(case.model_dump_json()), updated=db.now())
        with self.engine.begin() as c:
            hit = c.execute(select(db.cases.c.id).where(db.cases.c.id == a.id, db.cases.c.tenant == self.tenant)).first()
            if hit:
                c.execute(update(db.cases).where(db.cases.c.id == a.id, db.cases.c.tenant == self.tenant).values(**row))
            else:
                c.execute(insert(db.cases).values(id=a.id, **row))

    def get(self, alert_id: str) -> Case | None:
        with self.engine.connect() as c:
            r = c.execute(select(db.cases.c.doc).where(db.cases.c.id == alert_id,
                                                       db.cases.c.tenant == self.tenant)).first()
        return Case.model_validate(r[0]) if r else None

    def all(self, status: str | None = None, rule: str | None = None, limit: int | None = None) -> list[Case]:
        q = select(db.cases.c.doc).where(db.cases.c.tenant == self.tenant).order_by(db.cases.c.ts.desc())
        if status:
            q = q.where(db.cases.c.status == status)
        if rule:
            q = q.where(db.cases.c.rule == rule)
        if limit:
            q = q.limit(limit)
        with self.engine.connect() as c:
            return [Case.model_validate(r[0]) for r in c.execute(q)]

    def exists(self, alert_id: str) -> bool:
        with self.engine.connect() as c:
            return c.execute(select(db.cases.c.id).where(db.cases.c.id == alert_id,
                                                         db.cases.c.tenant == self.tenant)).first() is not None

    def delete_all(self) -> None:
        with self.engine.begin() as c:
            c.execute(delete(db.cases).where(db.cases.c.tenant == self.tenant))

    # ---------------------------------------------------------------- events
    def add_events(self, evs) -> int:
        """Insert normalized events, skipping ones already stored. Returns rows added."""
        rows = [dict(tenant=self.tenant, ts=e.ts, kind=e.kind, source=e.source, user=e.user,
                     source_ip=e.source_ip, host=e.host, dedupe=e.dedupe_key()[:512],
                     doc=json.loads(e.model_dump_json(exclude={"raw"}))) for e in evs]
        if not rows:
            return 0
        with self.engine.begin() as c:
            have = {r[0] for r in c.execute(select(db.events.c.dedupe).where(
                db.events.c.tenant == self.tenant, db.events.c.dedupe.in_([r["dedupe"] for r in rows])))}
            new = [r for r in rows if r["dedupe"] not in have]
            seen: set[str] = set()
            new = [r for r in new if not (r["dedupe"] in seen or seen.add(r["dedupe"]))]
            if new:
                c.execute(insert(db.events), new)
        return len(new)

    def events(self, since=None, until=None, kind: str | None = None, user: str | None = None):
        from .events import parse_event
        q = select(db.events.c.doc).where(db.events.c.tenant == self.tenant).order_by(db.events.c.ts)
        if since:
            q = q.where(db.events.c.ts >= since)
        if until:
            q = q.where(db.events.c.ts < until)
        if kind:
            q = q.where(db.events.c.kind == kind)
        if user:
            q = q.where(db.events.c.user == user)
        with self.engine.connect() as c:
            return [parse_event(r[0]) for r in c.execute(q)]

    # ---------------------------------------------------------------- audit
    def audit(self, actor: str, action: str, target: str = "", **detail) -> None:
        with self.engine.begin() as c:
            c.execute(insert(db.audit).values(tenant=self.tenant, ts=db.now(), actor=actor, action=action,
                                              target=target, detail=detail))

    def audit_log(self, limit: int = 200) -> list[dict]:
        q = (select(db.audit).where(db.audit.c.tenant == self.tenant)
             .order_by(db.audit.c.ts.desc(), db.audit.c.id.desc()).limit(limit))
        with self.engine.connect() as c:
            return [dict(r._mapping) for r in c.execute(q)]

    # ---------------------------------------------------------------- model calls
    def log_llm_call(self, **row) -> None:
        with self.engine.begin() as c:
            c.execute(insert(db.llm_calls).values(tenant=self.tenant, ts=db.now(), **row))

    def llm_calls(self, subject_id: str | None = None, limit: int = 200) -> list[dict]:
        q = select(db.llm_calls).where(db.llm_calls.c.tenant == self.tenant).order_by(db.llm_calls.c.id.desc()).limit(limit)
        if subject_id:
            q = q.where(db.llm_calls.c.subject_id == subject_id)
        with self.engine.connect() as c:
            return [dict(r._mapping) for r in c.execute(q)]

    # ---------------------------------------------------------------- exclusions
    def add_exclusion(self, rule: str, field: str, value: str, reason: str, note: str = "",
                      actor: str = "system", days: int | None = None) -> int:
        from datetime import timedelta
        days = days if days is not None else settings.exclusion_days
        with self.engine.begin() as c:
            r = c.execute(insert(db.exclusions).values(
                tenant=self.tenant, rule=rule, field=field, value=value, reason=reason, note=note,
                created_by=actor, created=db.now(), expires=db.now() + timedelta(days=days), hits=0))
            return r.inserted_primary_key[0]

    def exclusions(self, active_only: bool = True) -> list[dict]:
        q = select(db.exclusions).where(db.exclusions.c.tenant == self.tenant).order_by(db.exclusions.c.id.desc())
        if active_only:
            q = q.where(db.exclusions.c.expires > db.now())
        with self.engine.connect() as c:
            return [dict(r._mapping) for r in c.execute(q)]

    def exclusion_hit(self, ex_id: int) -> None:
        with self.engine.begin() as c:
            c.execute(update(db.exclusions).where(db.exclusions.c.id == ex_id)
                      .values(hits=db.exclusions.c.hits + 1))

    def expire_exclusion(self, ex_id: int, actor: str) -> None:
        with self.engine.begin() as c:
            c.execute(update(db.exclusions).where(db.exclusions.c.id == ex_id, db.exclusions.c.tenant == self.tenant)
                      .values(expires=db.now()))
        self.audit(actor, "expire_exclusion", str(ex_id))
