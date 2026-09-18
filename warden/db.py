"""Persistence. SQLite by default, Postgres when WARDEN_DATABASE_URL points at one.

Cases are stored as a JSON document plus the columns the dashboard filters on, so the
`Case` model can evolve without a migration for every field. Everything that has to be
replayable - model calls, analyst decisions - gets its own append-only table.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

from sqlalchemy import (JSON, Column, DateTime, Float, Integer, MetaData, String, Table, Text, UniqueConstraint,
                        create_engine, event)
from sqlalchemy.engine import Engine

from .config import settings

metadata = MetaData()

cases = Table(
    "cases", metadata,
    Column("id", String(64), primary_key=True),
    Column("tenant", String(64), nullable=False, default="default", index=True),
    Column("ts", DateTime(timezone=True), index=True),
    Column("rule", String(64), index=True),
    Column("status", String(32), index=True),
    Column("verdict", String(32)),
    Column("risk", Integer),
    Column("incident_id", String(64), index=True),
    Column("doc", JSON, nullable=False),
    Column("updated", DateTime(timezone=True)),
)

incidents = Table(
    "incidents", metadata,
    Column("id", String(64), primary_key=True),
    Column("tenant", String(64), nullable=False, default="default", index=True),
    Column("ts", DateTime(timezone=True), index=True),
    Column("status", String(32), index=True),
    Column("risk", Integer),
    Column("doc", JSON, nullable=False),
    Column("updated", DateTime(timezone=True)),
)

events = Table(
    "events", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("tenant", String(64), nullable=False, default="default", index=True),
    Column("ts", DateTime(timezone=True), index=True),
    Column("kind", String(16), index=True),
    Column("source", String(64)),
    Column("user", String(256), index=True),
    Column("source_ip", String(64), index=True),
    Column("host", String(256), index=True),
    Column("dedupe", String(512), nullable=False),
    Column("doc", JSON, nullable=False),
    UniqueConstraint("tenant", "dedupe", name="uq_events_dedupe"),
)

audit = Table(
    "audit", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("tenant", String(64), nullable=False, default="default", index=True),
    Column("ts", DateTime(timezone=True), index=True),
    Column("actor", String(256), index=True),
    Column("action", String(64), index=True),
    Column("target", String(256)),
    Column("detail", JSON),
)

llm_calls = Table(
    "llm_calls", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("tenant", String(64), nullable=False, default="default", index=True),
    Column("ts", DateTime(timezone=True), index=True),
    Column("subject_id", String(64), index=True),     # alert or incident id
    Column("stage", String(32)),                       # analyze | propose | verify ...
    Column("prompt_version", String(32)),
    Column("model", String(64)),
    Column("kb_snapshot", String(64)),
    Column("retrieved", JSON),
    Column("input_tokens", Integer),
    Column("output_tokens", Integer),
    Column("cost_usd", Float),
    Column("latency_ms", Integer),
    Column("output", JSON),
    Column("error", Text),
)


iocs = Table(
    "iocs", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("type", String(16), nullable=False),          # ip | domain | url | sha256 | cve
    Column("value", String(512), nullable=False),
    Column("source", String(64), nullable=False),
    Column("confidence", Integer),                         # 0-100
    Column("tags", JSON),
    Column("first_seen", DateTime(timezone=True)),
    Column("last_seen", DateTime(timezone=True)),
    Column("updated", DateTime(timezone=True)),
    UniqueConstraint("type", "value", "source", name="uq_iocs"),
)

kb_snapshots = Table(
    "kb_snapshots", metadata,
    Column("id", String(32), primary_key=True),
    Column("ts", DateTime(timezone=True), index=True),
    Column("detail", JSON),
)

exclusions = Table(
    "exclusions", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("tenant", String(64), nullable=False, default="default", index=True),
    Column("rule", String(64), index=True),
    Column("field", String(32)),                           # user | source_ip | host
    Column("value", String(256)),
    Column("reason", String(64)),
    Column("note", Text),
    Column("created_by", String(256)),
    Column("created", DateTime(timezone=True)),
    Column("expires", DateTime(timezone=True)),
    Column("hits", Integer, default=0),
)


baselines = Table(
    "baselines", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("tenant", String(64), nullable=False, default="default", index=True),
    Column("entity_type", String(16), index=True),
    Column("entity", String(256), index=True),
    Column("days", Integer),
    Column("profile", JSON),
    Column("updated", DateTime(timezone=True)),
)


proposals = Table(
    "proposals", metadata,
    Column("id", String(32), primary_key=True),
    Column("created", DateTime(timezone=True), index=True),
    Column("updated", DateTime(timezone=True)),
    Column("trigger", String(32)),            # anomaly_tp | analyst_note | intel_gap | hunt
    Column("source", String(256)),
    Column("status", String(32), index=True),  # generated | rejected_static | failed_eval | ready_for_review | rejected | approved | pr_opened
    Column("rule_id", String(64)),
    Column("rationale", Text),
    Column("files", JSON),
    Column("checks", JSON),
    Column("eval", JSON),
    Column("review", JSON),
    Column("model", String(64)),
    Column("prompt_version", String(64)),
    Column("cost_usd", Float),
    Column("pr_url", String(512)),
    Column("evidence", JSON),                  # anonymized events the proposal was built from
)


eval_runs = Table(
    "eval_runs", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("ts", DateTime(timezone=True), index=True),
    Column("suite", String(32)),
    Column("git_sha", String(40)),
    Column("analyzer", String(64)),
    Column("metrics", JSON),
)


def _url() -> str:
    if settings.database_url:
        return settings.database_url
    path = settings.state_dir / "warden.db"
    path.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{path}"


def make_engine(url: str) -> Engine:
    eng = create_engine(url, future=True, json_serializer=lambda o: json.dumps(o, default=str))
    if url.startswith("sqlite"):
        @event.listens_for(eng, "connect")
        def _pragma(conn, _):  # WAL so the dashboard can read while the pipeline writes
            cur = conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()
    metadata.create_all(eng)
    migrate(eng)
    return eng


def migrate(eng: Engine) -> list[str]:
    """Additive migrations: any column in the model that an existing table lacks is added
    (nullable). Warden only ever adds columns, so this keeps SQLite and Postgres databases
    from older versions working without a migration framework."""
    from sqlalchemy import inspect, text
    insp = inspect(eng)
    added = []
    with eng.begin() as c:
        for table in metadata.sorted_tables:
            if not insp.has_table(table.name):
                continue
            have = {col["name"] for col in insp.get_columns(table.name)}
            for col in table.columns:
                if col.name not in have:
                    ctype = col.type.compile(dialect=eng.dialect)
                    c.execute(text(f'ALTER TABLE {table.name} ADD COLUMN "{col.name}" {ctype}'))
                    added.append(f"{table.name}.{col.name}")
    return added


@lru_cache(maxsize=8)
def engine(url: str | None = None) -> Engine:
    return make_engine(url or _url())


def engine_for_dir(state_dir: Path) -> Engine:
    state_dir.mkdir(parents=True, exist_ok=True)
    return engine(f"sqlite:///{state_dir / 'warden.db'}")


def now() -> datetime:
    return datetime.now(timezone.utc)
