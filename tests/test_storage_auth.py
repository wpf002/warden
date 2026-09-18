"""SQL storage, audit trail, model-call log, and dashboard auth."""
import base64
import os
from pathlib import Path

os.environ["WARDEN_LLM"] = "mock"
os.environ["WARDEN_EMBEDDINGS"] = "hash"

import pytest
from fastapi.testclient import TestClient

from warden import auth, feedback
from warden.agent import run_alert
from warden.config import settings
from warden.detect import detect
from warden.ingest import generate_logs, load_file
from warden.knowledge import KnowledgeBase
from warden.llm import PROMPT_VERSION, MockAnalyzer
from warden.store import CaseStore

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def world(tmp_path):
    generate_logs(tmp_path / "a.jsonl", events=200)
    events = load_file(tmp_path / "a.jsonl")
    kb = KnowledgeBase(persist=False)
    kb.index_dir(ROOT / "data" / "knowledge")
    store = CaseStore(tmp_path / "state")
    return events, kb, store


def test_events_are_stored_once(world):
    events, _, store = world
    assert store.add_events(events) == len(events)
    assert store.add_events(events) == 0
    got = store.events(kind="auth", user="john.doe")
    assert got and all(e.user == "john.doe" for e in got)


def test_case_round_trip_and_filters(world):
    events, kb, store = world
    alerts = detect(events)
    for a in alerts:
        run_alert(a, kb, MockAnalyzer(), store)
    all_cases = store.all()
    assert len(all_cases) == len(alerts)
    assert {c.alert.rule for c in store.all(rule="mfa_fatigue")} == {"mfa_fatigue"}
    assert all(c.status == "awaiting_approval" for c in store.all(status="awaiting_approval"))
    c = all_cases[0]
    assert c.prompt_version == PROMPT_VERSION and c.kb_snapshot.startswith("kb-") and c.model == "mock"


def test_every_model_call_is_logged(world):
    events, kb, store = world
    alert = detect(events, only=["brute_force"])[0]
    case = run_alert(alert, kb, MockAnalyzer(), store)
    [row] = store.llm_calls(alert.id)
    assert row["prompt_version"] == PROMPT_VERSION
    assert row["retrieved"] == [d["id"] for d in case.retrieved_docs]
    assert row["output"]["risk_score"] == case.analysis.risk_score
    assert row["kb_snapshot"] == case.kb_snapshot


def test_analyst_actions_are_audited(world):
    events, kb, store = world
    alert = detect(events, only=["brute_force"])[0]
    case = run_alert(alert, kb, MockAnalyzer(), store)
    idx = next(i for i, a in enumerate(case.actions) if a.status == "pending_approval")
    feedback.approve_action(case, idx, store, actor="alice")
    feedback.record_verdict(case, "true_positive", "confirmed", store, kb, actor="bob")
    log = store.audit_log()
    assert [(r["actor"], r["action"]) for r in log] == [("bob", "verdict"), ("alice", "approve_action")]
    assert "by alice" in store.get(alert.id).guardrail_log[-1]


def test_snapshot_changes_when_kb_changes(world):
    _, kb, _ = world
    before = kb.snapshot_id()
    kb.add_learned_case("learned-x", "# note\nsomething new")
    assert kb.snapshot_id() != before


# ---------------------------------------------------------------- auth
def test_password_hashing():
    h = auth.hash_password("hunter2")
    assert auth.verify_password("hunter2", h) and not auth.verify_password("nope", h)


def _client(monkeypatch, tmp_path, mode, users=""):
    monkeypatch.setattr(settings, "auth_mode", mode)
    monkeypatch.setattr(settings, "users", users)
    from warden import dashboard
    monkeypatch.setattr(dashboard, "store", CaseStore(tmp_path / "dash"))
    return TestClient(dashboard.app)


def _basic(u, p):
    return {"Authorization": "Basic " + base64.b64encode(f"{u}:{p}".encode()).decode()}


def test_basic_auth_and_roles(monkeypatch, tmp_path):
    users = f"alice:{auth.hash_password('a')}:analyst,vic:{auth.hash_password('v')}:viewer"
    c = _client(monkeypatch, tmp_path, "basic", users)
    assert c.get("/").status_code == 401
    assert c.get("/", headers=_basic("alice", "wrong")).status_code == 401
    assert c.get("/", headers=_basic("vic", "v")).status_code == 200
    assert c.post("/classic/run", headers=_basic("vic", "v")).status_code == 403          # viewer cannot run
    assert c.post("/classic/reindex", headers=_basic("alice", "a")).status_code == 403    # analyst is not admin
    assert c.get("/classic/audit", headers=_basic("alice", "a")).status_code == 200


def test_proxy_auth_trusts_only_configured_hops(monkeypatch, tmp_path):
    c = _client(monkeypatch, tmp_path, "proxy")
    monkeypatch.setattr(settings, "trusted_proxies", "10.9.0.0/16")
    r = c.get("/", headers={"x-forwarded-user": "mallory", "x-forwarded-groups": "soc-admins"})
    assert r.status_code == 403          # TestClient's address is not a trusted proxy
    monkeypatch.setattr(auth, "_trusted", lambda host: True)
    assert c.get("/", headers={"x-forwarded-user": "carol", "x-forwarded-groups": "soc-analysts"}).status_code == 200
    assert c.post("/classic/reindex", headers={"x-forwarded-user": "carol", "x-forwarded-groups": "soc-analysts"}).status_code == 403


def test_noauth_refuses_remote_clients(monkeypatch, tmp_path):
    c = _client(monkeypatch, tmp_path, "none")
    assert c.get("/").status_code == 200          # TestClient host is "testclient"
    monkeypatch.delenv("WARDEN_ALLOW_NOAUTH", raising=False)
    remote = TestClient(c.app, client=("203.0.113.7", 5555))
    assert remote.get("/").status_code == 403


def test_verdict_rejects_bad_values(monkeypatch, tmp_path):
    c = _client(monkeypatch, tmp_path, "none")
    assert c.post("/classic/case/X/verdict", data={"verdict": "maybe"}).status_code == 422


def test_hec_receiver(monkeypatch, tmp_path):
    c = _client(monkeypatch, tmp_path, "none")
    monkeypatch.setattr(settings, "hec_token", "t0ken")
    body = ('{"time": 1788339600, "sourcetype": "linux_secure", "event": '
            '"Sep 02 09:00:03 web-01 sshd[812]: Failed password for root from 192.0.2.99 port 50123 ssh2"}'
            '{"time": 1788339601, "sourcetype": "warden", "event": {"kind": "auth", "ts": "2026-09-02T09:00:04+00:00",'
            ' "event_type": "login_success", "user": "pwong", "source_ip": "10.0.3.3"}}')
    assert c.post("/services/collector/event", content=body).status_code == 401
    r = c.post("/services/collector/event", content=body, headers={"Authorization": "Splunk t0ken"})
    assert r.status_code == 200 and r.json()["stored"] == 2
    assert c.post("/services/collector/event", content="{bad", headers={"Authorization": "Splunk t0ken"}).status_code == 400


def test_older_databases_gain_new_columns(tmp_path):
    import sqlite3
    from warden import db
    path = tmp_path / "old.db"
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE proposals (id VARCHAR(32) PRIMARY KEY, status VARCHAR(32))")
    con.commit()
    con.close()
    eng = db.make_engine(f"sqlite:///{path}")
    from sqlalchemy import inspect
    cols = {c["name"] for c in inspect(eng).get_columns("proposals")}
    assert {"evidence", "pr_url", "files"} <= cols
