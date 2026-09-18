"""Phase 7: two tenants in one deployment stay isolated, through storage, knowledge, policy,
the API, and HEC. Plus the API's role checks."""
import base64
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from warden import auth, feedback, guardrails, tenancy
from warden.agent import run_alert
from warden.config import settings
from warden.detect import detect
from warden.ingest import generate_logs, load_file
from warden.knowledge import KnowledgeBase
from warden.llm import MockAnalyzer
from warden.models import Analysis, RecommendedAction
from warden.store import CaseStore

ROOT = Path(__file__).resolve().parents[1]


def _basic(u, p):
    return {"Authorization": "Basic " + base64.b64encode(f"{u}:{p}".encode()).decode()}


@pytest.fixture()
def two_tenants(tmp_path, monkeypatch):
    from warden import api, dashboard
    monkeypatch.setattr(settings, "database_url", f"sqlite:///{tmp_path / 'shared.db'}")
    api.store_for.cache_clear()
    api.kb_for.cache_clear()
    monkeypatch.setattr(dashboard, "store", CaseStore(tmp_path / "default"))
    stores = {t: api.store_for(t) for t in ("acme", "globex")}
    generate_logs(tmp_path / "a.jsonl", events=150)
    kb = KnowledgeBase(persist=False)
    kb.index_dir(ROOT / "data" / "knowledge")
    for a in detect(load_file(tmp_path / "a.jsonl"), only=["brute_force"]):
        run_alert(a, kb, MockAnalyzer(), stores["acme"])
    users = ",".join([f"alice:{auth.hash_password('a')}:admin:acme", f"gary:{auth.hash_password('g')}:admin:globex",
                      f"vic:{auth.hash_password('v')}:viewer:acme"])
    monkeypatch.setattr(settings, "auth_mode", "basic")
    monkeypatch.setattr(settings, "users", users)
    yield TestClient(dashboard.app), stores
    api.store_for.cache_clear()
    api.kb_for.cache_clear()


def test_storage_is_scoped_by_tenant(two_tenants):
    _, stores = two_tenants
    assert stores["acme"].all() and stores["globex"].all() == []
    cid = stores["acme"].all()[0].alert.id
    assert stores["globex"].get(cid) is None and stores["globex"].llm_calls(cid) == []


def test_api_serves_each_tenant_only_its_own_cases(two_tenants):
    c, stores = two_tenants
    cid = stores["acme"].all()[0].alert.id
    assert [x["id"] for x in c.get("/api/v1/cases", headers=_basic("alice", "a")).json()] == [cid]
    assert c.get("/api/v1/cases", headers=_basic("gary", "g")).json() == []
    assert c.get(f"/api/v1/cases/{cid}", headers=_basic("gary", "g")).status_code == 404
    assert c.get(f"/api/v1/cases/{cid}", headers=_basic("alice", "a")).json()["summary"]["id"] == cid


def test_api_role_checks(two_tenants):
    c, stores = two_tenants
    cid = stores["acme"].all()[0].alert.id
    assert c.get("/api/v1/me", headers=_basic("vic", "v")).json() == {"name": "vic", "role": "viewer", "tenant": "acme",
                                                                      "auth_mode": "basic"}
    assert c.post(f"/api/v1/cases/{cid}/verdict", json={"verdict": "true_positive"}, headers=_basic("vic", "v")).status_code == 403
    r = c.post(f"/api/v1/cases/{cid}/verdict", json={"verdict": "true_positive", "note": "ok"}, headers=_basic("alice", "a"))
    assert r.status_code == 200 and r.json()["analyst_verdict"] == "true_positive"
    assert c.get("/api/v1/audit", headers=_basic("alice", "a")).json()[0]["actor"] == "alice"
    assert c.get("/api/v1/audit", headers=_basic("gary", "g")).json() == []


def test_learned_cases_do_not_cross_tenants(two_tenants):
    _, stores = two_tenants
    case = stores["acme"].all()[0]
    kb_a = KnowledgeBase(persist=False, tenant="acme")
    feedback.record_verdict(case, "false_positive", "zz-unique-acme-note", stores["acme"], kb_a, actor="alice",
                            reason="other")
    assert (tenancy.tenant_dir("acme") / "knowledge" / f"learned-{case.alert.id.lower()}.md").exists()
    kb_g = KnowledgeBase(persist=False, tenant="globex")
    assert not any("zz-unique-acme-note" in d["text"] for d in kb_g.retrieve("zz-unique-acme-note", 10))
    assert any("zz-unique-acme-note" in d["text"] for d in kb_a.retrieve("zz-unique-acme-note", 10))


def test_tenant_playbook_overrides_global(tmp_path):
    d = tenancy.tenant_dir("acme") / "knowledge"
    d.mkdir(parents=True)
    (d / "playbook-brute-force.md").write_text("# Acme brute force playbook\n\nacme-specific-marker call the NOC")
    kb = KnowledgeBase(persist=False, tenant="acme")
    kb.index_dir(ROOT / "data" / "knowledge")
    kb.sync()
    hits = kb.retrieve("brute force playbook containment", 10)
    bf = [h for h in hits if h["doc"] == "playbook-brute-force"]
    assert bf and all(h["id"].startswith("t:acme:") for h in bf)
    other = KnowledgeBase(persist=False, tenant="globex")
    other.index_dir(ROOT / "data" / "knowledge")
    assert not any("acme-specific-marker" in h["text"] for h in other.retrieve("brute force playbook", 10))


def test_tenant_policy_changes_guardrails():
    d = tenancy.tenant_dir("strict")
    d.mkdir(parents=True)
    (d / "policy.json").write_text(json.dumps({"auto_action_min_risk": 99, "ip_safelist": ["203.0.113.42"]}))
    from datetime import datetime, timezone
    from warden.models import Alert
    t = datetime(2026, 9, 1, tzinfo=timezone.utc)
    a = Alert(id="A1", ts=t, rule="brute_force", title="x", first_seen=t, last_seen=t, source_ip="198.51.100.9",
              related_ips=["203.0.113.42"])
    an = Analysis(explanation="x", mitre_attack="T1110", risk_score=95, severity="critical", false_positive_likelihood="low",
                  recommended_actions=[RecommendedAction(action="block_ip", target="198.51.100.9"),
                                       RecommendedAction(action="block_ip", target="203.0.113.42")])
    default = [d.verdict for d in guardrails.evaluate(a, an, policy=tenancy.policy("default"))]
    strict = [d.verdict for d in guardrails.evaluate(a, an, policy=tenancy.policy("strict"))]
    assert default == ["execute", "execute"] and strict == ["approve", "deny"]


def test_hec_routes_by_token(two_tenants, monkeypatch):
    c, stores = two_tenants
    monkeypatch.setattr(settings, "hec_tokens", "acme:tokA,globex:tokG")
    body = '{"time": 1788339600, "event": {"kind": "auth", "ts": "2026-09-02T09:00:04+00:00", "event_type": "login_success", "user": "zed", "source_ip": "10.9.9.9"}}'
    r = c.post("/services/collector/event", content=body, headers={"Authorization": "Splunk tokG"})
    assert r.json()["tenant"] == "globex"
    assert [e.user for e in stores["globex"].events()] == ["zed"]
    assert not any(e.user == "zed" for e in stores["acme"].events())
