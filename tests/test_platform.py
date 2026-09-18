"""Phase 7: model routing, provider abstraction, observability."""
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import httpx
from fastapi.testclient import TestClient

from warden import obs, tenancy
from warden.agent import run_alert
from warden.knowledge import KnowledgeBase
from warden.llm import MockAnalyzer, OpenAICompatibleAnalyzer, RoutingAnalyzer, get_analyzer
from warden.models import Alert
from warden.store import CaseStore

T = datetime(2026, 9, 1, tzinfo=timezone.utc)


def A(**kw):
    return Alert(**{**dict(id="A1", ts=T, rule="brute_force", title="t", first_seen=T, last_seen=T, source_ip="203.0.113.5",
                           users=["jdoe"], failed_attempts=12), **kw})


class Tag(MockAnalyzer):
    def __init__(self, name):
        self.model = name
        self.last_usage = {"model": name}


def test_routing_sends_heavy_subjects_to_the_strong_model():
    r = RoutingAnalyzer(Tag("strong"), Tag("triage"))
    assert r.pick(A()).model == "triage"
    assert r.pick(A(asset_tier="crown_jewel")).model == "strong"
    assert r.pick(A(rule="credential_dumping")).model == "strong"
    assert r.pick(A(rule="anomaly.user")).model == "strong"
    assert r.pick(A(members=[A(id="m1"), A(id="m2")])).model == "strong"
    r.analyze(A(), [])
    assert r.last_usage["stage"] == "triage" and r.model == "triage"


def test_tenant_policy_selects_provider_and_models(monkeypatch):
    from warden.config import settings
    d = tenancy.tenant_dir("t-local")
    d.mkdir(parents=True)
    (d / "policy.json").write_text(json.dumps({"llm": {"provider": "openai", "base_url": "http://localhost:11434/v1",
                                                       "model": "llama3.3:70b", "model_triage": "llama3.2:3b"}}))
    an = get_analyzer("t-local")
    assert isinstance(an, RoutingAnalyzer) and an.strong.model == "llama3.3:70b" and an.triage.model == "llama3.2:3b"
    assert str(an.strong.http.base_url).startswith("http://localhost:11434")
    monkeypatch.setattr(settings, "llm_provider", "mock")
    assert isinstance(get_analyzer("default"), MockAnalyzer)


def test_openai_compatible_request_and_parse():
    seen = {}
    good = {"explanation": "12 failures for jdoe", "mitre_attack": "T1110.001", "risk_score": 80, "severity": "high",
            "false_positive_likelihood": "low", "recommended_actions": [{"action": "notify", "target": "soc", "reason": "x"}],
            "citations": []}

    def handler(req):
        seen["body"] = json.loads(req.content)
        seen["auth"] = req.headers.get("authorization")
        return httpx.Response(200, json={"model": "gpt-x", "choices": [{"message": {"content": json.dumps(good)}}],
                                         "usage": {"prompt_tokens": 900, "completion_tokens": 120}})
    an = OpenAICompatibleAnalyzer("gpt-x", "https://llm.example/v1", "sk-test", transport=httpx.MockTransport(handler))
    out = an.analyze(A(), [{"id": "d#0", "text": "playbook"}])
    assert out.risk_score == 80 and an.last_usage["input_tokens"] == 900
    b = seen["body"]
    assert b["response_format"]["type"] == "json_schema" and b["messages"][0]["role"] == "system"
    assert "<context>" in b["messages"][1]["content"] and seen["auth"] == "Bearer sk-test"


def test_case_carries_its_trace_and_metrics_move(tmp_path):
    before = obs.render()[0].decode()
    case = run_alert(A(), KnowledgeBase(persist=False), MockAnalyzer(), CaseStore(tmp_path))
    names = [s["span"] for s in case.spans]
    assert names[:2] == ["retrieve", "analyze"] and all(s["ms"] >= 0 for s in case.spans)
    after = obs.render()[0].decode()
    assert 'warden_cases_total{kind="alert"}' in after
    assert after.count("warden_actions_total{") >= before.count("warden_actions_total{")


def test_metrics_endpoint_and_token(monkeypatch):
    from warden import dashboard
    from warden.config import settings
    c = TestClient(dashboard.app)
    assert c.get("/metrics").status_code == 200 and b"warden_stage_seconds" in c.get("/metrics").content
    monkeypatch.setattr(settings, "metrics_token", "m3tr1cs")
    assert c.get("/metrics").status_code == 401
    assert c.get("/metrics", headers={"Authorization": "Bearer m3tr1cs"}).status_code == 200
    assert c.get("/healthz").json() == {"ok": True}


def test_json_logs_carry_trace_ids():
    rec = logging.LogRecord("warden", logging.INFO, __file__, 1, "case analyzed", None, None)
    rec.fields = {"case": "A1", "risk": 80}
    tok = obs.new_trace("A1")
    try:
        line = json.loads(obs.JsonFormatter().format(rec))
    finally:
        obs._trace.reset(tok)
    assert line["trace_id"] == "A1" and line["risk"] == 80 and line["msg"] == "case analyzed"
