import os
from pathlib import Path

os.environ["WARDEN_LLM"] = "mock"
os.environ["WARDEN_EMBEDDINGS"] = "hash"

import pytest

from warden import guardrails
from warden.detect import detect_brute_force
from warden.ingest import generate_logs, load_file, from_syslog_sshd
from warden.knowledge import KnowledgeBase, chunk
from warden.llm import MockAnalyzer
from warden.models import Analysis, RecommendedAction
from warden.agent import run_alert
from warden.store import CaseStore


@pytest.fixture(scope="module")
def events(tmp_path_factory):
    p = tmp_path_factory.mktemp("logs") / "auth.jsonl"
    generate_logs(p, events=400, attackers=2)
    return load_file(p)


def test_ingest_dedupes_and_enriches(events):
    assert len(events) == len({e.dedupe_key() for e in events})
    assert all(e.geo for e in events)
    assert any(e.asset_tier == "crown_jewel" for e in events)


def test_sshd_adapter():
    e = from_syslog_sshd("Sep 02 12:00:01 web-01 sshd[123]: Failed password for invalid user bob from 1.2.3.4 port 22 ssh2")
    assert e and e.user == "bob" and e.source_ip == "1.2.3.4" and e.event_type == "login_failure"


def test_detects_both_attacks(events):
    alerts = detect_brute_force(events, threshold=10, window_sec=300)
    rules = {a.rule: a for a in alerts}
    assert "brute_force" in rules and "password_spray" in rules
    assert rules["brute_force"].success_after_failures is True
    assert rules["password_spray"].success_after_failures is False
    assert len(rules["password_spray"].users) >= 3


def test_background_noise_does_not_alert(events):
    internal = [e for e in events if e.geo == "internal"]
    assert detect_brute_force(internal, threshold=10, window_sec=300) == []


def test_chunking_splits_on_headings():
    cs = chunk("# A\n\npara\n\n## B\n\npara2")
    assert len(cs) == 2


def test_guardrails_enforce_policy(events):
    alert = [a for a in detect_brute_force(events) if a.rule == "brute_force"][0]
    an = Analysis(explanation="x", mitre_attack="T1110", risk_score=95, severity="critical", false_positive_likelihood="low",
                  recommended_actions=[
                      RecommendedAction(action="block_ip", target=alert.source_ip),
                      RecommendedAction(action="block_ip", target="10.0.0.1"),          # safelisted
                      RecommendedAction(action="block_ip", target="8.8.8.8"),           # hallucinated
                      RecommendedAction(action="lock_user", target=alert.users[0]),     # needs approval
                      RecommendedAction(action="lock_user", target="ceo"),              # hallucinated
                      RecommendedAction(action="notify", target="soc"),
                  ])
    v = [d.verdict for d in guardrails.evaluate(alert, an)]
    assert v == ["execute", "deny", "deny", "approve", "deny", "execute"]


def test_low_risk_blocks_wait_for_approval(events):
    alert = [a for a in detect_brute_force(events) if a.rule == "brute_force"][0]
    an = Analysis(explanation="x", mitre_attack="T1110", risk_score=40, severity="medium", false_positive_likelihood="medium",
                  recommended_actions=[RecommendedAction(action="block_ip", target=alert.source_ip)])
    assert guardrails.evaluate(alert, an)[0].verdict == "approve"


def test_end_to_end_graph(events, tmp_path):
    kb = KnowledgeBase(persist=False)
    kb.index_dir(Path(__file__).resolve().parents[1] / "data" / "knowledge")
    store = CaseStore(tmp_path)
    alert = [a for a in detect_brute_force(events) if a.rule == "brute_force"][0]
    case = run_alert(alert, kb, MockAnalyzer(), store)
    assert case.retrieved_docs and any("brute-force" in d["doc"] for d in case.retrieved_docs)
    assert case.analysis.risk_score >= 80
    statuses = {a.action: a.status for a in case.actions}
    assert statuses["block_ip"] == "executed"
    assert statuses["lock_user"] == "pending_approval"
    assert case.status == "awaiting_approval"
    assert store.get(alert.id) is not None
