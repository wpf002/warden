"""Phase 5: baselines, explainable anomaly scoring, approval-only guardrails, the tuning loop."""
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from warden import baselines, feedback, guardrails
from warden.agent import run_alert
from warden.correlate import correlate
from warden.detect import detect
from warden.events import AuthEvent, ProcessEvent
from warden.ingest import load_file, normalize
from warden.knowledge import KnowledgeBase
from warden.llm import MockAnalyzer
from warden.models import Analysis, RecommendedAction
from warden.store import CaseStore

ROOT = Path(__file__).resolve().parents[1]
CASE = ROOT / "data" / "eval" / "29-planted-unknown-recon"
T0 = datetime(2026, 8, 1, tzinfo=timezone.utc)


def routine(user, days, hosts=("ws-a", "srv-1")):
    out = []
    for d in range(days):
        for h in range(3):
            out.append(AuthEvent(ts=T0 + timedelta(days=d, hours=9 + h), event_type="login_success", user=user,
                                 host=hosts[h % len(hosts)], source_ip="10.0.0.5", geo="internal"))
        out.append(ProcessEvent(ts=T0 + timedelta(days=d, hours=10), host="ws-a", user=user, process_name="outlook.exe",
                                parent_name="explorer.exe"))
    return normalize(out)


@pytest.fixture(scope="module")
def planted():
    prior, events = load_file(CASE / "history.jsonl"), load_file(CASE / "events.jsonl")
    return prior, events, detect(events, prior=prior, only=["anomaly.user", "anomaly.host"])


def test_profile_accumulates_numeric_and_seen_values():
    p = baselines.build_profiles(routine("bob", 10))[("user", "bob")]
    assert p.days == 10 and p.numeric["logins"] == [3.0] * 10
    assert set(p.seen["hosts"]) == {"ws-a", "srv-1"} and p.seen["hours"]["9"] == 10


def test_every_alert_explains_itself(planted):
    _, _, alerts = planted
    user = next(a for a in alerts if a.rule == "anomaly.user")
    kinds = {c["kind"] for c in user.detail["contributions"]}
    assert {"volume", "new_value"} <= kinds
    assert any("nltest.exe" in c["why"] for c in user.detail["contributions"])
    assert user.detail["score"] >= 8 and user.mitre == []


def test_benign_novelty_stays_under_threshold(planted):
    _, _, alerts = planted
    assert not any(a.detail["entity"] == "rkhan" for a in alerts)


def test_needs_enough_history():
    prior = routine("new", 3)
    today = normalize([AuthEvent(ts=T0 + timedelta(days=3, hours=3), event_type="login_success", user="new",
                                 host=f"srv-{i}", source_ip="10.0.0.5", geo="internal") for i in range(9)])
    assert detect(today, prior=prior, only=["anomaly.user"]) == []


def test_peer_common_values_weigh_less():
    prof = baselines.build_profiles(routine("bob", 10))[("user", "bob")]
    feats = {"num": {}, "sets": {"hosts": {"srv-9"}}}
    alone = baselines.score_day(prof, feats)[0].score
    peers = {("user", "hosts"): __import__("collections").Counter({"srv-9": 5})}
    shared = baselines.score_day(prof, feats, peers=peers)[0].score
    assert shared < alone


def test_muted_feature_is_not_scored(planted):
    prior, events, _ = planted
    muted = {("dkim", "hosts"), ("dkim", "distinct_hosts"), ("dkim", "logins"), ("dkim", "processes_set")}
    alerts = detect(events, prior=prior, only=["anomaly.user"], suppressed_features=muted)
    assert not any(a.detail["entity"] == "dkim" for a in alerts)


def test_anomaly_actions_are_approval_only(planted):
    _, _, alerts = planted
    [inc] = [s for s in correlate(alerts) if s.is_incident]
    an = Analysis(explanation="x", mitre_attack="T1087", risk_score=99, severity="critical", false_positive_likelihood="low",
                  recommended_actions=[RecommendedAction(action="isolate_host", target="ws-dkim"),
                                       RecommendedAction(action="notify", target="soc")])
    assert [d.verdict for d in guardrails.evaluate(inc, an)] == ["approve", "execute"]


def test_rule_evidence_still_auto_executes_inside_a_mixed_incident(planted):
    from warden.events import ProcessEvent
    _, events, alerts = planted
    recon_end = max(e.ts for e in events if e.user == "dkim")
    rule = detect(normalize([ProcessEvent(ts=recon_end + timedelta(minutes=10), host="ws-dkim", user="dkim",
                                          action="log_cleared", target="Security")]))
    inc = next(s for s in correlate(alerts + rule) if s.is_incident)
    an = Analysis(explanation="x", mitre_attack="T1070", risk_score=95, severity="critical", false_positive_likelihood="low",
                  recommended_actions=[RecommendedAction(action="isolate_host", target="ws-dkim")])
    assert guardrails.evaluate(inc, an)[0].verdict == "execute"


def test_false_positive_teaches_the_baseline(tmp_path, planted):
    prior, events, alerts = planted
    store = CaseStore(tmp_path)
    baselines.save_profiles(store, baselines.build_profiles(prior))
    kb = KnowledgeBase(persist=False)
    user = next(a for a in alerts if a.rule == "anomaly.user")
    case = run_alert(user, kb, MockAnalyzer(), store)
    feedback.record_verdict(case, "false_positive", "new DC project", store, kb, actor="ana", reason="other", suppress=True)
    prof = baselines.load_profiles(store)[("user", "dkim")]
    assert "dc-01" in prof.seen["hosts"] and "nltest.exe" in prof.seen["processes_set"]
    muted = [e for e in store.exclusions() if e["field"].startswith("feature:")]
    assert muted and all(e["value"] == "dkim" for e in muted)
    again = detect(events, prior=prior, only=["anomaly.user"], profiles=baselines.load_profiles(store),
                   suppressed_features={(e["value"], e["field"].split(":", 1)[1]) for e in muted})
    assert not any(a.detail["entity"] == "dkim" for a in again)


def test_update_skips_anomalous_days(tmp_path):
    store = CaseStore(tmp_path)
    profiles = baselines.build_profiles(routine("bob", 10))
    day = normalize([AuthEvent(ts=T0 + timedelta(days=10, hours=3), event_type="login_success", user="bob",
                               host="dc-01", source_ip="10.0.0.5", geo="internal")])
    baselines.update(store, profiles, day, skip={("user", "bob", (T0 + timedelta(days=10)).date().isoformat())})
    assert "dc-01" not in profiles[("user", "bob")].seen["hosts"]
    baselines.update(store, profiles, day, skip=set())
    assert "dc-01" in baselines.load_profiles(store)[("user", "bob")].seen["hosts"]
