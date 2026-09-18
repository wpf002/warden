"""Phase 3: intel, feedback that changes behavior, KB snapshots, replayability."""
import json
from pathlib import Path

import pytest

from warden import db, feedback, intel
from warden.agent import run_alert
from warden.correlate import correlate
from warden.detect import detect
from warden.ingest import generate_logs, load_file
from warden.knowledge import KnowledgeBase
from warden.llm import MockAnalyzer
from warden.pipeline import run, suppressed_by
from warden.stats import detection_stats, threshold_bump
from warden.store import CaseStore

ROOT = Path(__file__).resolve().parents[1]

KEV = json.dumps({"vulnerabilities": [{"cveID": "CVE-2026-0001", "vendorProject": "Acme", "product": "VPN",
                                       "vulnerabilityName": "Acme VPN auth bypass", "dateAdded": "2026-09-01",
                                       "shortDescription": "Auth bypass.", "requiredAction": "Patch.",
                                       "knownRansomwareCampaignUse": "Known"}]}).encode()
FEODO = json.dumps([{"ip_address": "203.0.113.42", "port": 443, "status": "online", "malware": "QakBot",
                     "first_seen": "2026-08-01 00:00:00", "last_online": "2026-09-01"}]).encode()
TOR = b"# exit list\n198.51.100.17\n"


@pytest.fixture()
def env(tmp_path):
    kb = KnowledgeBase(persist=False)
    kb.index_dir(ROOT / "data" / "knowledge")
    store = CaseStore(tmp_path / "state")
    return kb, store


def _refresh(kb, store):
    return intel.refresh(["cisa_kev", "feodo", "tor_exit"], kb=kb, engine=store.engine,
                         raw={"cisa_kev": KEV, "feodo": FEODO, "tor_exit": TOR})


def test_intel_refresh_is_idempotent_and_splits_iocs_from_docs(env):
    kb, store = env
    r = _refresh(kb, store)
    assert r["cisa_kev"] == {"iocs": 1, "docs": 1} and r["feodo"]["iocs"] == 1
    _refresh(kb, store)
    hits = intel.lookup(["203.0.113.42", "198.51.100.17", "8.8.8.8"], store.engine)
    assert set(hits) == {"203.0.113.42", "198.51.100.17"}
    assert hits["203.0.113.42"][0]["tags"]["malware"] == "QakBot"
    assert len(hits["203.0.113.42"]) == 1                       # no duplicate rows after the second refresh
    assert kb.col.get(ids=["intel-kev-CVE-2026-0001"])["ids"]


def test_a_failing_feed_does_not_stop_the_others(env):
    kb, store = env
    r = intel.refresh(["feodo", "cisa_kev"], kb=kb, engine=store.engine, raw={"feodo": b"not json", "cisa_kev": KEV})
    assert "error" in r["feodo"] and r["cisa_kev"]["iocs"] == 1


def test_enrichment_tags_alerts_with_intel(env, tmp_path):
    kb, store = env
    _refresh(kb, store)
    generate_logs(tmp_path / "a.jsonl", events=200)
    alerts = intel.enrich(detect(load_file(tmp_path / "a.jsonl")), store.engine)
    bf = next(a for a in alerts if a.rule == "brute_force")
    assert bf.detail["intel"]["203.0.113.42"][0]["source"] == "feodo"
    inc = correlate(alerts)
    assert any(m.detail.get("intel") for s in inc for m in (s.members or [s]))


def test_intel_docs_stay_out_of_playbook_retrieval(env, tmp_path):
    kb, store = env
    _refresh(kb, store)
    generate_logs(tmp_path / "a.jsonl", events=200)
    a = detect(load_file(tmp_path / "a.jsonl"), only=["brute_force"])[0]
    assert all(d["kind"] != "intel" for d in kb.retrieve_for_alert(a))


def test_sync_leaves_feed_documents_alone(env, tmp_path):
    kb, store = env
    _refresh(kb, store)
    kdir = tmp_path / "kn"
    kdir.mkdir()
    (kdir / "playbook-x.md").write_text("# X\n\nbody")
    r = kb.sync(kdir)
    assert "intel-kev-CVE-2026-0001" not in r["removed"]
    assert kb.col.get(ids=["intel-kev-CVE-2026-0001"])["ids"]


# ---------------------------------------------------------------- feedback that changes behavior
def _cases(env, tmp_path, n_batches=1):
    kb, store = env
    generate_logs(tmp_path / "a.jsonl", events=200)
    alerts = detect(load_file(tmp_path / "a.jsonl"))
    return [run_alert(a, kb, MockAnalyzer(), store) for a in alerts]


def test_fp_rate_raises_threshold_and_lowers_prior(env, tmp_path, monkeypatch):
    from warden.config import settings
    kb, store = env
    monkeypatch.setattr(settings, "fp_prior_min_verdicts", 1)
    cases = _cases(env, tmp_path)
    spray = [c for c in cases if c.alert.rule == "password_spray"]
    for c in spray:
        feedback.record_verdict(c, "false_positive", "pentest", store, kb, actor="a", reason="known_scanner")
    st = detection_stats(store)
    assert st["password_spray"].fp_rate == 1.0 and st["password_spray"].fp_reasons == {"known_scanner": 1}
    assert threshold_bump(st["password_spray"]) == 20
    again = run_alert(spray[0].alert, kb, MockAnalyzer(), store, st)
    assert again.analysis.false_positive_likelihood == "high"
    assert "+20" in " ".join(again.guardrail_log) or all(a.action != "block_ip" or a.status != "executed" for a in again.actions)


def test_structured_reason_is_validated(env, tmp_path):
    kb, store = env
    c = _cases(env, tmp_path)[0]
    with pytest.raises(ValueError):
        feedback.record_verdict(c, "false_positive", "", store, kb, reason="because")


def test_suppression_mutes_the_next_run(env, tmp_path):
    kb, store = env
    log = tmp_path / "a.jsonl"
    generate_logs(log, events=200)
    first = run(log, kb=kb, analyzer=MockAnalyzer(), store=store)
    spray = next(c for c in first if c.alert.rule == "password_spray")
    feedback.record_verdict(spray, "false_positive", "red team", store, kb, actor="ana",
                            reason="known_scanner", suppress=True)
    ex = store.exclusions()
    assert ex and ex[0]["rule"] == "password_spray" and ex[0]["field"] == "source_ip"
    second = run(log, kb=kb, analyzer=MockAnalyzer(), store=store, rerun=True)
    muted = next(c for c in second if c.alert.id == spray.alert.id)
    assert muted.suppressed_by == ex[0]["id"] and muted.analysis is None and muted.status == "closed"
    assert store.exclusions()[0]["hits"] == 1
    assert store.llm_calls(spray.alert.id)[0]["id"]            # the first run's call is still on record
    others = [c for c in second if c.alert.id != spray.alert.id]
    assert all(c.suppressed_by is None for c in others)


def test_incident_is_muted_only_when_every_member_is(env, tmp_path):
    [case] = [c for c in __import__("warden.evaluate", fromlist=["discover"]).discover(ROOT / "data" / "eval")
              if c.name.startswith("spray -> success")]
    inc = next(s for s in correlate(detect(load_file(case.events_file))) if s.is_incident)
    spray = next(m for m in inc.members if m.rule == "password_spray")
    ex = [{"id": 1, "rule": "password_spray", "field": "source_ip", "value": spray.source_ip}]
    assert suppressed_by(inc, ex) is None
    assert suppressed_by(spray, ex)["id"] == 1


# ---------------------------------------------------------------- snapshots
def test_snapshot_is_recorded_once_and_tracks_content(env):
    kb, store = env
    s1 = kb.record_snapshot(store.engine)
    assert kb.record_snapshot(store.engine) == s1
    with store.engine.connect() as c:
        row = c.execute(db.kb_snapshots.select()).first()
    assert row.id == s1 and "playbook-brute-force" in row.detail["docs"]
    kb.add_learned_case("learned-x", "# x")
    assert kb.record_snapshot(store.engine) != s1
