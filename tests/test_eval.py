"""Eval harness and ATT&CK ingest."""
import json
import os
from pathlib import Path

os.environ["WARDEN_LLM"] = "mock"
os.environ["WARDEN_EMBEDDINGS"] = "hash"

import pytest

from warden import attack, evaluate
from warden.evaluate import Counts, EvalCase, ExpectedAlert
from warden.knowledge import KnowledgeBase
from warden.llm import MockAnalyzer

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def kb():
    k = KnowledgeBase(persist=False)
    k.index_dir(ROOT / "data" / "knowledge")
    return k


@pytest.fixture(scope="module")
def cases():
    cs = evaluate.discover(ROOT / "data" / "eval")
    assert cs, "eval fixtures missing; run scripts/make_eval_fixtures.py"
    return cs


# ---------------------------------------------------------------- scoring maths
def test_counts_arithmetic():
    c = Counts(tp=3, fp=1, fn=1)
    assert c.precision == 0.75 and c.recall == 0.75 and c.f1 == 0.75
    assert Counts().precision == 0.0 and Counts().f1 == 0.0


def test_expected_alert_matching():
    from datetime import datetime, timezone

    from warden.models import Alert

    t = datetime(2026, 9, 2, tzinfo=timezone.utc)
    a = Alert(id="X", ts=t, rule="brute_force", title="t", source_ip="1.1.1.1", related_ips=["2.2.2.2"],
              users=["bob"], hosts=["web-01"], first_seen=t, last_seen=t, detail={"distinct_users": 1})
    assert ExpectedAlert("brute_force", {"source_ip": "1.1.1.1"}).matches(a)
    assert ExpectedAlert("brute_force", {"source_ip": "2.2.2.2"}).matches(a)      # related ip counts
    assert ExpectedAlert("brute_force", {"user": "bob", "host": "web-01"}).matches(a)
    assert ExpectedAlert("brute_force", {"distinct_users": 1}).matches(a)         # detail key
    assert not ExpectedAlert("password_spray", {"source_ip": "1.1.1.1"}).matches(a)
    assert not ExpectedAlert("brute_force", {"user": "eve"}).matches(a)


# ---------------------------------------------------------------- harness
def test_fixtures_load_and_are_labeled(cases):
    assert len(cases) >= 6
    labeled = [e for c in cases for e in c.expected]
    assert all(e.label in ("true_positive", "false_positive") for e in labeled)
    assert any(e.label == "false_positive" for e in labeled), "need a negative case"


def test_pipeline_scores_clean_on_fixtures(cases, kb):
    rep = evaluate.run(cases, kb=kb, analyzer=MockAnalyzer())
    assert rep.overall.precision == 1.0, rep.spurious
    assert rep.overall.recall == 1.0, rep.misses
    assert rep.brier < 0.1                     # much better than the 0.25 coin flip
    assert rep.action_agreement == 1.0
    assert rep.retrieval_hit_rate >= 0.8
    assert not rep.risk_violations and not rep.unexpected_executes


def test_quiet_hour_produces_no_alerts(cases, kb):
    quiet = [c for c in cases if not c.expected]
    assert quiet, "expected a benign case"
    rep = evaluate.run(quiet, kb=kb, analyzer=MockAnalyzer())
    assert rep.overall.fp == 0, rep.spurious


def test_harness_reports_a_miss(tmp_path, kb):
    d = tmp_path / "case"
    d.mkdir()
    (d / "events.jsonl").write_text("")
    (d / "expected.json").write_text(json.dumps(
        {"name": "impossible", "alerts": [{"rule": "brute_force", "match": {"source_ip": "9.9.9.9"}}]}))
    rep = evaluate.run([EvalCase.load(d)], kb=kb, analyzer=MockAnalyzer())
    assert rep.overall.fn == 1 and rep.overall.recall == 0.0 and rep.misses


def test_report_serializes(cases, kb):
    rep = evaluate.run(cases, kb=kb, analyzer=MockAnalyzer())
    d = rep.to_dict()
    assert d["overall"]["f1"] == 1.0 and "brute_force" in d["per_rule"]
    assert evaluate.format_report(rep, cases).splitlines()[0].startswith("cases: ")


def test_no_llm_mode_skips_scoring(cases):
    rep = evaluate.run(cases, with_llm=False)
    assert rep.overall.f1 == 1.0
    assert rep.brier is None and rep.action_agreement is None


# ---------------------------------------------------------------- ATT&CK ingest
@pytest.fixture(scope="module")
def bundle():
    return attack.fetch_bundle(file=FIXTURES / "mini-attack-bundle.json")


def test_parse_skips_deprecated_and_revoked(bundle):
    ids = {t["id"] for t in attack.parse(bundle)}
    assert ids == {"T1110", "T1110.001"}


def test_parse_resolves_relationships(bundle):
    ts = {t["id"]: t for t in attack.parse(bundle)}
    assert ts["T1110"]["mitigations"] == ["Multi-factor Authentication: Require MFA."]
    assert ts["T1110.001"]["groups"] == ["APT-TEST"]
    assert ts["T1110.001"]["software"] == ["TestCracker"]
    assert ts["T1110.001"]["is_subtechnique"] and ts["T1110.001"]["base"] == "T1110"
    assert ts["T1110"]["tactics"] == ["credential-access"]


def test_render_keeps_detection_guidance_addressable(bundle):
    md = attack.render(next(t for t in attack.parse(bundle) if t["id"] == "T1110"))
    assert md.startswith("# T1110 Brute Force")
    assert "## Detection guidance for T1110" in md
    assert "Monitor authentication logs" in md


def test_ingest_indexes_and_writes_manifest(tmp_path, bundle):
    k = KnowledgeBase(persist=False)
    n_tech, n_chunks = attack.ingest(file=FIXTURES / "mini-attack-bundle.json", out=tmp_path, kb=k)
    assert n_tech == 2 and n_chunks > 0
    m = json.loads((tmp_path / "_manifest.json").read_text())
    assert m["techniques"] == 2 and m["attack_version"] == "17.0" and m["fetched"]
    assert (tmp_path / "T1110.001.md").exists()

    hits = k.retrieve_by_technique("brute force password guessing", ["T1110.001"], k=3, kind="attack")
    assert hits and all(h["technique"].startswith("T1110") for h in hits)


def test_attack_corpus_does_not_crowd_out_playbooks(tmp_path):
    """The regression the eval caught: 4k ATT&CK chunks swamping an unfiltered search."""
    from warden.detect import detect
    from warden.ingest import load_file

    k = KnowledgeBase(persist=False)
    k.index_dir(ROOT / "data" / "knowledge")
    attack.ingest(file=FIXTURES / "mini-attack-bundle.json", out=tmp_path, kb=k)
    alert = detect(load_file(ROOT / "data" / "eval" / "01-brute-force-vpn" / "events.jsonl"),
                   only=["brute_force"])[0]
    docs = k.retrieve_for_alert(alert, k=5)
    kinds = [d["kind"] for d in docs]
    assert "attack" in kinds, "the mapped technique page should be retrieved"
    assert sum(x == "attack" for x in kinds) <= 2, "ATT&CK must not dominate the budget"
    assert any(d["doc"] == alert.playbook for d in docs[:3])
