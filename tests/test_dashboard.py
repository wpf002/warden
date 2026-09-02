"""Dashboard renders every alert shape. v0.1 could not even import this module:
the verdict route uses fastapi Form(), which needs python-multipart."""
import os
from pathlib import Path

os.environ["WARDEN_LLM"] = "mock"
os.environ["WARDEN_EMBEDDINGS"] = "hash"

import pytest

from warden.agent import run_alert
from warden.detect import detect
from warden.ingest import generate_logs, load_file
from warden.knowledge import KnowledgeBase
from warden.llm import MockAnalyzer
from warden.store import CaseStore

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def populated(tmp_path_factory):
    d = tmp_path_factory.mktemp("dash")
    generate_logs(d / "auth.jsonl", events=300, attackers=2)
    kb = KnowledgeBase(persist=False)
    kb.index_dir(ROOT / "data" / "knowledge")
    store = CaseStore(d)
    for alert in detect(load_file(d / "auth.jsonl")):
        run_alert(alert, kb, MockAnalyzer(), store)
    return store


def test_index_lists_every_rule(populated, monkeypatch):
    from warden import dashboard

    monkeypatch.setattr(dashboard, "store", populated)
    body = dashboard.index().body.decode()
    for rule in ("brute_force", "password_spray", "impossible_travel", "mfa_fatigue"):
        assert rule in body


def test_index_columns_line_up(populated, monkeypatch):
    from warden import dashboard

    monkeypatch.setattr(dashboard, "store", populated)
    body = dashboard.index().body.decode()
    header, first_row = body.split("<tr>")[1], body.split("<tr>")[2]
    assert header.count("<th>") == first_row.count("<td>")


def test_case_view_renders_rule_specific_detail(populated, monkeypatch):
    from warden import dashboard

    monkeypatch.setattr(dashboard, "store", populated)
    for c in populated.all():
        body = dashboard.case_view(c.alert.id).body.decode()
        assert c.alert.id in body and c.alert.rule in body
        for key in c.alert.detail:
            assert key in body


def test_case_view_404s(monkeypatch):
    from fastapi import HTTPException

    from warden import dashboard

    with pytest.raises(HTTPException):
        dashboard.case_view("ALT-NOPE")
