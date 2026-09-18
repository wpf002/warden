"""Phase 6 machinery with a stand-in proposer. The stand-in returns a draft written by hand
for these tests; real proposals come from Claude (AnthropicProposer)."""
from datetime import datetime, timezone
from pathlib import Path

import pytest

from warden import proposals
from warden.events import AuthEvent, IdentityChangeEvent
from warden.proposals import Anonymizer, FixtureSpec, ProposalDraft, check_code, check_detection
from warden.store import CaseStore

ROOT = Path(__file__).resolve().parents[1]

GOOD = '''from __future__ import annotations

from ..events import IdentityChangeEvent
from ..models import Alert
from . import Detection, register


@register
class MachineAccountLookalike(Detection):
    id = "machine_account_lookalike"
    name = "Account created with a machine-account-style name"
    mitre = ["T1136.002"]
    event_kinds = ("identity",)
    window_sec = 0
    playbook = "playbook-machine-account-lookalike"

    def run(self, events: list[IdentityChangeEvent]) -> list[Alert]:
        out = []
        for e in events:
            name = e.target_user or ""
            if e.change_type == "account_created" and name.endswith("$") and len(name.rstrip("$")) <= 2:
                out.append(self.new_alert(key=f"{name}|{e.ts.isoformat()}", first_seen=e.ts, ts=e.ts,
                                          title=f"Account {name!r} created by {e.user}", users=[e.user, name],
                                          hosts=[e.host] if e.host else [], last_seen=e.ts,
                                          detail={"account": name, "created_by": e.user}))
        return out
'''

TEST = '''from datetime import datetime, timezone

from warden.detect import detect
from warden.events import IdentityChangeEvent
from warden.ingest import normalize

T = datetime(2026, 9, 1, tzinfo=timezone.utc)


def test_fires_on_lookalike_and_not_on_real_machine_account():
    bad = IdentityChangeEvent(ts=T, change_type="account_created", user="host-01$", target_user="$", host="host-01")
    ok = IdentityChangeEvent(ts=T, change_type="account_created", user="admin", target_user="WEB-SERVER-07$", host="dc")
    assert [a.rule for a in detect(normalize([bad]), only=["machine_account_lookalike"])] == ["machine_account_lookalike"]
    assert detect(normalize([ok]), only=["machine_account_lookalike"]) == []
'''


def draft(code=GOOD, test=TEST, rid="machine_account_lookalike"):
    return ProposalDraft(
        detection_id=rid, mitre=["T1136.002"], rationale="Lone '$' account creation, as in the real 4720 sample.",
        detection_code=code, playbook_markdown="# Playbook: machine account lookalike\n\nDisable it.",
        fixture=FixtureSpec(events=[
            {"kind": "identity", "ts": "2026-09-01T09:00:00+00:00", "change_type": "account_created",
             "user": "host-01$", "target_user": "$", "host": "host-01"},
            {"kind": "identity", "ts": "2026-09-01T09:05:00+00:00", "change_type": "account_created",
             "user": "admin", "target_user": "WEB-SERVER-07$", "host": "dc"}],
            expected_alerts=[{"rule": rid, "match": {}, "label": "true_positive"}], description="lookalike vs real"),
        test_code=test)


class StandIn:
    model = "test-double"
    last_usage = {}

    def __init__(self, d):
        self.d, self.seen = d, None

    def propose(self, system, user):
        self.seen = (system, user)
        return self.d


def test_anonymizer_is_consistent_and_hides_identifiers():
    a = Anonymizer()
    e1 = AuthEvent(ts=datetime(2026, 9, 1, tzinfo=timezone.utc), event_type="login_success", user="jlee",
                   source_ip="10.0.4.17", host="WS-17")
    e2 = e1.model_copy(update={"source_ip": "185.220.101.66"})
    d1, d2 = a.event(e1), a.event(e2)
    assert d1["user"] == d2["user"] == "user-01" and d1["host"] == "host-01"
    assert d1["source_ip"].startswith("10.99.") and d2["source_ip"].startswith("203.0.113.")
    p = IdentityChangeEvent(ts=e1.ts, change_type="group_add", user="jlee", target_user="Guest", group="Administrators")
    assert a.event(p)["target_user"] == "Guest"          # built-ins keep their meaning


def test_static_checks_catch_the_dangerous_and_the_malformed():
    assert check_detection(GOOD, "machine_account_lookalike") == []
    assert any("os" in p for p in check_detection(GOOD.replace("from __future__ import annotations",
                                                               "from __future__ import annotations\nimport os"), "machine_account_lookalike"))
    assert any("open" in p for p in check_detection(GOOD.replace("out = []", "out = []\n        open('/etc/passwd')"),
                                                    "machine_account_lookalike"))
    assert any("__class__" in p for p in check_detection(GOOD.replace("out = []", "out = ().__class__"),
                                                         "machine_account_lookalike"))
    assert any("already exists" in p for p in check_detection(GOOD.replace('"machine_account_lookalike"', '"brute_force"'),
                                                              "brute_force"))
    assert any("register" in p for p in check_detection(GOOD.replace("@register\n", ""), "machine_account_lookalike"))
    assert check_code("import subprocess\n", proposals.TEST_IMPORTS, "test")


def test_prompt_carries_interface_and_existing_ids():
    system, user = proposals.build_prompt("hunt", [{"kind": "identity"}], [])
    assert "Hard constraints" in system and "brute_force" in user and "class Detection" in user


def test_end_to_end_with_sandbox(tmp_path):
    store = CaseStore(tmp_path)
    ev = IdentityChangeEvent(ts=datetime(2026, 9, 1, tzinfo=timezone.utc), change_type="account_created",
                             user="DC01$", target_user="$", host="dc01")
    sp = StandIn(draft())
    pid = proposals.create("hunt", [ev], "lone $ account", store=store, proposer=sp, source="DE_Fake_ComputerAccount_4720.evtx")
    p = proposals.get(pid, store.engine)
    assert "DC01" not in sp.seen[1] and "dc01" not in sp.seen[1]         # the model never sees the real host
    assert p["status"] == "ready_for_review", p["eval"]
    assert p["eval"]["test"]["ok"] and p["eval"]["synthetic"]["rule"]["tp"] == 1
    assert p["eval"]["synthetic"]["overall"]["precision"] == 1.0
    real = Path(ROOT / "data" / "real" / "DE_Fake_ComputerAccount_4720.evtx")
    if real.exists():
        assert any("DE_Fake_ComputerAccount_4720" in h["file"] for h in p["eval"]["historical_hits"])
    r = proposals.review(pid, "approve", "admin", "looks right", store=store, open_pr=False)
    assert r["status"] == "approved" and store.audit_log()[0]["action"] == "approve_proposal"
    with pytest.raises(ValueError):
        proposals.review(pid, "approve", "admin", store=store, open_pr=False)


def test_bad_code_never_reaches_the_sandbox(tmp_path, monkeypatch):
    store = CaseStore(tmp_path)
    ran = []
    monkeypatch.setattr(proposals, "sandbox_eval", lambda *a, **k: ran.append(1) or {})
    pid = proposals.create("hunt", [], "x", store=store, proposer=StandIn(draft(code=GOOD.replace(
        "from . import Detection, register", "from . import Detection, register\nimport socket"))))
    assert proposals.get(pid, store.engine)["status"] == "rejected_static" and not ran


def test_failing_proposed_test_fails_eval(tmp_path):
    store = CaseStore(tmp_path)
    broken = TEST.replace('== ["machine_account_lookalike"]', '== []')
    pid = proposals.create("hunt", [], "x", store=store, proposer=StandIn(draft(test=broken)))
    assert proposals.get(pid, store.engine)["status"] == "failed_eval"


def test_tp_on_anomaly_queues_a_request(tmp_path):
    from warden import feedback
    from warden.knowledge import KnowledgeBase
    from warden.models import Alert, Case
    store = CaseStore(tmp_path)
    t = datetime(2026, 9, 1, tzinfo=timezone.utc)
    a = Alert(id="ALT-ANOM0001", ts=t, rule="anomaly.user", title="x", first_seen=t, last_seen=t, users=["dkim"],
              detail={"source": "anomaly", "entity_type": "user", "entity": "dkim", "contributions": []})
    case = Case(alert=a)
    store.save(case)
    feedback.record_verdict(case, "true_positive", "recon", store, KnowledgeBase(persist=False), actor="ana")
    reqs = [p for p in proposals.list_proposals(store.engine) if p["status"] == "requested"]
    assert reqs and reqs[0]["source"] == "ALT-ANOM0001" and reqs[0]["trigger"] == "anomaly_tp"
