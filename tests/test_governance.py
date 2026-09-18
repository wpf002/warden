"""Phase 7 governance: PII redaction, retention, output verification."""
from datetime import datetime, timedelta, timezone

from warden import governance
from warden.events import ProcessEvent
from warden.models import Alert, Analysis, Case, RecommendedAction
from warden.store import CaseStore

T = datetime(2026, 9, 1, tzinfo=timezone.utc)


def test_redaction_scrubs_free_text_not_identity():
    e = ProcessEvent(ts=T, user="jane@corp.example", host="ws-1", process_name="curl.exe",
                     command_line="curl -d 'to=jane@corp.example&card=4111 1111 1111 1111&ssn=123-45-6789' x",
                     raw={"note": "call 415-555-0199", "nested": ["bob@x.io"]})
    governance.redact(e, {"email", "card", "ssn", "phone"})
    assert e.user == "jane@corp.example"                       # detection keys stay intact
    assert "[REDACTED:email]" in e.command_line and "[REDACTED:card]" in e.command_line
    assert "[REDACTED:ssn]" in e.command_line and e.raw["note"] == "call [REDACTED:phone]"
    assert e.raw["nested"] == ["[REDACTED:email]"]


def test_card_redaction_needs_a_valid_luhn():
    assert governance.redact_text("order 1234 5678 9012 3456", {"card"}) == "order 1234 5678 9012 3456"
    assert "REDACTED" in governance.redact_text("4111-1111-1111-1111", {"card"})


def test_redaction_off_by_default():
    e = ProcessEvent(ts=T, command_line="mail bob@x.io")
    assert governance.redact(e).command_line == "mail bob@x.io"


def test_retention_is_per_tenant(tmp_path, monkeypatch):
    from warden.config import settings
    monkeypatch.setattr(settings, "database_url", f"sqlite:///{tmp_path / 'r.db'}")
    old = datetime.now(timezone.utc) - timedelta(days=400)
    a, b = CaseStore(tenant="a"), CaseStore(tenant="b")
    for st in (a, b):
        st.add_events([ProcessEvent(ts=old, host="h", command_line="x"),
                       ProcessEvent(ts=datetime.now(timezone.utc), host="h", command_line="y")])
    out = governance.retention(a)
    assert out["events"] == 1 and len(a.events()) == 1 and len(b.events()) == 2


def _alert():
    return Alert(id="A1", ts=T, rule="brute_force", title="bf", first_seen=T, last_seen=T, source_ip="203.0.113.5",
                 users=["jdoe"], hosts=["ws-1"])


def _an(expl, acts=(), mitre="T1110.001 Brute Force"):
    return Analysis(explanation=expl, mitre_attack=mitre, risk_score=90, severity="high", false_positive_likelihood="low",
                    recommended_actions=[RecommendedAction(action=a, target=t) for a, t in acts])


def test_verify_accepts_grounded_analysis():
    assert governance.verify(_alert(), _an("12 failures for jdoe from 203.0.113.5", [("block_ip", "203.0.113.5")])) == []


def test_verify_flags_invented_entities():
    probs = governance.verify(_alert(), _an("also seen from 198.51.100.77 exploiting CVE-2099-0001",
                                            [("isolate_host", "dc-99")]))
    assert any("198.51.100.77" in p for p in probs) and any("CVE-2099-0001" in p for p in probs)
    assert any("dc-99" in p for p in probs)


def test_verify_flags_made_up_techniques(monkeypatch, tmp_path):
    from warden.config import settings
    d = tmp_path / "attack"
    d.mkdir()
    (d / "T1110.001.md").write_text("x")
    monkeypatch.setattr(settings, "data_dir", tmp_path)
    assert governance.verify(_alert(), _an("x", mitre="T1110.001")) == []
    assert governance.verify(_alert(), _an("x", mitre="T9999.123 Imaginary"))


def test_unverified_analysis_holds_actions_for_a_human(tmp_path):
    from warden.agent import run_alert
    from warden.knowledge import KnowledgeBase

    class Liar:
        model, last_usage = "liar", {}

        def analyze(self, alert, docs, context=None):
            return _an("pivoted to 198.51.100.77", [("block_ip", "203.0.113.5"), ("notify", "soc")])

    case = run_alert(_alert(), KnowledgeBase(persist=False), Liar(), CaseStore(tmp_path))
    st = {a.action: a.status for a in case.actions}
    assert st == {"block_ip": "pending_approval", "notify": "executed"}
    assert case.verification and any(l.startswith("VERIFY") for l in case.guardrail_log)
