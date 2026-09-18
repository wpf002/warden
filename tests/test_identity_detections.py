"""Phase 2 identity detections and correlation. One positive and one negative per rule."""
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from warden.correlate import build_incident, correlate
from warden.detect import detect
from warden.detections._identity import in_change_window, is_privileged_group, is_service_account, norm_user
from warden.events import AuthEvent, IdentityChangeEvent
from warden.evaluate import discover, run
from warden.ingest import normalize

T0 = datetime(2026, 9, 2, 9, 0, tzinfo=timezone.utc)
ROOT = Path(__file__).resolve().parents[1]


def A(m=0, s=0, **kw):
    kw.setdefault("source", "okta")
    return AuthEvent(ts=T0 + timedelta(minutes=m, seconds=s), **kw)


def I(m=0, **kw):
    kw.setdefault("source", "windows")
    return IdentityChangeEvent(ts=T0 + timedelta(minutes=m), **kw)


def rules(evs, prior=None, only=None):
    return [a.rule for a in detect(normalize(evs), prior=normalize(prior) if prior else None, only=only)]


def test_helpers():
    assert norm_user("CORP\\ASmith") == norm_user("asmith@corp.example") == "asmith"
    assert is_service_account("svc-backup") and is_service_account("WEB01$") and not is_service_account("jlee")
    assert is_privileged_group("domain admins") and not is_privileged_group("Marketing")


def test_change_window(monkeypatch):
    from warden.config import settings
    monkeypatch.setattr(settings, "change_window", "days=sat,sun;hours=22-06")
    assert in_change_window(datetime(2026, 9, 5, 23, 0, tzinfo=timezone.utc))       # Saturday 23:00
    assert not in_change_window(datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc))   # Saturday noon
    assert not in_change_window(datetime(2026, 9, 2, 23, 0, tzinfo=timezone.utc))   # Wednesday


def test_credential_stuffing():
    ips = [f"185.220.10{i}.9" for i in range(6)]
    users = [f"u{i}" for i in range(12)]
    evs = [A(s=i * 20, event_type="login_failure", user=u, source_ip=ips[i % 6], user_agent="OpenBullet")
           for i, u in enumerate(users)]
    assert "credential_stuffing" in rules(evs)
    # the same volume from a single IP is a spray, not stuffing
    assert "credential_stuffing" not in rules([e.model_copy(update={"source_ip": "1.1.1.1"}) for e in evs])


def test_new_geo_needs_history():
    hist = [A(-600 - i, event_type="login_success", user="bob", source_ip="72.14.0.1", geo="US") for i in range(4)]
    new = [A(0, event_type="login_success", user="bob", source_ip="45.83.1.1")]
    assert rules(new, prior=hist, only=["new_geo_login"]) == ["new_geo_login"]
    assert rules(new, prior=hist[:1], only=["new_geo_login"]) == []                    # too little history
    home = [A(0, event_type="login_success", user="bob", source_ip="72.14.0.2", geo="US")]
    assert rules(home, prior=hist, only=["new_geo_login"]) == []


def test_mfa_method_change_requires_suspicious_lead_in():
    lead = [A(0, event_type="mfa_denied", user="eve", source_ip="45.83.1.1"),
            A(1, event_type="login_success", user="eve", source_ip="45.83.1.1")]
    enroll = [I(10, change_type="mfa_enrolled", user="eve", target_user="eve")]
    assert rules(lead + enroll, only=["mfa_method_change"]) == ["mfa_method_change"]
    clean = [A(1, event_type="login_success", user="eve", source_ip="10.0.0.9")]
    assert rules(clean + enroll, only=["mfa_method_change"]) == []


def test_dormant_account():
    hist = [A(-60 * 24 * 70, event_type="login_success", user="old", source_ip="10.0.0.2")]
    assert rules([A(0, event_type="login_success", user="old", source_ip="10.0.0.2")], prior=hist,
                 only=["dormant_account"]) == ["dormant_account"]
    recent = [A(-60 * 24 * 10, event_type="login_success", user="old", source_ip="10.0.0.2")]
    assert rules([A(0, event_type="login_success", user="old", source_ip="10.0.0.2")], prior=recent,
                 only=["dormant_account"]) == []


def test_service_account_interactive():
    ev = A(0, event_type="login_success", user="svc-sql", source_ip="10.0.0.5", host="jump-01",
           logon_type="remote_interactive")
    assert rules([ev], only=["service_account_interactive"]) == ["service_account_interactive"]
    assert rules([ev.model_copy(update={"logon_type": "service"})], only=["service_account_interactive"]) == []
    assert rules([ev.model_copy(update={"user": "WEB01$"})], only=["service_account_interactive"]) == []


def test_privileged_group_add_and_create_then_privilege():
    add = I(8, change_type="group_add", user="it-admin", target_user="support2", group="Domain Admins")
    assert rules([add], only=["privileged_group_add"]) == ["privileged_group_add"]
    assert rules([add.model_copy(update={"group": "Marketing"})], only=["privileged_group_add"]) == []
    create = I(0, change_type="account_created", user="it-admin", target_user="support2")
    assert rules([create, add], only=["account_create_then_privilege"]) == ["account_create_then_privilege"]
    late = add.model_copy(update={"ts": T0 + timedelta(hours=3)})
    assert rules([create, late], only=["account_create_then_privilege"]) == []


def test_session_anomaly():
    a = A(0, event_type="login_success", user="t", source_ip="72.14.0.1", session_id="s1",
          user_agent="Mozilla/5.0 (Macintosh) Chrome/128")
    b = A(40, event_type="login_success", user="t", source_ip="45.83.1.1", session_id="s1", user_agent="python-requests/2")
    assert "session_anomaly" in rules([a, b], only=["session_anomaly"])
    same_client = b.model_copy(update={"user_agent": a.user_agent})
    assert rules([a, same_client], only=["session_anomaly"]) == []      # mobile IP change


def test_password_reset_abuse_both_modes():
    op = [I(i * 5, change_type="password_reset", user="hd7", target_user=f"u{i}") for i in range(4)]
    assert rules(op, only=["password_reset_abuse"]) == ["password_reset_abuse"]
    tgt = [I(i * 5, change_type="password_reset", user=f"hd{i}", target_user="cfo") for i in range(3)]
    assert rules(tgt, only=["password_reset_abuse"]) == ["password_reset_abuse"]
    assert rules(op[:2], only=["password_reset_abuse"]) == []


def test_lockout_storm():
    locks = [A(s=i * 30, event_type="lockout", user=f"u{i}", source_ip="203.0.113.7") for i in range(6)]
    assert rules(locks, only=["lockout_storm"]) == ["lockout_storm"]
    assert rules(locks[:3], only=["lockout_storm"]) == []


# ---------------------------------------------------------------- correlation
def test_chain_merges_into_one_incident():
    [case] = [c for c in discover(ROOT / "data" / "eval") if c.name.startswith("spray -> success")]
    from warden.ingest import load_file
    subjects = correlate(detect(load_file(case.events_file)))
    incidents = [s for s in subjects if s.is_incident]
    assert len(incidents) == 1
    inc = incidents[0]
    assert {"password_spray", "mfa_method_change", "privileged_group_add"} <= set(inc.rules())
    assert inc.id.startswith("INC-") and inc.detail["focus"] == "jlee"
    assert [e["ts"] for e in inc.evidence] == sorted(e["ts"] for e in inc.evidence)


def test_unrelated_alerts_stay_apart():
    a = detect(normalize([I(0, change_type="group_add", user="x", target_user="alice", group="Domain Admins")]))
    b = detect(normalize([I(1, change_type="group_add", user="y", target_user="bob", group="Domain Admins")]))
    assert len(correlate(a + b)) == 2


def test_far_apart_in_time_stay_apart():
    a = detect(normalize([I(0, change_type="group_add", user="x", target_user="alice", group="Domain Admins")]))
    b = detect(normalize([I(600, change_type="group_add", user="x", target_user="alice", group="Domain Admins")]))
    assert len(correlate(a + b)) == 2


def test_incident_ids_are_stable():
    a = detect(normalize([I(0, change_type="group_add", user="x", target_user="alice", group="Domain Admins"),
                          I(1, change_type="group_add", user="x", target_user="alice", group="Enterprise Admins")]))
    assert build_incident(a).id == build_incident(list(reversed(a))).id


def test_full_synthetic_suite_meets_phase2_bar():
    rep = run(discover(ROOT / "data" / "eval"), with_llm=False)
    assert rep.overall.precision >= 0.9 and rep.overall.recall >= 0.9
    assert rep.merge_rate == 1.0, rep.unmerged
    assert len(rep.per_rule) >= 14
