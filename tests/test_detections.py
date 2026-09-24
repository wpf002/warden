"""Registry, event model, and the Phase 2 identity detections."""
import os
from datetime import datetime, timedelta, timezone

os.environ["WARDEN_LLM"] = "mock"
os.environ["WARDEN_EMBEDDINGS"] = "hash"

import pytest

from warden.detect import detect, load_all
from warden.detections import REGISTRY, Detection, alert_id
from warden.events import AuthEvent, IdentityChangeEvent, NetworkEvent, parse_event
from warden.geo import required_kmh
from warden.ingest import generate_logs, load_file, normalize

T0 = datetime(2026, 9, 2, 9, 0, tzinfo=timezone.utc)


def auth(mins=0, secs=0, **kw):
    kw.setdefault("user", "victim")
    kw.setdefault("source_ip", "203.0.113.9")
    return AuthEvent(ts=T0 + timedelta(minutes=mins, seconds=secs), source="okta", **kw)


# ---------------------------------------------------------------- event model
def test_event_subclasses_round_trip():
    for rec in [
        {"kind": "auth", "ts": T0.isoformat(), "event_type": "mfa_denied", "user": "a"},
        {"kind": "network", "ts": T0.isoformat(), "dest_ip": "8.8.8.8", "dest_port": 53},
        {"kind": "identity", "ts": T0.isoformat(), "change_type": "group_add", "target_user": "b", "group": "Domain Admins"},
    ]:
        e = parse_event(rec)
        assert e.kind == rec["kind"]
        assert parse_event(e.model_dump(mode="json")).kind == e.kind


def test_dedupe_key_separates_event_kinds():
    a = AuthEvent(ts=T0, event_type="login_failure", user="u", source_ip="1.2.3.4")
    b = NetworkEvent(ts=T0, user="u", source_ip="1.2.3.4", dest_ip="9.9.9.9")
    c = IdentityChangeEvent(ts=T0, user="u", source_ip="1.2.3.4", change_type="group_add", target_user="v")
    assert len({x.dedupe_key() for x in (a, b, c)}) == 3


def test_normalize_keeps_mixed_kinds():
    evs = normalize([auth(event_type="login_failure"), NetworkEvent(ts=T0, source_ip="203.0.113.9", host="web-01")])
    assert {e.kind for e in evs} == {"auth", "network"}
    assert all(e.geo for e in evs)


# ---------------------------------------------------------------- registry
def test_registry_populated_and_consistent():
    reg = load_all()
    assert {"brute_force", "password_spray", "impossible_travel", "mfa_fatigue"} <= set(reg)
    for det in reg.values():
        # anomaly rules carry no technique of their own; the model maps each one to ATT&CK
        assert det.id and det.playbook and det.event_kinds and (det.mitre or det.id.startswith("anomaly."))


def test_registry_rejects_duplicate_ids():
    from warden.detections import register

    with pytest.raises(ValueError):
        register(type("Dup", (Detection,), {"id": "brute_force"}))


def test_only_filter_restricts_which_rules_run(tmp_path):
    events = load_file(_logs(tmp_path))
    assert {a.rule for a in detect(events, only=["mfa_fatigue"])} == {"mfa_fatigue"}


def test_unknown_detection_is_an_error(tmp_path):
    with pytest.raises(KeyError):
        detect([], only=["does_not_exist"])


def test_alert_ids_are_stable():
    assert alert_id("brute_force", "1.2.3.4", T0) == alert_id("brute_force", "1.2.3.4", T0)
    assert alert_id("brute_force", "1.2.3.4", T0) != alert_id("password_spray", "1.2.3.4", T0)


def _logs(tmp_path):
    p = tmp_path / "auth.jsonl"
    generate_logs(p, events=300, attackers=2)
    return p


def test_generated_logs_fire_every_detection(tmp_path):
    rules = {a.rule for a in detect(load_file(_logs(tmp_path)))}
    assert {"brute_force", "password_spray", "impossible_travel", "mfa_fatigue"} <= rules


def test_alerts_carry_mitre_and_playbook(tmp_path):
    for a in detect(load_file(_logs(tmp_path))):
        assert a.mitre and a.playbook and a.detail


# ---------------------------------------------------------------- impossible travel
def test_impossible_travel_fires_on_unreachable_pair():
    evs = normalize([
        auth(0, event_type="login_success", source_ip="72.14.201.9", geo="US", host="web-01"),
        auth(22, event_type="login_success", source_ip="45.83.140.6", host="web-01"),
    ])
    alerts = detect(evs, only=["impossible_travel"])
    assert len(alerts) == 1
    d = alerts[0].detail
    assert d["from_geo"] == "US" and d["to_geo"] == "DE"
    assert d["implied_kmh"] > d["max_plausible_kmh"]
    assert set(alerts[0].all_ips()) == {"72.14.201.9", "45.83.140.6"}


def test_impossible_travel_ignores_reachable_and_internal():
    slow = normalize([
        auth(0, event_type="login_success", source_ip="72.14.201.9", geo="US", host="web-01"),
        auth(60 * 20, event_type="login_success", source_ip="45.83.140.6", host="web-01"),
    ])
    assert detect(slow, only=["impossible_travel"]) == []
    internal = normalize([
        auth(0, event_type="login_success", source_ip="10.0.0.5", host="web-01"),
        auth(5, event_type="login_success", source_ip="10.0.0.6", host="web-01"),
    ])
    assert detect(internal, only=["impossible_travel"]) == []


def test_impossible_travel_ignores_failures():
    evs = normalize([
        auth(0, event_type="login_failure", source_ip="72.14.201.9", geo="US"),
        auth(10, event_type="login_failure", source_ip="45.83.140.6"),
    ])
    assert detect(evs, only=["impossible_travel"]) == []


def test_required_speed_is_symmetric():
    assert required_kmh("US", "DE", 3600) == pytest.approx(required_kmh("DE", "US", 3600))


# ---------------------------------------------------------------- MFA fatigue
def _pushes(n, approve, user="asmith"):
    evs = [auth(secs=i * 80, user=user, event_type="mfa_denied" if i % 3 else "mfa_timeout",
                mfa_factor="push", host="ad-dc-01") for i in range(n)]
    if approve:
        evs.append(auth(secs=n * 80 + 40, user=user, event_type="mfa_success", mfa_factor="push", host="ad-dc-01"))
    return normalize(evs)


def test_mfa_fatigue_fires_and_flags_the_approval():
    a = detect(_pushes(7, approve=True), only=["mfa_fatigue"])[0]
    assert a.failed_attempts == 7
    assert a.success_after_failures is True
    assert a.detail["approved_after"] is True
    assert a.detail["denied"] + a.detail["timed_out"] == 7
    assert a.mitre == ["T1621"]


def test_mfa_fatigue_fires_without_approval_but_marks_it():
    a = detect(_pushes(7, approve=False), only=["mfa_fatigue"])[0]
    assert a.success_after_failures is False and a.detail["approved_after"] is False


def test_mfa_fatigue_quiet_below_threshold():
    assert detect(_pushes(4, approve=True), only=["mfa_fatigue"]) == []


def test_mfa_fatigue_does_not_merge_two_users():
    evs = normalize(_pushes(6, True, "asmith") + _pushes(6, True, "jlee"))
    assert {a.users[0] for a in detect(evs, only=["mfa_fatigue"])} == {"asmith", "jlee"}


def test_tdl_coverage_index(tmp_path, monkeypatch):
    """The TDL coverage map: real index shape, revoked techniques excluded from the gaps."""
    import json
    from warden import tdl
    from warden.config import settings
    d = tmp_path / "tdl"
    d.mkdir()
    (d / "index.json").write_text(json.dumps({"rules": [
        {"rule_id": "TDL-CA-1", "technique_id": "T1110", "technique_name": "Brute Force",
         "tactic": "Credential Access", "severity": "High", "lifecycle": "Deployed", "platform": ["Windows"]},
        {"rule_id": "TDL-DE-1", "technique_id": "T9999", "technique_name": "Gone", "tactic": "Defense Evasion",
         "severity": "Low", "lifecycle": "Proposed", "platform": ["Windows"]},
        {"rule_id": "TDL-IA-1", "technique_id": "T1190", "technique_name": "Exploit Public-Facing Application",
         "tactic": "Initial Access", "severity": "High", "lifecycle": "Deployed", "platform": ["Linux"]},
    ]}))
    (tmp_path / "attack").mkdir()
    (tmp_path / "attack" / "_revoked.json").write_text(json.dumps(["T9999"]))
    monkeypatch.setattr(settings, "data_dir", tmp_path)     # attack_dir derives from data_dir
    tdl._load.cache_clear()
    c = tdl.coverage()
    assert c["available"] and c["rules"] == 3 and c["revoked"] == 1
    by = {t["technique"]: t for t in c["techniques_detail"]}
    assert by["T1110"]["covered"] and "brute_force" in by["T1110"]["detections"]
    assert [g["technique"] for g in c["gaps"]] == ["T1190"]     # T9999 is revoked, not a gap
