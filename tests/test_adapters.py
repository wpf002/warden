"""Each source adapter against a fixture built from that vendor's documented schema,
plus the real Windows samples when they have been fetched."""
import os
from pathlib import Path

os.environ["WARDEN_LLM"] = "mock"
os.environ["WARDEN_EMBEDDINGS"] = "hash"

import pytest

from warden.adapters import detect_format, iter_events
from warden.adapters._util import clean_ip, parse_ts
from warden.detect import detect
from warden.ingest import load_file

FX = Path(__file__).parent / "fixtures" / "adapters"
REAL = Path(__file__).resolve().parents[1] / "data" / "real"


@pytest.mark.parametrize("name,fmt", [
    ("okta_system_log.json", "okta"), ("entra_signins.json", "entra"), ("entra_audit.json", "entra"),
    ("cloudtrail.json", "cloudtrail"), ("elastic_search.json", "elastic"), ("splunk_export.json", "splunk"),
    ("sshd_auth.log", "sshd"),
])
def test_format_detection(name, fmt):
    assert detect_format(FX / name) == fmt


def test_util_normalizers():
    assert clean_ip("::ffff:172.16.66.1") == "172.16.66.1"
    assert clean_ip("-") == ""
    assert parse_ts("2026-09-02T09:25:00.1234567Z").microsecond == 123456
    assert parse_ts("2020-07-22 20:29:36.425364+00:00").year == 2020
    assert parse_ts(1788339600000).year == 2026


def test_okta_push_bombing_maps_and_fires():
    evs = load_file(FX / "okta_system_log.json")
    types = [e.event_type for e in evs if e.kind == "auth"]
    assert types.count("mfa_denied") == 6 and "mfa_success" in types and "mfa_challenge" in types
    assert any(e.kind == "identity" and e.change_type == "group_add" and e.group == "Okta Super Admins" for e in evs)
    assert any(e.kind == "identity" and e.change_type == "mfa_enrolled" for e in evs)
    nl = next(e for e in evs if e.source_ip == "185.220.101.44")
    assert nl.geo == "NL" and nl.geo_lat == pytest.approx(52.37)
    alerts = detect(evs, only=["mfa_fatigue"])
    assert len(alerts) == 1 and alerts[0].success_after_failures


def test_entra_signins_and_audit():
    evs = load_file(FX / "entra_signins.json")
    by = {e.raw["id"]: e for e in evs}
    assert by["s1"].event_type == "login_success" and by["s1"].geo == "US"
    assert by["s3"].event_type == "mfa_denied"
    assert by["s4"].event_type == "login_failure" and by["s5"].event_type == "lockout"
    trip = detect(evs, only=["impossible_travel"])
    assert trip and trip[0].detail["precision"] == "coordinates"
    audit = load_file(FX / "entra_audit.json")
    assert audit[0].change_type == "group_add" and audit[0].group == "Global Administrator"


def test_cloudtrail_records_and_console_login():
    evs = load_file(FX / "cloudtrail.json")
    cloud = [e for e in evs if e.kind == "cloud"]
    assert {e.api_call for e in cloud} == {"ConsoleLogin", "PutBucketPolicy", "StopLogging"}
    assert next(e for e in cloud if e.api_call == "PutBucketPolicy").resource == "corp-backups"
    stop = next(e for e in cloud if e.api_call == "StopLogging")
    assert stop.source_ip == "" and stop.user == "admin"
    login = next(e for e in evs if e.kind == "auth")
    assert login.event_type == "login_success" and login.mfa_factor == ""


def test_elastic_ecs_kinds():
    kinds = {e.kind: e for e in load_file(FX / "elastic_search.json")}
    assert kinds["auth"].event_type == "login_failure" and kinds["auth"].geo == "CN"
    assert kinds["process"].parent_name == "winword.exe"
    assert kinds["network"].dest_port == 443


def test_splunk_routes_raw_by_shape():
    evs = load_file(FX / "splunk_export.json")
    assert {e.source for e in evs} == {"sshd", "windows", "okta_json"}
    win = next(e for e in evs if e.source == "windows")
    assert win.user == "svc-sql" and win.logon_type == "network"


def test_sshd_counts_invalid_user_once():
    evs = load_file(FX / "sshd_auth.log")
    assert [e.event_type for e in evs].count("login_failure") == 2
    assert any(e.event_type == "login_success" and e.user == "deploy" for e in evs)


@pytest.mark.skipif(not (REAL / "kerberos_pwd_spray_4771.evtx").exists(), reason="run scripts/fetch_real_samples.py")
def test_real_kerberos_spray_detected():
    alerts = detect(load_file(REAL / "kerberos_pwd_spray_4771.evtx"))
    spray = [a for a in alerts if a.rule == "password_spray"]
    assert len(spray) == 1
    assert spray[0].detail["distinct_users"] == 9 and spray[0].detail["succeeded_users"] == ["normal"]


@pytest.mark.skipif(not (REAL / "Network_Service_Guest_added_to_admins_4732.evtx").exists(), reason="samples not fetched")
def test_real_windows_group_add_parses():
    evs = list(iter_events(REAL / "Network_Service_Guest_added_to_admins_4732.evtx"))
    assert all(e.kind == "identity" and e.change_type == "group_add" and e.group == "Administrators" for e in evs)


def test_sshd_year_rollover(tmp_path):
    from datetime import datetime, timezone
    from warden.adapters import sshd
    f = tmp_path / "auth.log"
    f.write_text("Dec 31 23:59:00 h sshd[1]: Failed password for root from 5.6.7.8 port 22 ssh2\n"
                 "Jan 01 00:01:00 h sshd[1]: Accepted password for bob from 5.6.7.8 port 22 ssh2\n")
    a, b = list(sshd.parse(f))
    assert b.ts.year == a.ts.year + 1 and b.ts > a.ts
    assert b.ts <= datetime.now(timezone.utc).replace(year=datetime.now().year + 1)
    assert a.ts < datetime.now(timezone.utc)
