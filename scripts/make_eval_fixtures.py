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


if __name__ == "__main__":
    if EVAL.exists():
        shutil.rmtree(EVAL)
    EVAL.mkdir(parents=True)
    for fn in [case_brute_force, case_password_spray, case_impossible_travel, case_mfa_fatigue, case_service_account_fp,
               case_quiet_hour, case_credential_stuffing, case_new_geo_benign, case_attack_chain, case_dormant,
               case_service_account_rdp, case_create_then_privilege, case_session_replay, case_reset_abuse,
               case_lockout_storm, case_single_reset]:
        fn()
    print(f"\nfixtures written to {EVAL}")
