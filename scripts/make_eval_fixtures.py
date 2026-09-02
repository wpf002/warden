"""Regenerate the labeled eval fixtures under data/eval/.

Each case is deliberately small and hand-labeled: these are the numbers every later
phase is measured against, so they need to be readable, not realistic in volume.

    python scripts/make_eval_fixtures.py
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVAL = ROOT / "data" / "eval"
T0 = datetime(2026, 9, 2, 9, 0, tzinfo=timezone.utc)
UA_MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
UA_BOT = "python-requests/2.31.0"


def ev(ts: datetime, **kw) -> dict:
    return {"ts": ts.isoformat(), "kind": "auth", **kw}


def noise(start: datetime, n: int, seed: int = 3) -> list[dict]:
    """Benign internal traffic. Never enough failures from one IP to fire anything."""
    import random
    rng = random.Random(seed)
    users = ["john.doe", "asmith", "mgarcia", "jlee", "pwong"]
    hosts = ["web-01", "jump-01", "ad-dc-01"]
    ips = [f"10.0.{rng.randint(1, 9)}.{rng.randint(2, 250)}" for _ in range(20)]
    out = []
    for _ in range(n):
        ts = start + timedelta(seconds=rng.randint(0, 3600))
        out.append(ev(ts, source="splunk",
                      event_type="login_failure" if rng.random() < 0.07 else "login_success",
                      user=rng.choice(users), source_ip=rng.choice(ips), host=rng.choice(hosts),
                      logon_type="network", user_agent=UA_MAC))
    return out


def write(name: str, events: list[dict], spec: dict) -> None:
    d = EVAL / name
    d.mkdir(parents=True, exist_ok=True)
    events.sort(key=lambda r: r["ts"])
    with open(d / "events.jsonl", "w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")
    (d / "expected.json").write_text(json.dumps(spec, indent=2) + "\n")
    print(f"{name}: {len(events)} events, {len(spec['alerts'])} expected alerts")


# ---------------------------------------------------------------- cases
def case_brute_force() -> None:
    ip, base = "203.0.113.42", T0 + timedelta(minutes=10)
    evs = noise(T0, 120, seed=11)
    for i in range(18):
        evs.append(ev(base + timedelta(seconds=i * 7), source="splunk", event_type="login_failure",
                      user="john.doe", source_ip=ip, host="vpn-gw-01", user_agent=UA_BOT,
                      outcome_reason="bad_password"))
    evs.append(ev(base + timedelta(seconds=133), source="splunk", event_type="login_success",
                  user="john.doe", source_ip=ip, host="vpn-gw-01", user_agent=UA_BOT))
    write("01-brute-force-vpn", evs, {
        "name": "brute force on the VPN gateway, then a success",
        "description": "18 failures for one account from a Russian IP, followed by a login. Crown-jewel asset.",
        "alerts": [{
            "rule": "brute_force", "match": {"source_ip": ip, "user": "john.doe"},
            "label": "true_positive", "risk_min": 80,
            "expect_actions": {"block_ip": "execute", "lock_user": "approve",
                               "create_ticket": "execute", "notify": "execute"},
            "note": "PB-004: auto-block the source, hold the account lock for an analyst.",
        }],
    })


def case_password_spray() -> None:
    ip, base = "198.51.100.17", T0 + timedelta(minutes=25)
    users = ["john.doe", "asmith", "mgarcia", "svc-backup", "admin", "jlee", "pwong"]
    evs = noise(T0, 120, seed=12)
    for i, u in enumerate(users * 2):
        evs.append(ev(base + timedelta(seconds=i * 11), source="okta", event_type="login_failure",
                      user=u, source_ip=ip, host="ad-dc-01", user_agent=UA_BOT, outcome_reason="bad_password"))
    write("02-password-spray-idp", evs, {
        "name": "password spray against the IdP",
        "description": "14 failures across 7 accounts from one IP, two attempts each. No success.",
        "alerts": [{
            "rule": "password_spray", "match": {"source_ip": ip},
            "label": "true_positive", "risk_min": 70,
            "expect_actions": {"block_ip": "execute", "create_ticket": "execute", "notify": "execute"},
            "note": "PB-005 lowers the auto-block threshold to 70 for spray.",
        }],
    })


def case_impossible_travel() -> None:
    base = T0 + timedelta(minutes=40)
    evs = noise(T0, 120, seed=13)
    evs += [
        ev(base, source="okta", event_type="login_success", user="mgarcia",
           source_ip="72.14.201.9", host="web-01", geo="US", user_agent=UA_MAC, logon_type="network"),
        ev(base + timedelta(minutes=22), source="okta", event_type="login_success", user="mgarcia",
           source_ip="45.83.140.6", host="web-01", user_agent=UA_BOT, logon_type="network"),
    ]
    write("03-impossible-travel", evs, {
        "name": "impossible travel, US to DE in 22 minutes",
        "description": "Two successful logins for one account 7,000+ km apart. Device fingerprint also changes.",
        "alerts": [{
            "rule": "impossible_travel", "match": {"user": "mgarcia", "source_ip": "45.83.140.6"},
            "label": "true_positive", "risk_min": 60,
            "expect_actions": {"lock_user": "approve", "create_ticket": "execute", "notify": "execute"},
            "note": "PB-007: never auto-block either leg, one of the two IPs is the real user.",
        }],
    })


def case_mfa_fatigue() -> None:
    ip, base = "185.220.101.44", T0 + timedelta(minutes=50)
    evs = noise(T0, 120, seed=14)
    for i in range(7):
        evs.append(ev(base + timedelta(seconds=i * 80), source="okta",
                      event_type="mfa_timeout" if i % 3 == 2 else "mfa_denied",
                      user="asmith", source_ip=ip, host="ad-dc-01", mfa_factor="push",
                      outcome_reason="user_rejected", user_agent=UA_BOT))
    evs.append(ev(base + timedelta(seconds=600), source="okta", event_type="mfa_success",
                  user="asmith", source_ip=ip, host="ad-dc-01", mfa_factor="push", user_agent=UA_BOT))
    evs.append(ev(base + timedelta(seconds=605), source="okta", event_type="login_success",
                  user="asmith", source_ip=ip, host="ad-dc-01", user_agent=UA_BOT, logon_type="network"))
    write("04-mfa-fatigue-approved", evs, {
        "name": "MFA push bombing ending in an approval",
        "description": "Seven denied or timed-out pushes in nine minutes, then the user taps approve.",
        "alerts": [{
            "rule": "mfa_fatigue", "match": {"user": "asmith", "source_ip": ip},
            "label": "true_positive", "risk_min": 80,
            "expect_actions": {"block_ip": "execute", "lock_user": "approve",
                               "create_ticket": "execute", "notify": "execute"},
            "note": "PB-008: approval after a burst is a presumed compromise.",
        }],
    })


def case_service_account_fp() -> None:
    """The known false positive from INC-2026-0642. It SHOULD fire; it should not act."""
    ip, base = "10.0.7.31", T0 + timedelta(minutes=15)
    evs = noise(T0, 120, seed=15)
    for i in range(14):
        evs.append(ev(base + timedelta(seconds=i * 12), source="splunk", event_type="login_failure",
                      user="svc-backup", source_ip=ip, host="jump-01", logon_type="service",
                      outcome_reason="bad_password"))
    write("05-service-account-fp", evs, {
        "name": "service account failing after a credential rotation",
        "description": "Textbook false positive: svc-backup grinding from an internal host with a stale secret.",
        "alerts": [{
            "rule": "brute_force", "match": {"source_ip": ip, "user": "svc-backup"},
            "label": "false_positive", "risk_max": 40,
            "expect_actions": {"create_ticket": "execute", "notify": "execute"},
            "note": "Detection firing is correct. Auto-blocking an internal host is not.",
        }],
    })


def case_quiet_hour() -> None:
    write("06-quiet-hour", noise(T0, 400, seed=16), {
        "name": "an hour of ordinary traffic",
        "description": "Nothing should fire. Anything that does is a false positive.",
        "alerts": [],
    })


if __name__ == "__main__":
    EVAL.mkdir(parents=True, exist_ok=True)
    case_brute_force()
    case_password_spray()
    case_impossible_travel()
    case_mfa_fatigue()
    case_service_account_fp()
    case_quiet_hour()
    print(f"\nfixtures written to {EVAL}")
