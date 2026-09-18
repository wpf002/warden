"""Ingestion and normalization. Stage 2 of the pipeline.

Sources produce dicts in their own shape. Each adapter maps to an `Event` subclass.
Per-source adapters live in warden/adapters/; this module normalizes and enriches.
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Iterator

from .events import AuthEvent, Event, parse_event
from .geo import country_for_ip

# ---- enrichment tables (stand-ins for GeoIP / CMDB lookups) ----
ASSETS = {"vpn-gw-01": "crown_jewel", "ad-dc-01": "crown_jewel", "web-01": "standard", "jump-01": "standard"}


def enrich_geo(ip: str) -> str:
    return country_for_ip(ip)


def enrich_asset(host: str) -> str:
    return ASSETS.get(host, "unknown")


# ---- adapters ----
# Per-source parsing lives in warden/adapters/. These two names stay for v0.1 callers.
def from_generic_json(rec: dict) -> Event:
    return parse_event({**rec, "raw": rec})


def from_syslog_sshd(line: str) -> AuthEvent | None:
    from .adapters.sshd import parse_line
    return parse_line(line)


# ---- pipeline ----
def normalize(events: Iterable[Event]) -> list[Event]:
    """Dedupe, enrich, sort. Output is what detection sees."""
    seen: set[str] = set()
    out: list[Event] = []
    for e in events:
        k = e.dedupe_key()
        if k in seen:
            continue
        seen.add(k)
        e.geo = e.geo or (enrich_geo(e.source_ip) if e.source_ip else "")
        e.asset_tier = enrich_asset(e.host) if e.host else "unknown"
        out.append(e)
    out.sort(key=lambda e: e.ts)
    return out


def load_file(path: Path, fmt: str | None = None) -> list[Event]:
    """Read one log file with the matching adapter (autodetected unless `fmt` is given)."""
    from .adapters import iter_events
    return normalize(iter_events(Path(path), fmt))


def load_many(paths: Iterable[Path], fmt: str | None = None) -> list[Event]:
    from .adapters import iter_events
    def _all() -> Iterator[Event]:
        for p in paths:
            yield from iter_events(Path(p), fmt)
    return normalize(_all())


# ---- synthetic data (stands in for the SIEM feed) ----
UA_MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
UA_LINUX = "python-requests/2.31.0"


def _rec(ts: datetime, **kw) -> dict:
    return {"ts": ts.isoformat(), "kind": "auth", **kw}


def generate_logs(out: Path, events: int = 600, attackers: int = 2, seed: int = 7,
                  scenarios: bool = True) -> int:
    """Background noise plus scripted attacks, one per detection in the registry."""
    rng = random.Random(seed)
    users = ["john.doe", "asmith", "mgarcia", "svc-backup", "admin", "jlee", "pwong"]
    hosts = list(ASSETS)
    internal_ips = [f"10.0.{rng.randint(1, 20)}.{rng.randint(2, 250)}" for _ in range(30)]
    attacker_ips = ["203.0.113.42", "198.51.100.17", "192.0.2.99"][:attackers]
    t0 = datetime(2026, 9, 2, 14, 0, tzinfo=timezone.utc)
    recs: list[dict] = []

    # background noise: mostly successes, some scattered failures
    for _ in range(events):
        ts = t0 + timedelta(seconds=rng.randint(0, 3600))
        fail = rng.random() < 0.08
        recs.append(_rec(ts, source="splunk", event_type="login_failure" if fail else "login_success",
                         user=rng.choice(users), source_ip=rng.choice(internal_ips), host=rng.choice(hosts),
                         logon_type="network", user_agent=UA_MAC))

    # attacker 1: classic brute force on one account, then succeeds (T1110.001)
    ip = attacker_ips[0]
    base = t0 + timedelta(minutes=12)
    for i in range(18):
        recs.append(_rec(base + timedelta(seconds=i * 7), source="splunk", event_type="login_failure",
                         user="john.doe", source_ip=ip, host="vpn-gw-01", user_agent=UA_LINUX,
                         outcome_reason="bad_password"))
    recs.append(_rec(base + timedelta(seconds=18 * 7), source="splunk", event_type="login_success",
                     user="john.doe", source_ip=ip, host="vpn-gw-01", user_agent=UA_LINUX))

    # attacker 2: password spray across many users, no success (T1110.003)
    if attackers > 1:
        ip = attacker_ips[1]
        base = t0 + timedelta(minutes=31)
        for i, u in enumerate(users * 2):
            recs.append(_rec(base + timedelta(seconds=i * 11), source="okta", event_type="login_failure",
                             user=u, source_ip=ip, host="ad-dc-01", user_agent=UA_LINUX,
                             outcome_reason="bad_password"))

    if scenarios:
        recs += _impossible_travel_scenario(t0)
        recs += _mfa_fatigue_scenario(t0)

    recs.sort(key=lambda r: r["ts"])
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w") as f:
        for r in recs:
            f.write(json.dumps(r) + "\n")
    return len(recs)


def _impossible_travel_scenario(t0: datetime) -> list[dict]:
    """mgarcia signs in from the US, then 22 minutes later from Germany (T1078)."""
    base = t0 + timedelta(minutes=44)
    return [
        _rec(base, source="okta", event_type="login_success", user="mgarcia",
             source_ip="72.14.201.9", host="web-01", geo="US", user_agent=UA_MAC, logon_type="network"),
        _rec(base + timedelta(minutes=22), source="okta", event_type="login_success", user="mgarcia",
             source_ip="45.83.140.6", host="web-01", user_agent=UA_LINUX, logon_type="network"),
    ]


def _mfa_fatigue_scenario(t0: datetime) -> list[dict]:
    """Seven pushes to asmith in nine minutes; the eighth is approved (T1621)."""
    base = t0 + timedelta(minutes=51)
    ip = "185.220.101.44"
    out = []
    for i in range(7):
        out.append(_rec(base + timedelta(seconds=i * 80), source="okta",
                        event_type="mfa_timeout" if i % 3 == 2 else "mfa_denied",
                        user="asmith", source_ip=ip, host="ad-dc-01", mfa_factor="push",
                        outcome_reason="user_rejected", user_agent=UA_LINUX))
    out.append(_rec(base + timedelta(seconds=7 * 80 + 40), source="okta", event_type="mfa_success",
                    user="asmith", source_ip=ip, host="ad-dc-01", mfa_factor="push", user_agent=UA_LINUX))
    out.append(_rec(base + timedelta(seconds=7 * 80 + 45), source="okta", event_type="login_success",
                    user="asmith", source_ip=ip, host="ad-dc-01", user_agent=UA_LINUX, logon_type="network"))
    return out
