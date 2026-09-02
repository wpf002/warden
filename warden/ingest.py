"""Ingestion and normalization. Stage 2 of the pipeline.

Sources produce dicts in their own shape. Each adapter maps to AuthEvent.
Add a real SIEM by writing one adapter function and registering it.
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterable, Iterator

from .models import AuthEvent

# ---- enrichment tables (stand-ins for GeoIP / CMDB lookups) ----
GEO = {"203.0.113.": "RU", "198.51.100.": "CN", "192.0.2.": "BR", "10.": "internal", "172.16.": "internal"}
ASSETS = {"vpn-gw-01": "crown_jewel", "ad-dc-01": "crown_jewel", "web-01": "standard", "jump-01": "standard"}


def enrich_geo(ip: str) -> str:
    for prefix, geo in GEO.items():
        if ip.startswith(prefix):
            return geo
    return "US"


def enrich_asset(host: str) -> str:
    return ASSETS.get(host, "unknown")


# ---- adapters ----
def from_generic_json(rec: dict) -> AuthEvent:
    """Shape written by gen-logs and most SIEM JSON exports."""
    return AuthEvent(
        ts=datetime.fromisoformat(rec["ts"]),
        source=rec.get("source", "siem"),
        event_type=rec["event_type"],
        user=rec["user"],
        source_ip=rec["source_ip"],
        host=rec.get("host", ""),
        raw=rec,
    )


def from_syslog_sshd(line: str) -> AuthEvent | None:
    """'Sep 02 12:00:01 web-01 sshd[123]: Failed password for bob from 1.2.3.4 port 22 ssh2'"""
    parts = line.split()
    if len(parts) < 10 or "sshd" not in line:
        return None
    ok = "Accepted" in line
    fail = "Failed password" in line
    if not (ok or fail):
        return None
    try:
        user = parts[parts.index("for") + 1]
        if user == "invalid":
            user = parts[parts.index("user") + 1]
        ip = parts[parts.index("from") + 1]
    except (ValueError, IndexError):
        return None
    ts = datetime.strptime(" ".join(parts[:3]), "%b %d %H:%M:%S").replace(year=datetime.now().year, tzinfo=timezone.utc)
    return AuthEvent(ts=ts, source="sshd", event_type="login_success" if ok else "login_failure",
                     user=user, source_ip=ip, host=parts[3], raw={"line": line})


ADAPTERS: dict[str, Callable] = {"json": from_generic_json, "sshd": from_syslog_sshd}


# ---- pipeline ----
def normalize(events: Iterable[AuthEvent]) -> list[AuthEvent]:
    """Dedupe, enrich, sort. Output is what detection sees."""
    seen: set[str] = set()
    out: list[AuthEvent] = []
    for e in events:
        k = e.dedupe_key()
        if k in seen:
            continue
        seen.add(k)
        e.geo = e.geo or enrich_geo(e.source_ip)
        e.asset_tier = enrich_asset(e.host) if e.host else "unknown"
        out.append(e)
    out.sort(key=lambda e: e.ts)
    return out


def load_file(path: Path) -> list[AuthEvent]:
    def _iter() -> Iterator[AuthEvent]:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if line.startswith("{"):
                    yield from_generic_json(json.loads(line))
                else:
                    ev = from_syslog_sshd(line)
                    if ev:
                        yield ev
    return normalize(_iter())


# ---- synthetic data (stands in for the SIEM feed) ----
def generate_logs(out: Path, events: int = 600, attackers: int = 2, seed: int = 7) -> int:
    rng = random.Random(seed)
    users = ["john.doe", "asmith", "mgarcia", "svc-backup", "admin", "jlee", "pwong"]
    hosts = list(ASSETS)
    internal_ips = [f"10.0.{rng.randint(1, 20)}.{rng.randint(2, 250)}" for _ in range(30)]
    attacker_ips = ["203.0.113.42", "198.51.100.17", "192.0.2.99"][:attackers]
    t0 = datetime(2026, 9, 2, 14, 0, tzinfo=timezone.utc)
    recs: list[dict] = []

    # background noise: mostly successes, some scattered failures
    for i in range(events):
        ts = t0 + timedelta(seconds=rng.randint(0, 3600))
        fail = rng.random() < 0.08
        recs.append({"ts": ts.isoformat(), "source": "splunk", "event_type": "login_failure" if fail else "login_success",
                     "user": rng.choice(users), "source_ip": rng.choice(internal_ips), "host": rng.choice(hosts)})

    # attacker 1: classic brute force on one account, then succeeds
    ip = attacker_ips[0]
    base = t0 + timedelta(minutes=12)
    for i in range(18):
        recs.append({"ts": (base + timedelta(seconds=i * 7)).isoformat(), "source": "splunk", "event_type": "login_failure",
                     "user": "john.doe", "source_ip": ip, "host": "vpn-gw-01"})
    recs.append({"ts": (base + timedelta(seconds=18 * 7)).isoformat(), "source": "splunk", "event_type": "login_success",
                 "user": "john.doe", "source_ip": ip, "host": "vpn-gw-01"})

    # attacker 2: password spray across many users, no success
    if attackers > 1:
        ip = attacker_ips[1]
        base = t0 + timedelta(minutes=31)
        for i, u in enumerate(users * 2):
            recs.append({"ts": (base + timedelta(seconds=i * 11)).isoformat(), "source": "okta", "event_type": "login_failure",
                         "user": u, "source_ip": ip, "host": "ad-dc-01"})

    recs.sort(key=lambda r: r["ts"])
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w") as f:
        for r in recs:
            f.write(json.dumps(r) + "\n")
    return len(recs)
