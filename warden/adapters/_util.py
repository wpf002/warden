"""Helpers shared by adapters."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

# Country names some sources emit instead of ISO codes.
COUNTRY_CODES = {
    "united states": "US", "united states of america": "US", "canada": "CA", "brazil": "BR",
    "united kingdom": "GB", "germany": "DE", "france": "FR", "netherlands": "NL", "russia": "RU",
    "russian federation": "RU", "china": "CN", "india": "IN", "japan": "JP", "australia": "AU",
    "nigeria": "NG", "south africa": "ZA", "singapore": "SG", "iran": "IR", "north korea": "KP",
    "ukraine": "UA",
}


def country_code(v: str | None) -> str:
    if not v:
        return ""
    v = v.strip()
    if len(v) == 2:
        return v.upper()
    return COUNTRY_CODES.get(v.lower(), v)


def clean_ip(ip: str | None) -> str:
    """Strip IPv4-mapped IPv6 and placeholders Windows uses for 'no address'."""
    if not ip or ip in ("-", "::1", "127.0.0.1", "localhost"):
        return "" if not ip or ip == "-" else ip
    if ip.lower().startswith("::ffff:"):
        return ip[7:]
    return ip


def parse_ts(v) -> datetime:
    if isinstance(v, (int, float)):
        return datetime.fromtimestamp(v / 1000 if v > 1e12 else v, tz=timezone.utc)
    s = str(v).strip().replace(" ", "T", 1) if "T" not in str(v) else str(v).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    # Python < 3.11 chokes on 7-digit fractions (Entra); trim to microseconds.
    if "." in s:
        head, frac = s.split(".", 1)
        digits = "".join(ch for ch in frac if ch.isdigit())
        tail = frac[len(digits):]
        s = f"{head}.{digits[:6]}{tail}"
    dt = datetime.fromisoformat(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def iter_json_records(path: Path, list_keys: tuple[str, ...] = ("value", "Records", "records", "results", "events")) -> Iterator[dict]:
    """Yield records from a JSON array, an object wrapping one, or JSON lines."""
    text = Path(path).read_text()
    stripped = text.lstrip()
    if stripped.startswith("["):
        yield from json.loads(stripped)
        return
    if stripped.startswith("{"):
        try:
            doc = json.loads(stripped)
        except json.JSONDecodeError:
            doc = None
        if isinstance(doc, dict):
            for k in list_keys:
                if isinstance(doc.get(k), list):
                    yield from doc[k]
                    return
            if "hits" in doc and isinstance(doc["hits"], dict):
                yield from doc["hits"].get("hits", [])
                return
            yield doc
            return
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("{"):
            yield json.loads(line)


def dig(d: dict, dotted: str, default=None):
    cur = d
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return default
        if part in cur:
            cur = cur[part]
        else:
            return default
    return cur
