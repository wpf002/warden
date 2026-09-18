"""Shared helpers for cloud audit rules."""
from __future__ import annotations

import json

from ..events import CloudAuditEvent


def params(e: CloudAuditEvent) -> dict:
    p = (e.raw or {}).get("requestParameters") or {}
    return p if isinstance(p, dict) else {}


def doc(v) -> dict:
    """Policy documents arrive as dicts or URL-encoded JSON strings."""
    if isinstance(v, dict):
        return v
    if isinstance(v, str):
        from urllib.parse import unquote
        try:
            return json.loads(unquote(v))
        except (json.JSONDecodeError, TypeError):
            return {}
    return {}


def statements(policy: dict) -> list[dict]:
    st = policy.get("Statement") or []
    return st if isinstance(st, list) else [st]


def as_list(v) -> list:
    return v if isinstance(v, list) else [v]


def cloud_alert(det, e: CloudAuditEvent, title: str, mitre: list[str] | None = None, **detail):
    a = det.new_alert(
        key=f"{e.account_id}|{e.api_call}|{e.resource}|{e.ts.isoformat()}", first_seen=e.ts, ts=e.ts, title=title,
        source_ip=e.source_ip, users=[e.user] if e.user else [], hosts=[e.host] if e.host else [], geo=e.geo,
        asset_tier="crown_jewel", last_seen=e.ts,
        detail={"api_call": e.api_call, "resource": e.resource, "region": e.region, "account": e.account_id,
                "provider": e.provider, **detail},
        evidence=[{"ts": e.ts.isoformat(), "user": e.user, "host": e.host,
                   "type": f"{e.provider}:{e.api_call} {e.resource}".strip()}],
    )
    if mitre:
        a.mitre = mitre
    return a
