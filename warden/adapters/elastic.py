"""Elastic / OpenSearch. Accepts a `_search` response, a list of hits, or ECS NDJSON.
Field mapping follows the Elastic Common Schema."""
from __future__ import annotations

from pathlib import Path
from typing import Iterator

from ..events import AuthEvent, Event, IdentityChangeEvent, NetworkEvent, ProcessEvent
from ._util import clean_ip, dig, iter_json_records, parse_ts

NAME = "elastic"


def sniff(head: str, path: Path) -> bool:
    return '"@timestamp"' in head and ('"event"' in head or '"_source"' in head)


def to_event(src: dict) -> Event | None:
    cats = dig(src, "event.category") or []
    cats = [cats] if isinstance(cats, str) else cats
    outcome = (dig(src, "event.outcome") or "").lower()
    action = (dig(src, "event.action") or "").lower()
    common = dict(
        ts=parse_ts(src["@timestamp"]), source=dig(src, "event.dataset") or dig(src, "event.module") or "elastic",
        host=(dig(src, "host.name") or "").lower(), user=dig(src, "user.name") or "",
        source_ip=clean_ip(dig(src, "source.ip")), geo=dig(src, "source.geo.country_iso_code") or "",
        geo_lat=dig(src, "source.geo.location.lat"), geo_lon=dig(src, "source.geo.location.lon"), raw=src,
    )
    if "authentication" in cats:
        if "mfa" in action:
            et = "mfa_success" if outcome == "success" else ("mfa_timeout" if "timeout" in action else "mfa_denied")
        elif "lock" in action:
            et = "lockout"
        else:
            et = "login_success" if outcome == "success" else "login_failure"
        return AuthEvent(**common, event_type=et, user_agent=dig(src, "user_agent.original") or "")
    if "iam" in cats:
        change = "group_add" if "added" in action or "add" in action else \
            "account_created" if "creat" in action else "password_reset" if "password" in action else None
        if change:
            return IdentityChangeEvent(**common, change_type=change,
                                       target_user=dig(src, "user.target.name") or "", group=dig(src, "group.name") or "")
    if "process" in cats:
        return ProcessEvent(**common, process_name=dig(src, "process.name") or "",
                            command_line=dig(src, "process.command_line") or "",
                            parent_name=dig(src, "process.parent.name") or "", pid=dig(src, "process.pid") or 0)
    if "network" in cats:
        return NetworkEvent(**common, dest_ip=dig(src, "destination.ip") or "", dest_port=dig(src, "destination.port") or 0,
                            protocol=dig(src, "network.transport") or "", domain=dig(src, "dns.question.name") or "",
                            bytes_out=dig(src, "source.bytes") or 0, bytes_in=dig(src, "destination.bytes") or 0)
    return None


def parse(path: Path) -> Iterator[Event]:
    for rec in iter_json_records(path):
        src = rec.get("_source", rec)
        ev = to_event(src)
        if ev is not None:
            yield ev
