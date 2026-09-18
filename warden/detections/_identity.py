"""Helpers shared by the identity detections: name normalization, account classes,
privileged-group matching, change windows, and per-user history."""
from __future__ import annotations

import fnmatch
from collections import defaultdict
from datetime import datetime

from ..config import settings
from ..events import AuthEvent, Event


def norm_user(u: str) -> str:
    """'CORP\\\\asmith', 'asmith@corp.example', 'ASmith' -> 'asmith'. Lets Okta, Entra, and AD
    events about the same person land on the same entity."""
    u = (u or "").strip().lower()
    if "\\" in u:
        u = u.split("\\", 1)[1]
    if "@" in u:
        u = u.split("@", 1)[0]
    return u


def is_service_account(u: str) -> bool:
    n = norm_user(u)
    return any(fnmatch.fnmatch(n, p.strip().lower()) for p in settings.service_account_patterns.split(",") if p.strip())


def is_privileged_group(g: str) -> bool:
    g = (g or "").strip().lower()
    return any(g == p.strip().lower() for p in settings.privileged_groups.split(",") if p.strip())


def in_change_window(ts: datetime) -> bool:
    """WARDEN_CHANGE_WINDOW = 'days=sat,sun;hours=22-06' in UTC. Empty = no sanctioned window."""
    spec = settings.change_window.strip()
    if not spec:
        return False
    parts = dict(p.split("=", 1) for p in spec.split(";") if "=" in p)
    days = {d.strip()[:3].lower() for d in parts.get("days", "").split(",") if d.strip()}
    if days and ts.strftime("%a").lower() not in days:
        return False
    if "hours" in parts:
        start, end = (int(x) for x in parts["hours"].split("-"))
        h = ts.hour
        return (start <= h < end) if start < end else (h >= start or h < end)
    return True


INTERACTIVE = {"interactive", "remote_interactive", "cached_interactive", "unlock", "console"}


class History:
    """What we knew about each user before the events being scored. Built from stored
    events (the DB) plus earlier events in the same batch."""

    def __init__(self, prior: list[Event] | None = None):
        self.last_seen: dict[str, datetime] = {}
        self.geos: dict[str, set[str]] = defaultdict(set)
        self.devices: dict[str, set[str]] = defaultdict(set)
        self.logins: dict[str, int] = defaultdict(int)
        for e in prior or []:
            self.observe(e)

    def observe(self, e: Event) -> None:
        u = norm_user(e.user)
        if not u:
            return
        prev = self.last_seen.get(u)
        if prev is None or e.ts > prev:
            self.last_seen[u] = e.ts
        if isinstance(e, AuthEvent) and e.event_type == "login_success":
            self.logins[u] += 1
            if e.geo and e.geo != "internal":
                self.geos[u].add(e.geo)
            fp = device_fingerprint(e)
            if fp:
                self.devices[u].add(fp)


def device_fingerprint(e: AuthEvent) -> str:
    if e.device_id:
        return f"dev:{e.device_id}"
    if e.user_agent:
        # browser family + OS family; version churn should not look like a new device
        ua = e.user_agent.lower()
        fam = next((b for b in ("edg", "chrome", "firefox", "safari", "python-requests", "curl", "okhttp") if b in ua), "other")
        os_ = next((o for o in ("windows", "mac os", "iphone", "android", "linux") if o in ua), "other")
        return f"ua:{fam}/{os_}"
    return ""
