"""Shared sliding-window burst scan used by the T1110 family."""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Iterator

from ..events import AuthEvent


def failure_bursts(
    events: list[AuthEvent], threshold: int, window_sec: int
) -> Iterator[tuple[str, list[AuthEvent], list[AuthEvent]]]:
    """Yield (source_ip, burst, all_events_from_that_ip).

    A burst is >= `threshold` login failures from one IP inside `window_sec`.
    Bursts do not overlap: the scan resumes after the end of the one it emitted.
    """
    window = timedelta(seconds=window_sec)
    by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for e in events:
        by_ip[e.source_ip].append(e)

    for ip, evs in by_ip.items():
        fails = [e for e in evs if e.event_type == "login_failure"]
        if len(fails) < threshold:
            continue
        i = 0
        while i < len(fails):
            j = i
            while j + 1 < len(fails) and fails[j + 1].ts - fails[i].ts <= window:
                j += 1
            burst = fails[i:j + 1]
            if len(burst) >= threshold:
                yield ip, burst, evs
            i = j + 1


def is_spray(burst: list[AuthEvent]) -> bool:
    """Same test password_spray fires on: enough distinct accounts, few tries each."""
    from ..config import settings
    users = {e.user for e in burst}
    return len(users) >= settings.spray_min_users and len(burst) / len(users) <= settings.spray_max_per_user


def success_after(evs: list[AuthEvent], users: set[str], last, window_sec: int) -> bool:
    window = timedelta(seconds=window_sec)
    return any(
        e.event_type == "login_success" and e.user in users and last <= e.ts <= last + window for e in evs
    )


def top_asset_tier(evs: list[AuthEvent]) -> str:
    return max((e.asset_tier for e in evs), key=lambda t: {"crown_jewel": 2, "standard": 1}.get(t, 0), default="unknown")


def evidence(evs: list[AuthEvent], limit: int = 25) -> list[dict]:
    return [{"ts": e.ts.isoformat(), "user": e.user, "host": e.host, "type": e.event_type} for e in evs[:limit]]
