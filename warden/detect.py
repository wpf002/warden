"""Detection rules. Deterministic. The LLM never decides whether something IS an alert,
only how to explain and respond to one. Keep it that way."""
from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import timedelta

from .config import settings
from .models import Alert, AuthEvent


def _alert_id(rule: str, ip: str, first_seen) -> str:
    return "ALT-" + hashlib.sha1(f"{rule}|{ip}|{first_seen.isoformat()}".encode()).hexdigest()[:8].upper()


def detect_brute_force(events: list[AuthEvent], threshold: int | None = None, window_sec: int | None = None) -> list[Alert]:
    """Sliding window per source IP. Fires once per IP per burst.
    brute_force   = many failures against one user
    password_spray = many failures spread across many users
    """
    threshold = threshold or settings.bf_threshold
    window = timedelta(seconds=window_sec or settings.bf_window_sec)

    by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for e in events:
        by_ip[e.source_ip].append(e)

    alerts: list[Alert] = []
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
                users = sorted({e.user for e in burst})
                rule = "password_spray" if len(users) >= max(3, len(burst) // 3) else "brute_force"
                last = burst[-1].ts
                success_after = any(
                    e.event_type == "login_success" and e.user in users and last <= e.ts <= last + window for e in evs
                )
                alerts.append(Alert(
                    id=_alert_id(rule, ip, burst[0].ts),
                    ts=last,
                    rule=rule,
                    title=f"{'Password spray' if rule == 'password_spray' else 'Brute force'} from {ip}"
                          + (" followed by SUCCESSFUL login" if success_after else ""),
                    source_ip=ip,
                    users=users,
                    failed_attempts=len(burst),
                    window_sec=int(window.total_seconds()),
                    first_seen=burst[0].ts,
                    last_seen=last,
                    success_after_failures=success_after,
                    hosts=sorted({e.host for e in burst if e.host}),
                    geo=burst[0].geo,
                    asset_tier=max((e.asset_tier for e in burst), key=lambda t: {"crown_jewel": 2, "standard": 1}.get(t, 0)),
                    evidence=[{"ts": e.ts.isoformat(), "user": e.user, "host": e.host, "type": e.event_type} for e in burst[:25]],
                ))
            i = j + 1
    alerts.sort(key=lambda a: a.ts)
    return alerts
