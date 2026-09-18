"""OpenSSH auth.log / secure lines."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

from ..events import AuthEvent

NAME = "sshd"


def sniff(head: str, path: Path) -> bool:
    return "sshd[" in head


def parse_line(line: str, year: int | None = None) -> AuthEvent | None:
    """'Sep 02 12:00:01 web-01 sshd[123]: Failed password for bob from 1.2.3.4 port 22 ssh2'"""
    parts = line.split()
    if len(parts) < 10 or "sshd" not in line:
        return None
    ok = "Accepted" in line
    fail = "Failed password" in line or "Invalid user" in line
    if not (ok or fail):
        return None
    try:
        if "Invalid user" in line and "Failed" not in line:
            user = parts[parts.index("user") + 1]
        else:
            user = parts[parts.index("for") + 1]
            if user == "invalid":
                user = parts[parts.index("user") + 1]
        ip = parts[parts.index("from") + 1]
    except (ValueError, IndexError):
        return None
    ts = datetime.strptime(" ".join(parts[:3]), "%b %d %H:%M:%S").replace(year=year or datetime.now().year, tzinfo=timezone.utc)
    return AuthEvent(ts=ts, source="sshd", event_type="login_success" if ok else "login_failure",
                     user=user, source_ip=ip, host=parts[3], logon_type="remote_interactive", raw={"line": line})


def parse(path: Path) -> Iterator[AuthEvent]:
    """Syslog lines carry no year. Count a year forward when the month wraps (Dec -> Jan),
    then shift the whole file back if that puts its last event in the future."""
    seen_invalid: set[tuple[str, str]] = set()
    out: list[AuthEvent] = []
    year, last_month = datetime.now().year, 0
    with open(path, errors="replace") as f:
        for line in f:
            ev = parse_line(line.strip(), year)
            if ev is None:
                continue
            if ev.ts.month < last_month:
                year += 1
                ev = parse_line(line.strip(), year)
            last_month = ev.ts.month
            # sshd logs "Invalid user x" and then "Failed password for invalid user x" for one attempt
            key = (ev.ts.isoformat(), ev.user)
            if "Invalid user" in line and "Failed" not in line:
                seen_invalid.add(key)
            elif key in seen_invalid:
                continue
            out.append(ev)
    shift = 0
    while out and out[-1].ts.replace(year=out[-1].ts.year - shift) > datetime.now(timezone.utc) + timedelta(days=1):
        shift += 1
    for ev in out:
        if shift:
            ev.ts = ev.ts.replace(year=ev.ts.year - shift)
        yield ev
