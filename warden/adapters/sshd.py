"""OpenSSH auth.log / secure lines."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from ..events import AuthEvent

NAME = "sshd"


def sniff(head: str, path: Path) -> bool:
    return "sshd[" in head


def parse_line(line: str) -> AuthEvent | None:
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
    ts = datetime.strptime(" ".join(parts[:3]), "%b %d %H:%M:%S").replace(year=datetime.now().year, tzinfo=timezone.utc)
    return AuthEvent(ts=ts, source="sshd", event_type="login_success" if ok else "login_failure",
                     user=user, source_ip=ip, host=parts[3], logon_type="remote_interactive", raw={"line": line})


def parse(path: Path) -> Iterator[AuthEvent]:
    seen_invalid: set[tuple[str, str]] = set()
    with open(path, errors="replace") as f:
        for line in f:
            ev = parse_line(line.strip())
            if ev is None:
                continue
            # sshd logs "Invalid user x" and then "Failed password for invalid user x" for one attempt
            key = (ev.ts.isoformat(), ev.user)
            if "Invalid user" in line and "Failed" not in line:
                seen_invalid.add(key)
            elif key in seen_invalid:
                continue
            yield ev
