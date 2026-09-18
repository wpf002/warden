"""Microsoft 365 unified audit log (Management Activity API, or a Purview audit search
export). Exchange operations become CloudAuditEvents with provider "m365"; the
`Parameters` list is kept on raw for the mailbox rules."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from ..events import AuthEvent, CloudAuditEvent, Event
from ._util import clean_ip, iter_json_records, parse_ts

NAME = "o365"


def sniff(head: str, path: Path) -> bool:
    return '"Operation"' in head and ('"Workload"' in head or '"RecordType"' in head)


def parse(path: Path) -> Iterator[Event]:
    for rec in iter_json_records(path):
        if "AuditData" in rec and isinstance(rec["AuditData"], str):     # Purview search export wraps the record
            rec = json.loads(rec["AuditData"])
        ip = clean_ip((rec.get("ClientIP") or rec.get("ClientIPAddress") or "").split(":")[0]
                      if rec.get("ClientIP", "").count(":") == 1 else (rec.get("ClientIP") or rec.get("ClientIPAddress")))
        ts = parse_ts(rec["CreationTime"])
        user = rec.get("UserId", "")
        op = rec.get("Operation", "")
        if op in ("UserLoggedIn", "UserLoginFailed"):
            yield AuthEvent(ts=ts, source="o365", user=user, source_ip=ip, host=rec.get("Workload", "m365"),
                            event_type="login_success" if op == "UserLoggedIn" else "login_failure", raw=rec)
            continue
        yield CloudAuditEvent(ts=ts, source="o365", user=user, source_ip=ip, host=rec.get("Workload", ""),
                              provider="m365", api_call=op, resource=str(rec.get("ObjectId", ""))[:200],
                              account_id=rec.get("OrganizationId", ""),
                              outcome="success" if rec.get("ResultStatus", "Succeeded") in ("Succeeded", "True", True, "") else "failure",
                              raw=rec)
