"""Windows Security event log. Reads .evtx directly (python-evtx) or XML exported with
`wevtutil qe Security /f:xml` / Get-WinEvent ... | ToXml.

Mapped event ids:
    4624 logon success          4625 logon failure          4740 account lockout
    4768 Kerberos TGT request   (status 0 = success, otherwise a failure)
    4771 Kerberos pre-auth failure                          4776 NTLM credential validation
    4720 account created        4722 account enabled        4725 account disabled
    4726 account deleted        4724 password reset by another account
    4728/4732/4756 member added to a security group         4729/4733/4757 removed
    1102 audit log cleared      (kept for Phase 4 defense-evasion rules)
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterator

from ..events import AuthEvent, Event, IdentityChangeEvent
from ._util import clean_ip, parse_ts

NAME = "windows"
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

LOGON_TYPES = {"2": "interactive", "3": "network", "4": "batch", "5": "service", "7": "unlock",
               "8": "network_cleartext", "9": "new_credentials", "10": "remote_interactive", "11": "cached_interactive"}
GROUP_ADD = {"4728", "4732", "4756"}
GROUP_REMOVE = {"4729", "4733", "4757"}
KERB_STATUS = {"0x6": "unknown_principal", "0x12": "account_disabled_or_locked", "0x17": "password_expired",
               "0x18": "bad_password", "0x25": "clock_skew"}


def sniff(head: str, path: Path) -> bool:
    return head.lstrip().startswith("<") and "schemas.microsoft.com/win/2004/08/events/event" in head


def _records(path: Path) -> Iterator[str]:
    if path.suffix.lower() == ".evtx":
        try:
            import Evtx.Evtx as evtx
        except ImportError as e:  # pragma: no cover
            raise RuntimeError("reading .evtx needs python-evtx: pip install python-evtx") from e
        with evtx.Evtx(str(path)) as log:
            for r in log.records():
                yield r.xml()
        return
    text = path.read_text(errors="replace")
    for m in re.finditer(r"<Event[ >].*?</Event>", text, re.S):
        yield m.group(0)


def _parse_xml(xml: str) -> tuple[str, dict, dict]:
    root = ET.fromstring(xml)
    sysn = root.find("e:System", NS)
    eid = (sysn.findtext("e:EventID", default="", namespaces=NS) or "").strip()
    tc = sysn.find("e:TimeCreated", NS)
    system = {
        "event_id": eid,
        "ts": tc.get("SystemTime") if tc is not None else "",
        "computer": sysn.findtext("e:Computer", default="", namespaces=NS),
        "record_id": sysn.findtext("e:EventRecordID", default="", namespaces=NS),
    }
    data = {}
    ed = root.find("e:EventData", NS)
    if ed is not None:
        for d in ed.findall("e:Data", NS):
            if d.get("Name"):
                data[d.get("Name")] = (d.text or "").strip()
    return eid, system, data


def _user(data: dict, key: str = "TargetUserName") -> str:
    u = data.get(key, "")
    return "" if u in ("-", "") else u


def to_event(eid: str, sysd: dict, data: dict) -> Event | None:
    ts = parse_ts(sysd["ts"])
    host = sysd["computer"].split(".")[0].lower() if sysd["computer"] else ""
    raw = {"event_id": eid, "record_id": sysd["record_id"], "computer": sysd["computer"], **data}
    ip = clean_ip(data.get("IpAddress"))
    common = dict(ts=ts, source="windows", host=host, source_ip=ip, raw=raw)

    if eid in ("4624", "4625"):
        return AuthEvent(**common, user=_user(data), event_type="login_success" if eid == "4624" else "login_failure",
                         logon_type=LOGON_TYPES.get(data.get("LogonType", ""), data.get("LogonType", "")),
                         outcome_reason=data.get("SubStatus") or data.get("Status", ""),
                         session_id=data.get("TargetLogonId", ""))
    if eid == "4768":
        status = data.get("Status", "0x0").lower()
        ok = status in ("0x0", "0x00000000", "0")
        short = "0x" + status[2:].lstrip("0") if status.startswith("0x") else status
        return AuthEvent(**common, user=_user(data), event_type="login_success" if ok else "login_failure",
                         logon_type="kerberos", outcome_reason="" if ok else KERB_STATUS.get(short, status))
    if eid == "4771":
        status = data.get("Status", "").lower()
        short = "0x" + status[2:].lstrip("0") if status.startswith("0x") else status
        return AuthEvent(**common, user=_user(data), event_type="login_failure", logon_type="kerberos",
                         outcome_reason=KERB_STATUS.get(short, status))
    if eid == "4776":
        ok = data.get("Status", "0x0").lower() in ("0x0", "0x00000000")
        return AuthEvent(**{**common, "host": (data.get("Workstation") or host).lower()},
                         user=_user(data, "TargetUserName"), event_type="login_success" if ok else "login_failure",
                         logon_type="ntlm", outcome_reason="" if ok else data.get("Status", ""))
    if eid == "4740":
        return AuthEvent(**common, user=_user(data), event_type="lockout")

    actor = _user(data, "SubjectUserName")
    if eid in GROUP_ADD | GROUP_REMOVE:
        member = data.get("MemberName", "")
        target = member if member not in ("-", "") else data.get("MemberSid", "")
        if target.upper().startswith("CN="):
            target = target.split(",")[0][3:]
        return IdentityChangeEvent(**common, user=actor, target_user=target, group=data.get("TargetUserName", ""),
                                   change_type="group_add" if eid in GROUP_ADD else "group_remove")
    changes = {"4720": "account_created", "4722": "account_enabled", "4725": "account_disabled",
               "4726": "account_deleted", "4724": "password_reset"}
    if eid in changes:
        return IdentityChangeEvent(**common, user=actor, target_user=_user(data), change_type=changes[eid])
    if eid == "1102":
        from ..events import CloudAuditEvent  # generic audit record until ProcessEvent-level rules exist
        return CloudAuditEvent(**common, user=_user(data, "SubjectUserName"), provider="windows",
                               api_call="audit_log_cleared", outcome="success")
    return None


def parse(path: Path) -> Iterator[Event]:
    for xml in _records(path):
        try:
            eid, sysd, data = _parse_xml(xml)
        except ET.ParseError:
            continue
        ev = to_event(eid, sysd, data)
        if ev is not None:
            yield ev
