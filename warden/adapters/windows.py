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

from ..events import AuthEvent, Event, FileEvent, IdentityChangeEvent, NetworkEvent, ProcessEvent
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
    system["provider"] = (sysn.find("e:Provider", NS).get("Name") if sysn.find("e:Provider", NS) is not None else "")
    system["channel"] = sysn.findtext("e:Channel", default="", namespaces=NS)
    data = {}
    ed = root.find("e:EventData", NS)
    if ed is not None:
        for d in ed.findall("e:Data", NS):
            if d.get("Name"):
                data[d.get("Name")] = (d.text or "").strip()
    ud = root.find("e:UserData", NS)
    if ud is not None:   # 1102/104 and friends put their fields under UserData/<SomeName>/
        for el in ud.iter():
            tag = el.tag.split("}")[-1]
            if len(el) == 0 and el.text and el.text.strip():
                data.setdefault(tag, el.text.strip())
    return eid, system, data


def _user(data: dict, key: str = "TargetUserName") -> str:
    u = data.get(key, "")
    return "" if u in ("-", "") else u


def _base(path: str) -> str:
    return path.replace("/", "\\").rsplit("\\", 1)[-1].lower() if path else ""


def _int(v) -> int:
    try:
        return int(v, 16) if str(v).lower().startswith("0x") else int(v)
    except (TypeError, ValueError):
        return 0


def _sysmon(eid: str, sysd: dict, data: dict) -> Event | None:
    ts = parse_ts(data.get("UtcTime") or sysd["ts"])
    host = sysd["computer"].split(".")[0].lower() if sysd["computer"] else ""
    user = data.get("User", "")
    common = dict(ts=ts, source="sysmon", host=host, user=user.split("\\")[-1] if user else "",
                  raw={"event_id": eid, "provider": "sysmon", "computer": sysd["computer"], **data})
    img = data.get("Image", "")
    if eid == "1":
        return ProcessEvent(**common, action="start", process_name=_base(img), image=img,
                            command_line=data.get("CommandLine", ""), parent_name=_base(data.get("ParentImage", "")),
                            parent_command_line=data.get("ParentCommandLine", ""), pid=_int(data.get("ProcessId")),
                            ppid=_int(data.get("ParentProcessId")),
                            sha256=next((h.split("=")[1] for h in data.get("Hashes", "").split(",") if h.startswith("SHA256=")), ""))
    if eid == "3":
        initiated = data.get("Initiated", "true").lower() == "true"
        src, dst = ("Source", "Destination") if initiated else ("Destination", "Source")
        return NetworkEvent(**{**common, "source_ip": clean_ip(data.get(f"{src}Ip"))}, dest_ip=clean_ip(data.get(f"{dst}Ip")),
                            dest_port=_int(data.get(f"{dst}Port")), source_port=_int(data.get(f"{src}Port")),
                            protocol=data.get("Protocol", ""), domain=data.get(f"{dst}Hostname", ""),
                            process_name=_base(img), action="allowed")
    if eid == "10":
        return ProcessEvent(**{**common, "user": (data.get("SourceUser") or "").split("\\")[-1]}, action="access",
                            process_name=_base(data.get("SourceImage", "")), image=data.get("SourceImage", ""),
                            target=data.get("TargetImage", ""), granted_access=data.get("GrantedAccess", ""),
                            pid=_int(data.get("SourceProcessId")), command_line=data.get("CallTrace", "")[:500])
    if eid in ("12", "13", "14"):
        return ProcessEvent(**common, action="registry_set", process_name=_base(img), image=img,
                            target=data.get("TargetObject", ""), command_line=data.get("Details", ""),
                            pid=_int(data.get("ProcessId")))
    if eid in ("11", "23", "26"):
        return FileEvent(**common, path=data.get("TargetFilename", ""), process_name=_base(img),
                         action="create" if eid == "11" else "delete")
    if eid == "22":
        return NetworkEvent(**common, domain=data.get("QueryName", ""), protocol="dns", process_name=_base(img),
                            dns_type=data.get("QueryType", ""), action="allowed")
    return None


def to_event(eid: str, sysd: dict, data: dict) -> Event | None:
    if "Sysmon" in sysd.get("provider", ""):
        return _sysmon(eid, sysd, data)
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
    if eid in ("1102", "104"):
        return ProcessEvent(**{**common, "user": data.get("SubjectUserName", "")}, action="log_cleared",
                            process_name="eventlog", target=data.get("Channel") or ("Security" if eid == "1102" else ""))
    if eid == "4688":
        return ProcessEvent(**{**common, "user": _user(data, "SubjectUserName")}, action="start",
                            process_name=_base(data.get("NewProcessName", "")), image=data.get("NewProcessName", ""),
                            command_line=data.get("CommandLine", ""), parent_name=_base(data.get("ParentProcessName", "")),
                            pid=_int(data.get("NewProcessId")), ppid=_int(data.get("ProcessId")))
    if eid == "4698":
        content = data.get("TaskContent", "")
        cmd = " ".join(re.findall(r"<(?:Command|Arguments)>(.*?)</(?:Command|Arguments)>", content.replace("&lt;", "<").replace("&gt;", ">")))
        return ProcessEvent(**{**common, "user": _user(data, "SubjectUserName")}, action="task_created",
                            process_name="schtasks", target=data.get("TaskName", ""), command_line=cmd)
    if eid == "7045":
        return ProcessEvent(**{**common, "user": data.get("AccountName", "")}, action="service_installed",
                            process_name="services.exe", target=data.get("ImagePath", ""),
                            command_line=f"{data.get('ServiceName', '')}: {data.get('ImagePath', '')}")
    if eid == "4104":
        return ProcessEvent(**common, action="script_block", process_name="powershell.exe",
                            command_line=data.get("ScriptBlockText", "")[:4000])
    if eid in ("5001", "5007", "5010", "5012") and "Defender" in sysd.get("provider", ""):
        return ProcessEvent(**common, action="av_tamper", process_name="msmpeng.exe",
                            target=data.get("New Value", "") or data.get("Feature Name", "") or f"defender event {eid}")
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
