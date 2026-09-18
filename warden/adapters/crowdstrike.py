"""CrowdStrike Falcon: Falcon Data Replicator (FDR) sensor telemetry and Streaming API events.

FDR records are flat JSON keyed by `event_simpleName` (ProcessRollup2, UserLogon, ...).
Streaming API records wrap an `event` in `metadata.eventType` (DetectionSummaryEvent, ...).
Both arrive as JSON lines or as concatenated JSON objects.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from ..events import AuthEvent, Event, FileEvent, IdentityChangeEvent, NetworkEvent, ProcessEvent
from ._util import clean_ip, parse_ts

NAME = "crowdstrike"

LOGON_TYPES = {"2": "interactive", "3": "network", "4": "batch", "5": "service", "7": "unlock",
               "10": "remote_interactive", "11": "cached_interactive"}
PROTOCOLS = {"6": "tcp", "17": "udp", "1": "icmp"}
IDENTITY = {"UserAccountCreated": "account_created", "ActiveDirectoryAccountCreated": "account_created",
            "UserAccountDeleted": "account_deleted", "UserAccountAddedToGroup": "group_add",
            "UserAccountRemovedFromGroup": "group_remove"}
FILE_DELETE = {"FileDeleteInfo", "ExecutableDeleted", "ProcessSelfDeleted"}
FILE_RENAME = {"FileRenameInfo", "NewExecutableRenamed"}
DETECTIONS = {"DetectionSummaryEvent", "EppDetectionSummaryEvent"}


def sniff(head: str, path: Path) -> bool:
    return '"event_simpleName"' in head or ('"metadata"' in head and '"customerIDString"' in head)


def _base(p: str) -> str:
    return p.replace("/", "\\").rsplit("\\", 1)[-1].lower()


def _int(v) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _fdr(r: dict) -> Event | None:
    name = r.get("event_simpleName", "")
    ts = parse_ts(float(r["ContextTimeStamp"]) if r.get("ContextTimeStamp") else int(r.get("timestamp", 0)))
    common = dict(ts=ts, source="crowdstrike", host=(r.get("ComputerName") or r.get("aid", "")).lower(),
                  user=r.get("UserName", ""), entity_ids={k: r[k] for k in ("aid", "TargetProcessId", "ContextProcessId") if r.get(k)},
                  raw={"event_simpleName": name, "id": r.get("id", "")})
    if name in ("ProcessRollup2", "SyntheticProcessRollup2"):
        image = r.get("ImageFileName", "")
        return ProcessEvent(**common, action="start", process_name=_base(image), image=image,
                            command_line=r.get("CommandLine", ""), parent_name=_base(r.get("ParentBaseFileName", "")),
                            pid=_int(r.get("RawProcessId")), sha256=r.get("SHA256HashData", ""))
    if name in ("NetworkConnectIP4", "NetworkConnectIP6"):
        return NetworkEvent(**common, source_ip=clean_ip(r.get("LocalAddressIP4") or r.get("LocalAddressIP6")),
                            dest_ip=clean_ip(r.get("RemoteAddressIP4") or r.get("RemoteAddressIP6")),
                            dest_port=_int(r.get("RemotePort")), source_port=_int(r.get("LocalPort")),
                            protocol=PROTOCOLS.get(str(r.get("Protocol")), ""),
                            process_name=_base(r.get("ContextBaseFileName", "")))
    if name in ("DnsRequest", "SuspiciousDnsRequest"):
        return NetworkEvent(**common, protocol="dns", domain=r.get("DomainName", "").rstrip(".").lower(),
                            dest_ip=clean_ip(r.get("RespondingDnsServer", "")),
                            process_name=_base(r.get("ContextBaseFileName", "")))
    if name in ("UserLogon", "UserLogonFailed", "UserLogonFailed2", "UserLogoff"):
        et = {"UserLogon": "login_success", "UserLogoff": "logout"}.get(name, "login_failure")
        return AuthEvent(**common, source_ip=clean_ip(r.get("RemoteAddressIP4") or r.get("RemoteAddressIP6")),
                         event_type=et, logon_type=LOGON_TYPES.get(str(r.get("LogonType")), ""),
                         outcome_reason=r.get("SubStatus", "") if et == "login_failure" else "")
    if name in IDENTITY:
        return IdentityChangeEvent(**{**common, "user": ""}, change_type=IDENTITY[name],
                                   target_user=r.get("UserName") or r.get("UserRid", ""), group=r.get("GroupRid", ""))
    if name in ("ScheduledTaskRegistered", "ScheduledTaskModified"):
        return ProcessEvent(**common, action="task_created", process_name="schtasks", target=r.get("TaskName", ""),
                            command_line=f"{r.get('TaskExecCommand', '')} {r.get('TaskExecArguments', '')}".strip())
    if name == "ServiceStarted" and r.get("ImageFileName"):
        return ProcessEvent(**common, action="service_installed", process_name="services.exe",
                            target=r.get("ImageFileName", ""), command_line=r.get("CommandLine", ""))
    path = r.get("TargetFileName", "")
    if path and name in FILE_DELETE:
        return FileEvent(**common, path=path, action="delete", process_name=_base(r.get("ContextImageFileName", "")))
    if path and name in FILE_RENAME:
        return FileEvent(**common, path=path, old_path=r.get("SourceFileName", ""), action="rename",
                         process_name=_base(r.get("ContextImageFileName", "")))
    if path and (name.endswith("Written") or name == "DirectoryCreate"):
        return FileEvent(**common, path=path, action="create", process_name=_base(r.get("ContextImageFileName", "")))
    return None


def _stream(r: dict) -> Event | None:
    et, e = r["metadata"].get("eventType", ""), r.get("event") or {}
    if et not in DETECTIONS:
        return None
    # A Falcon detection is kept as the process it fired on; the verdict rides in raw.
    image = f"{e.get('FilePath', '')}\\{e.get('FileName', '')}" if e.get("FilePath") else e.get("FileName", "")
    return ProcessEvent(ts=parse_ts(e.get("ProcessStartTime") or r["metadata"].get("eventCreationTime", 0)),
                        source="crowdstrike", host=(e.get("ComputerName") or e.get("Hostname", "")).lower(),
                        user=e.get("UserName", ""), source_ip=clean_ip(e.get("LocalIP", "")), action="start",
                        process_name=_base(e.get("FileName", "")), image=image, command_line=e.get("CommandLine", ""),
                        parent_name=_base(e.get("ParentImageFileName", "")), pid=_int(e.get("ProcessId")),
                        ppid=_int(e.get("ParentProcessId")), sha256=e.get("SHA256String", ""),
                        entity_ids={"aid": e["AgentId"]} if e.get("AgentId") else {},
                        raw={"falcon_detection": {k: e.get(k) for k in (
                            "DetectName", "Name", "DetectDescription", "Description", "SeverityName", "Tactic",
                            "Technique", "Objective", "SHA256String", "CompositeId") if e.get(k) is not None}})


def _records(path: Path) -> Iterator[dict]:
    text, dec, i = Path(path).read_text(errors="replace"), json.JSONDecoder(), 0
    while True:
        while i < len(text) and text[i] not in "{[":
            i += 1
        if i >= len(text):
            return
        try:
            obj, i = dec.raw_decode(text, i)
        except json.JSONDecodeError:
            i += 1
            continue
        yield from (obj if isinstance(obj, list) else [obj])


def parse(path: Path) -> Iterator[Event]:
    for r in _records(path):
        if not isinstance(r, dict):
            continue
        try:
            ev = _stream(r) if isinstance(r.get("metadata"), dict) else _fdr(r) if r.get("event_simpleName") else None
        except (ValueError, TypeError, KeyError):
            continue
        if ev is not None:
            yield ev
