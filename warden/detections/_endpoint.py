"""Shared matching for endpoint rules: process families and a helper that turns a
ProcessEvent into an alert."""
from __future__ import annotations

import re

from ..events import ProcessEvent

OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "mspub.exe", "visio.exe",
          "msaccess.exe", "eqnedt32.exe"}
SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
          "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msiexec.exe", "schtasks.exe", "wmic.exe", "hh.exe",
          "forfiles.exe", "scriptrunner.exe"}
USER_WRITABLE = re.compile(r"\\users\\|\\appdata\\|\\temp\\|\\programdata\\|\\public\\|\\downloads\\|%temp%|%appdata%", re.I)


def rx(*parts: str) -> re.Pattern:
    return re.compile("|".join(parts), re.I)


def evidence(e: ProcessEvent) -> dict:
    return {"ts": e.ts.isoformat(), "user": e.user, "host": e.host,
            "type": f"{e.action} {e.parent_name + ' -> ' if e.parent_name else ''}{e.process_name}"
                    f"{' ' + e.target if e.target else ''}", "cmd": e.command_line[:300]}


def proc_alert(det, e: ProcessEvent, title: str, mitre: list[str] | None = None, **detail):
    a = det.new_alert(
        key=f"{e.host}|{e.process_name}|{e.pid}|{e.target[:60]}|{e.command_line[:60]}", first_seen=e.ts, ts=e.ts,
        title=title, source_ip=e.source_ip, users=[e.user] if e.user else [], hosts=[e.host] if e.host else [],
        geo=e.geo, asset_tier=e.asset_tier, last_seen=e.ts,
        detail={"process": e.process_name, "parent": e.parent_name, "command_line": e.command_line[:1000],
                "target": e.target, **detail},
        evidence=[evidence(e)],
    )
    if mitre:
        a.mitre = mitre
    return a
