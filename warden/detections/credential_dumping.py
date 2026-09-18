"""T1003 OS Credential Dumping: LSASS memory access with read rights from a process
that has no business there, and the command lines of the usual dumpers (procdump,
comsvcs MiniDump, mimikatz, SAM/SYSTEM hive saves, NTDS extraction)."""
from __future__ import annotations

from ..events import ProcessEvent
from ..models import Alert
from . import Detection, register
from ._endpoint import proc_alert, rx

READ_MASKS = {0x10, 0x1010, 0x1410, 0x1438, 0x143a, 0x1418, 0x1fffff, 0x1f3fff, 0x1f1fff, 0x1f0fff, 0x40}
BENIGN_SOURCES = {"msmpeng.exe", "csrss.exe", "wininit.exe", "wmiprvse.exe", "lsm.exe", "mrt.exe", "svchost.exe",
                  "taskmgr.exe", "procexp64.exe", "vmtoolsd.exe", "sensecncproxy.exe", "mssense.exe"}
CMDS = [
    (rx(r"procdump.*\s-ma\s.*lsass", r"procdump.*lsass.*-ma"), "T1003.001", "procdump of LSASS"),
    (rx(r"comsvcs(\.dll)?[\s,]+#?(minidump|24)"), "T1003.001", "comsvcs MiniDump of LSASS"),
    (rx(r"sekurlsa::", r"lsadump::", r"invoke-mimikatz", r"privilege::debug"), "T1003.001", "mimikatz"),
    (rx(r"reg(\.exe)?\s+save\s+hklm\\(sam|system|security)"), "T1003.002", "registry hive save"),
    (rx(r"ntdsutil.*(ifm|ac\s+i\s+ntds)", r"\\ntds\.dit"), "T1003.003", "NTDS.dit extraction"),
    (rx(r"minidumpwritedump", r"out-minidump"), "T1003.001", "MiniDumpWriteDump in script"),
]


def _mask(v: str) -> int:
    try:
        return int(v, 16)
    except (TypeError, ValueError):
        return 0


@register
class CredentialDumping(Detection):
    id = "credential_dumping"
    name = "LSASS or credential store dumping"
    mitre = ["T1003.001", "T1003.002", "T1003.003"]
    event_kinds = ("process",)
    window_sec = 0
    playbook = "playbook-credential-dumping"

    def run(self, events: list[ProcessEvent]) -> list[Alert]:
        out = []
        for e in events:
            if e.action == "access" and e.target.lower().endswith("lsass.exe") and e.process_name not in BENIGN_SOURCES \
                    and _mask(e.granted_access) in READ_MASKS:
                out.append(proc_alert(self, e, f"{e.process_name} opened LSASS with {e.granted_access} on {e.host}",
                                      ["T1003.001"], granted_access=e.granted_access))
                continue
            if e.action in ("start", "script_block"):
                for pat, tech, what in CMDS:
                    if pat.search(e.command_line):
                        out.append(proc_alert(self, e, f"{what} on {e.host}", [tech], method=what))
                        break
        return out
