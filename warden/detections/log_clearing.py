"""T1685.005 Indicator Removal: Clear Windows Event Logs. There is almost no
legitimate reason to clear the Security log on a production host."""
from __future__ import annotations

from ..events import ProcessEvent
from ..models import Alert
from . import Detection, register
from ._endpoint import proc_alert, rx

CMD = rx(r"wevtutil(\.exe)?\s+(cl|clear-log)\b", r"clear-eventlog", r"remove-eventlog", r"limit-eventlog.*-maximumsize",
         r"fsutil.*usn.*deletejournal", r"auditpol.*/clear", r"auditpol.*/remove")


@register
class LogClearing(Detection):
    id = "log_clearing"
    name = "Event log cleared or auditing removed"
    mitre = ["T1685.005", "T1685.001"]
    event_kinds = ("process",)
    window_sec = 0
    playbook = "playbook-log-clearing"

    def run(self, events: list[ProcessEvent]) -> list[Alert]:
        out = []
        for e in events:
            if e.action == "log_cleared":
                out.append(proc_alert(self, e, f"{e.target or 'An'} event log cleared on {e.host} by {e.user or 'unknown'}",
                                      ["T1685.005"], channel=e.target))
            elif e.action in ("start", "script_block") and CMD.search(e.command_line):
                out.append(proc_alert(self, e, f"Log clearing command on {e.host}", ["T1685.005"]))
        return out
