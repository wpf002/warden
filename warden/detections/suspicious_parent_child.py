"""T1059 / T1204.002: an Office application spawning a shell or script host (macro and
exploit delivery), and T1569.002: the service control manager spawning a shell
(PsExec-style remote execution)."""
from __future__ import annotations

from ..events import ProcessEvent
from ..models import Alert
from . import Detection, register
from ._endpoint import OFFICE, SHELLS, proc_alert


@register
class SuspiciousParentChild(Detection):
    id = "suspicious_parent_child"
    name = "Office or service manager spawning a shell"
    mitre = ["T1059", "T1204.002", "T1569.002"]
    event_kinds = ("process",)
    window_sec = 0
    playbook = "playbook-suspicious-parent-child"

    def run(self, events: list[ProcessEvent]) -> list[Alert]:
        out = []
        for e in events:
            if e.action != "start":
                continue
            if e.parent_name in OFFICE and e.process_name in SHELLS:
                out.append(proc_alert(self, e, f"{e.parent_name} spawned {e.process_name} on {e.host}",
                                      ["T1204.002", "T1059"], pattern="office_child"))
            elif e.parent_name == "services.exe" and e.process_name in {"cmd.exe", "powershell.exe", "pwsh.exe"}:
                out.append(proc_alert(self, e, f"services.exe spawned {e.process_name} on {e.host} (remote service execution)",
                                      ["T1569.002", "T1059"], pattern="service_shell"))
        return out
