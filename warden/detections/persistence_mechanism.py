"""T1053.005 Scheduled Task, T1543.003 Windows Service, T1547.001 Run Keys: new
autostart entries. Every scheduled task and service install is recorded by Windows;
this rule fires on the ones pointing at shells, script hosts, or user-writable paths,
and on every write to the classic autostart registry keys."""
from __future__ import annotations

from ..events import ProcessEvent
from ..models import Alert
from . import Detection, register
from ._endpoint import USER_WRITABLE, proc_alert, rx

RISKY_TARGET = rx(r"cmd(\.exe)?\b", r"powershell", r"pwsh", r"mshta", r"rundll32", r"regsvr32", r"wscript", r"cscript",
                  r"\\\\[^\\]+\\admin\$", r"%comspec%", r"\.bat\b", r"\.vbs\b", r"\.ps1\b", r"\.hta\b",
                  r"\\users\\", r"\\temp\\", r"\\programdata\\", r"\\appdata\\", r"\\public\\")
AUTORUN_KEYS = rx(r"\\currentversion\\run(once)?\\", r"\\currentversion\\run(once)?$", r"\\winlogon\\(shell|userinit)",
                  r"\\image file execution options\\.*\\debugger", r"\\services\\[^\\]+\\imagepath",
                  r"\\currentversion\\explorer\\shell folders\\startup", r"\\environment\\userinitmprlogonscript")
CMD = rx(r"schtasks(\.exe)?\s+/create", r"\bsc(\.exe)?\s+(create|config)\s+.*binpath", r"new-scheduledtask",
         r"register-scheduledtask", r"new-service\s", r"reg(\.exe)?\s+add\s+.*\\currentversion\\run")


@register
class PersistenceMechanism(Detection):
    id = "persistence_mechanism"
    name = "New autostart: scheduled task, service, or Run key"
    mitre = ["T1053.005", "T1543.003", "T1547.001"]
    event_kinds = ("process",)
    window_sec = 0
    playbook = "playbook-persistence-mechanism"

    def run(self, events: list[ProcessEvent]) -> list[Alert]:
        out = []
        for e in events:
            if e.action == "task_created" and (RISKY_TARGET.search(e.command_line) or not e.command_line
                                                or USER_WRITABLE.search(e.command_line)):
                out.append(proc_alert(self, e, f"Scheduled task {e.target} created on {e.host}", ["T1053.005"],
                                      mechanism="scheduled_task"))
            elif e.action == "service_installed" and RISKY_TARGET.search(e.target):
                out.append(proc_alert(self, e, f"Service installed on {e.host} running {e.target[:80]}", ["T1543.003"],
                                      mechanism="service"))
            elif e.action == "registry_set" and AUTORUN_KEYS.search(e.target):
                out.append(proc_alert(self, e, f"Autostart key written on {e.host}: {e.target[-80:]}", ["T1547.001"],
                                      mechanism="registry_autorun"))
            elif e.action == "start" and CMD.search(e.command_line):
                tech = "T1053.005" if "task" in e.command_line.lower() else \
                    "T1543.003" if "sc" in e.process_name or "service" in e.command_line.lower() else "T1547.001"
                out.append(proc_alert(self, e, f"Autostart created from the command line on {e.host}", [tech],
                                      mechanism="command_line"))
        return out
