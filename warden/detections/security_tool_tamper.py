"""T1562.001 Impair Defenses: Disable or Modify Tools. Defender switched off or given
exclusions, AMSI bypassed in-process, the host firewall turned off (T1562.004)."""
from __future__ import annotations

from ..events import ProcessEvent
from ..models import Alert
from . import Detection, register
from ._endpoint import proc_alert, rx

CMD = [
    (rx(r"set-mppreference.*-disable(realtimemonitoring|behaviormonitoring|ioavprotection|scriptscanning|intrusionprevention)\s+\$?(true|1)",
        r"add-mppreference.*-exclusion(path|process|extension)"), "T1562.001", "Defender disabled or excluded"),
    (rx(r"\bsc(\.exe)?\s+(stop|config|delete)\s+(windefend|sense|wdnissvc|wdfilter|mpssvc)", r"stop-service.*windefend"),
     "T1562.001", "security service stopped"),
    (rx(r"amsiutils", r"amsiinitfailed", r"amsiscanbuffer", r"amsicontext"), "T1562.001", "AMSI bypass"),
    (rx(r"netsh\s+advfirewall\s+set\s+\w+\s+state\s+off", r"netsh\s+firewall\s+set\s+opmode\s+disable",
        r"set-netfirewallprofile.*-enabled\s+(false|0)"), "T1562.004", "host firewall disabled"),
    (rx(r"bcdedit.*(nointegritychecks|testsigning)\s+on"), "T1562.001", "driver signing enforcement off"),
]
REG = rx(r"\\windows defender\\(real-time protection\\)?disable", r"\\windows defender\\exclusions\\",
         r"disableantispyware", r"disablerealtimemonitoring")


@register
class SecurityToolTamper(Detection):
    id = "security_tool_tamper"
    name = "Security tooling disabled or bypassed"
    mitre = ["T1562.001", "T1562.004"]
    event_kinds = ("process",)
    window_sec = 0
    playbook = "playbook-security-tool-tamper"

    def run(self, events: list[ProcessEvent]) -> list[Alert]:
        out = []
        for e in events:
            if e.action == "av_tamper":
                out.append(proc_alert(self, e, f"Defender configuration changed on {e.host}: {e.target}", ["T1562.001"]))
            elif e.action == "registry_set" and REG.search(e.target):
                out.append(proc_alert(self, e, f"Defender policy key written on {e.host}", ["T1562.001"]))
            elif e.action in ("start", "script_block"):
                for pat, tech, what in CMD:
                    if pat.search(e.command_line):
                        out.append(proc_alert(self, e, f"{what} on {e.host}", [tech], method=what))
                        break
        return out
