"""An EDR's own detection (CrowdStrike Falcon today) raised as a Warden alert, so it is
correlated with identity and network activity and goes through the same analysis and
guardrails. Low and informational verdicts stay in the EDR console."""
from __future__ import annotations

from ..events import ProcessEvent
from ..models import Alert
from . import Detection, register
from ._endpoint import proc_alert

# Falcon reports a tactic name, not a technique id: map each to its most common technique
TACTIC = {"credential access": "T1003", "execution": "T1059", "persistence": "T1547",
          "privilege escalation": "T1068", "defense evasion": "T1027", "lateral movement": "T1021",
          "command and control": "T1071", "exfiltration": "T1041", "impact": "T1486",
          "discovery": "T1082", "initial access": "T1566", "collection": "T1005"}
RAISE = {"medium", "high", "critical"}


@register
class EdrAlert(Detection):
    id = "edr_alert"
    name = "EDR detection"
    mitre = ["T1204"]
    event_kinds = ("process",)
    window_sec = 0
    playbook = "playbook-edr-alert"

    def run(self, events: list[ProcessEvent]) -> list[Alert]:
        out = []
        for e in events:
            fd = e.raw.get("falcon_detection") if isinstance(e.raw, dict) else None
            if not fd or str(fd.get("SeverityName", "")).lower() not in RAISE:
                continue
            what = fd.get("DetectName") or fd.get("Name") or "detection"
            tech = TACTIC.get(str(fd.get("Tactic", "")).lower(), "T1204")
            out.append(proc_alert(self, e, f"Falcon {fd.get('SeverityName', '').lower()} {what} on {e.host}: {e.process_name}",
                                  [tech], vendor="crowdstrike", severity=fd.get("SeverityName", ""),
                                  tactic=fd.get("Tactic", ""), technique=fd.get("Technique", ""),
                                  description=fd.get("DetectDescription") or fd.get("Description", ""),
                                  sha256=e.sha256))
        return out
