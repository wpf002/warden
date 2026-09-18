"""T1685.002 Disable or Modify Cloud Logs: CloudTrail stopped or deleted, GuardDuty or
Config switched off, flow logs removed. The attacker turning off the cameras."""
from __future__ import annotations

from ..events import CloudAuditEvent
from ..models import Alert
from . import Detection, register
from ._cloud import cloud_alert, params

CALLS = {"StopLogging", "DeleteTrail", "DeleteFlowLogs", "DeleteDetector", "DisassociateFromMasterAccount",
         "StopConfigurationRecorder", "DeleteConfigurationRecorder", "DeleteDeliveryChannel", "DisableSecurityHub",
         "DeleteLogGroup", "DeleteLogStream", "PutEventSelectors", "UpdateDetector", "UpdateTrail"}


@register
class CloudLoggingDisabled(Detection):
    id = "cloud_logging_disabled"
    name = "Cloud audit logging disabled"
    mitre = ["T1685.002"]
    event_kinds = ("cloud",)
    window_sec = 0
    playbook = "playbook-cloud-logging-disabled"

    def run(self, events: list[CloudAuditEvent]) -> list[Alert]:
        out = []
        for e in events:
            if e.api_call not in CALLS or e.outcome == "failure":
                continue
            p = params(e)
            if e.api_call == "UpdateDetector" and p.get("enable") is not False:
                continue
            if e.api_call == "PutEventSelectors" and (p.get("eventSelectors") or p.get("advancedEventSelectors")):
                sel = str(p).lower()
                if "readwritetype': 'all'" in sel or "includemanagementevents': true" in sel:
                    continue
            if e.api_call == "UpdateTrail" and "false" not in str(p).lower():
                continue
            out.append(cloud_alert(self, e, f"{e.api_call} on {e.resource or 'account'} in {e.region} by {e.user or 'unknown'}"))
        return out
