"""T1535 Unused/Unsupported Cloud Regions: compute launched where the organisation does
not operate. Crypto-miners and staging infrastructure hide in regions nobody watches."""
from __future__ import annotations

from ..config import settings
from ..events import CloudAuditEvent
from ..models import Alert
from . import Detection, register
from ._cloud import cloud_alert

LAUNCH = {"RunInstances", "CreateFunction20150331", "CreateFunction", "CreateCluster", "CreateNodegroup",
          "RequestSpotInstances", "RequestSpotFleet", "CreateAutoScalingGroup", "StartInstances"}


@register
class UnusualRegion(Detection):
    id = "unusual_region"
    name = "Compute launched in an unused region"
    mitre = ["T1535"]
    event_kinds = ("cloud",)
    window_sec = 0
    playbook = "playbook-unusual-region"
    needs_history = True

    def run(self, events: list[CloudAuditEvent]) -> list[Alert]:
        allowed = {r.strip() for r in settings.aws_regions.split(",") if r.strip()}
        allowed |= {e.region for e in self.prior if e.kind == "cloud" and getattr(e, "api_call", "") in LAUNCH}
        seen, out = set(), []
        for e in events:
            if e.api_call in LAUNCH and e.outcome != "failure" and e.region and e.region not in allowed \
                    and (e.region, e.user) not in seen:
                seen.add((e.region, e.user))
                out.append(cloud_alert(self, e, f"{e.api_call} in unused region {e.region} by {e.user}",
                                       allowed_regions=sorted(allowed)))
        return out
