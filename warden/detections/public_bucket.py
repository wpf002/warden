"""T1530 Data from Cloud Storage: a bucket opened to the internet by policy, ACL, or by
removing its public-access block."""
from __future__ import annotations

from ..events import CloudAuditEvent
from ..models import Alert
from . import Detection, register
from ._cloud import as_list, cloud_alert, doc, params, statements

PUBLIC_GROUPS = ("http://acs.amazonaws.com/groups/global/AllUsers", "http://acs.amazonaws.com/groups/global/AuthenticatedUsers")


def _public_policy(policy: dict) -> bool:
    for s in statements(policy):
        pr = s.get("Principal")
        if s.get("Effect") == "Allow" and (pr == "*" or "*" in as_list((pr or {}).get("AWS", [])) if isinstance(pr, dict) else pr == "*"):
            if not s.get("Condition"):
                return True
    return False


@register
class PublicBucket(Detection):
    id = "public_bucket"
    name = "Storage bucket made public"
    mitre = ["T1530"]
    event_kinds = ("cloud",)
    window_sec = 0
    playbook = "playbook-public-bucket"

    def run(self, events: list[CloudAuditEvent]) -> list[Alert]:
        out = []
        for e in events:
            if e.outcome == "failure":
                continue
            p = params(e)
            b = p.get("bucketName", e.resource)
            if e.api_call == "PutBucketPolicy" and _public_policy(doc(p.get("bucketPolicy"))):
                out.append(cloud_alert(self, e, f"Bucket {b} policy allows anyone, set by {e.user}", how="policy"))
            elif e.api_call in ("PutBucketAcl", "PutObjectAcl") and any(g in str(p) for g in PUBLIC_GROUPS + ("public-read",)):
                out.append(cloud_alert(self, e, f"Bucket {b} ACL grants public access, set by {e.user}", how="acl"))
            elif e.api_call == "DeleteBucketPublicAccessBlock" or (
                    e.api_call == "PutBucketPublicAccessBlock" and "false" in str(p).lower()):
                out.append(cloud_alert(self, e, f"Public access block removed from {b} by {e.user}", how="access_block"))
        return out
