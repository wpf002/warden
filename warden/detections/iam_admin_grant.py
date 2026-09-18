"""T1098.003 Additional Cloud Roles: admin rights granted in AWS IAM - AdministratorAccess
attached, a wildcard inline policy, or a user dropped into an admin group."""
from __future__ import annotations

from ..events import CloudAuditEvent
from ..models import Alert
from . import Detection, register
from ._cloud import as_list, cloud_alert, doc, params, statements

ADMIN_POLICIES = ("AdministratorAccess", "IAMFullAccess", "PowerUserAccess", "AWSOrganizationsFullAccess")


def _wildcard(policy: dict) -> bool:
    for s in statements(policy):
        if s.get("Effect") == "Allow" and "*" in as_list(s.get("Action")) and "*" in as_list(s.get("Resource", "*")):
            return True
    return False


@register
class IamAdminGrant(Detection):
    id = "iam_admin_grant"
    name = "Cloud admin privileges granted"
    mitre = ["T1098.003"]
    event_kinds = ("cloud",)
    window_sec = 0
    playbook = "playbook-iam-admin-grant"

    def run(self, events: list[CloudAuditEvent]) -> list[Alert]:
        out = []
        for e in events:
            if e.outcome == "failure":
                continue
            p = params(e)
            who = p.get("userName") or p.get("roleName") or p.get("groupName") or e.resource
            if e.api_call in ("AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy") and \
                    str(p.get("policyArn", "")).endswith(ADMIN_POLICIES):
                out.append(cloud_alert(self, e, f"{p['policyArn'].rsplit('/', 1)[-1]} attached to {who} by {e.user}",
                                       principal=who, policy=p["policyArn"]))
            elif e.api_call in ("PutUserPolicy", "PutRolePolicy", "PutGroupPolicy") and _wildcard(doc(p.get("policyDocument"))):
                out.append(cloud_alert(self, e, f"Wildcard inline policy on {who} by {e.user}", principal=who,
                                       policy=p.get("policyName")))
            elif e.api_call == "AddUserToGroup" and "admin" in str(p.get("groupName", "")).lower():
                out.append(cloud_alert(self, e, f"{p.get('userName')} added to {p.get('groupName')} by {e.user}",
                                       principal=p.get("userName"), group=p.get("groupName")))
            elif e.api_call in ("CreateLoginProfile", "UpdateLoginProfile") and p.get("userName") and p["userName"] != e.user:
                out.append(cloud_alert(self, e, f"Console password set for {p['userName']} by {e.user}", ["T1098"],
                                       principal=p["userName"]))
        return out
