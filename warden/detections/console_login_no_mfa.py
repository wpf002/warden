"""T1078.004 Valid Accounts: Cloud Accounts. An IAM user or the root account signing in
to the AWS console without MFA. Federated (SSO) sign-ins carry MFA at the IdP and are
excluded."""
from __future__ import annotations

from ..events import CloudAuditEvent
from ..models import Alert
from . import Detection, register
from ._cloud import cloud_alert


@register
class ConsoleLoginNoMfa(Detection):
    id = "console_login_no_mfa"
    name = "Cloud console login without MFA"
    mitre = ["T1078.004"]
    event_kinds = ("cloud",)
    window_sec = 0
    playbook = "playbook-console-login-no-mfa"

    def run(self, events: list[CloudAuditEvent]) -> list[Alert]:
        out = []
        for e in events:
            if e.api_call != "ConsoleLogin" or e.outcome == "failure":
                continue
            raw = e.raw or {}
            kind = (raw.get("userIdentity") or {}).get("type", "")
            if (raw.get("responseElements") or {}).get("ConsoleLogin") != "Success" or kind not in ("IAMUser", "Root"):
                continue
            if (raw.get("additionalEventData") or {}).get("MFAUsed") == "Yes":
                continue
            out.append(cloud_alert(self, e, f"{'Root' if kind == 'Root' else e.user} signed in to the console without MFA "
                                   f"from {e.source_ip}", identity_type=kind))
        return out
