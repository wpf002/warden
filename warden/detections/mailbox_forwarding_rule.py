"""T1114.003 Email Forwarding Rule: an inbox rule or mailbox setting that forwards mail
outside the organisation. Business email compromise sets one up within minutes of
taking the mailbox."""
from __future__ import annotations

import re

from ..config import settings
from ..events import CloudAuditEvent
from ..models import Alert
from . import Detection, register
from ._cloud import cloud_alert

OPS = {"New-InboxRule", "Set-InboxRule", "UpdateInboxRules", "Set-Mailbox", "New-TransportRule"}
FWD_KEYS = {"forwardto", "forwardasattachmentto", "redirectto", "forwardingsmtpaddress", "forwardingaddress",
            "redirectmessageto", "blindcopyto"}
ADDR = re.compile(r"[\w.+-]+@([\w-]+\.[\w.-]+)")


@register
class MailboxForwardingRule(Detection):
    id = "mailbox_forwarding_rule"
    name = "Mail forwarded outside the organisation"
    mitre = ["T1114.003", "T1564.008"]
    event_kinds = ("cloud",)
    window_sec = 0
    playbook = "playbook-mailbox-forwarding"

    def run(self, events: list[CloudAuditEvent]) -> list[Alert]:
        ours = {d.strip().lower() for d in settings.email_domains.split(",") if d.strip()}
        out = []
        for e in events:
            if e.api_call not in OPS or e.outcome == "failure":
                continue
            ps = {str(p.get("Name", "")).lower(): str(p.get("Value", "")) for p in (e.raw or {}).get("Parameters") or []}
            targets = [v for k, v in ps.items() if k in FWD_KEYS and v]
            external = [m.group(0) for v in targets for m in ADDR.finditer(v) if m.group(1).lower() not in ours]
            deletes = ps.get("deletemessage", "").lower() == "true" or "movetofolder" in ps
            if external:
                out.append(cloud_alert(self, e, f"{e.user} forwards mail to {', '.join(external[:3])}"
                                       + (" and hides the originals" if deletes else ""),
                                       forward_to=external, rule_name=ps.get("name", ""), hides_mail=deletes))
        return out
