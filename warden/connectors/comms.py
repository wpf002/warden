"""Notification and ticketing.

slack       notify: incoming webhook (WARDEN_SLACK_WEBHOOK). No rollback: a message is a message.
pagerduty   notify: Events API v2 trigger (WARDEN_PD_ROUTING_KEY). Rollback resolves the incident.
smtp        notify: email via WARDEN_SMTP_HOST/PORT, WARDEN_SMTP_FROM, WARDEN_SMTP_TO (+ optional USER/PASSWORD).
jira        create_ticket: WARDEN_JIRA_BASE, WARDEN_JIRA_EMAIL, WARDEN_JIRA_TOKEN, WARDEN_JIRA_PROJECT
servicenow  create_ticket: WARDEN_SNOW_BASE, WARDEN_SNOW_USER, WARDEN_SNOW_PASSWORD

Notifications and tickets are low-impact and always allowed; none of them needs a
rollback to be auto-executed. PagerDuty offers one anyway.
"""
from __future__ import annotations

import os
import smtplib
from email.message import EmailMessage

from . import Connector, Receipt, register
from ._http import check, client


def _summary(alert) -> str:
    return f"[Warden] {alert.title}"[:1000]


def _body(alert) -> str:
    return (f"{alert.title}\n\ncase {alert.id}  rule {alert.rule}  mitre {', '.join(alert.mitre)}\n"
            f"users {', '.join(alert.users[:10])}  hosts {', '.join(alert.hosts[:10])}  ips {', '.join(sorted(alert.all_ips())[:10])}\n"
            f"{alert.first_seen:%Y-%m-%d %H:%M:%S} to {alert.last_seen:%H:%M:%S} UTC")


@register
class Slack(Connector):
    name = "slack"
    actions = ("notify",)

    def __init__(self, dry_run=None, webhook=None, transport=None):
        super().__init__(dry_run)
        self.webhook = webhook or os.environ.get("WARDEN_SLACK_WEBHOOK", "")
        self.transport = transport

    def execute(self, action, target, alert) -> Receipt:
        if self.dry_run:
            return self._dry(action, target, f"post to Slack: {_summary(alert)}")
        check(client("", transport=self.transport).post(self.webhook, json={"text": f"*{_summary(alert)}*\n```{_body(alert)}```"}),
              "slack")
        return Receipt(self.name, action, target, True, "posted to Slack")


@register
class PagerDuty(Connector):
    name = "pagerduty"
    actions = ("notify",)
    supports_rollback = True
    URL = "https://events.pagerduty.com/v2/enqueue"

    def __init__(self, dry_run=None, routing_key=None, transport=None):
        super().__init__(dry_run)
        self.key = routing_key or os.environ.get("WARDEN_PD_ROUTING_KEY", "")
        self.http = client("", transport=transport)

    def execute(self, action, target, alert) -> Receipt:
        dedup = f"warden-{alert.id}"
        if self.dry_run:
            return self._dry(action, target, f"trigger PagerDuty incident {dedup}", {"dedup_key": dedup})
        sev = "critical" if alert.asset_tier == "crown_jewel" else "error"
        check(self.http.post(self.URL, json={"routing_key": self.key, "event_action": "trigger", "dedup_key": dedup,
                                             "payload": {"summary": _summary(alert), "source": "warden", "severity": sev,
                                                         "custom_details": {"body": _body(alert)}}}), "pagerduty")
        return Receipt(self.name, action, target, True, f"PagerDuty incident {dedup} triggered", undo={"dedup_key": dedup})

    def rollback(self, receipt: Receipt) -> Receipt:
        if receipt.dry_run:
            return Receipt(self.name, receipt.action, receipt.target, True, "[dry-run] nothing to roll back", dry_run=True)
        check(self.http.post(self.URL, json={"routing_key": self.key, "event_action": "resolve",
                                             "dedup_key": receipt.undo["dedup_key"]}), "pagerduty resolve")
        return Receipt(self.name, receipt.action, receipt.target, True, f"PagerDuty {receipt.undo['dedup_key']} resolved")


@register
class Smtp(Connector):
    name = "smtp"
    actions = ("notify",)

    def __init__(self, dry_run=None, host=None, port=None, sender=None, to=None):
        super().__init__(dry_run)
        self.host = host or os.environ.get("WARDEN_SMTP_HOST", "localhost")
        self.port = int(port or os.environ.get("WARDEN_SMTP_PORT", "25"))
        self.sender = sender or os.environ.get("WARDEN_SMTP_FROM", "warden@localhost")
        self.to = to or os.environ.get("WARDEN_SMTP_TO", "soc@localhost")

    def execute(self, action, target, alert) -> Receipt:
        if self.dry_run:
            return self._dry(action, target, f"email {self.to}: {_summary(alert)}")
        msg = EmailMessage()
        msg["Subject"], msg["From"], msg["To"] = _summary(alert), self.sender, self.to
        msg["X-Warden-Case"] = alert.id
        msg.set_content(_body(alert))
        with smtplib.SMTP(self.host, self.port, timeout=20) as s:
            if os.environ.get("WARDEN_SMTP_USER"):
                s.starttls()
                s.login(os.environ["WARDEN_SMTP_USER"], os.environ.get("WARDEN_SMTP_PASSWORD", ""))
            s.send_message(msg)
        return Receipt(self.name, action, target, True, f"emailed {self.to}")


@register
class Jira(Connector):
    name = "jira"
    actions = ("create_ticket",)

    def __init__(self, dry_run=None, base=None, email=None, token=None, project=None, transport=None):
        super().__init__(dry_run)
        self.project = project or os.environ.get("WARDEN_JIRA_PROJECT", "SEC")
        self.http = client(base or os.environ.get("WARDEN_JIRA_BASE", ""), transport=transport)
        self.auth = (email or os.environ.get("WARDEN_JIRA_EMAIL", ""), token or os.environ.get("WARDEN_JIRA_TOKEN", ""))

    def execute(self, action, target, alert) -> Receipt:
        if self.dry_run:
            return self._dry(action, target, f"open {self.project} issue: {_summary(alert)}")
        doc = {"type": "doc", "version": 1, "content": [
            {"type": "paragraph", "content": [{"type": "text", "text": line}]} for line in _body(alert).splitlines() if line]}
        r = check(self.http.post("/rest/api/3/issue", auth=self.auth, json={"fields": {
            "project": {"key": self.project}, "summary": _summary(alert)[:255], "issuetype": {"name": "Task"},
            "labels": ["warden", alert.rule], "description": doc}}), "jira").json()
        return Receipt(self.name, action, target, True, f"Jira {r.get('key')} created", undo={"key": r.get("key")})


@register
class ServiceNow(Connector):
    name = "servicenow"
    actions = ("create_ticket",)

    def __init__(self, dry_run=None, base=None, user=None, password=None, transport=None):
        super().__init__(dry_run)
        self.http = client(base or os.environ.get("WARDEN_SNOW_BASE", ""), transport=transport)
        self.auth = (user or os.environ.get("WARDEN_SNOW_USER", ""), password or os.environ.get("WARDEN_SNOW_PASSWORD", ""))

    def execute(self, action, target, alert) -> Receipt:
        if self.dry_run:
            return self._dry(action, target, f"open ServiceNow incident: {_summary(alert)}")
        urgency = "1" if alert.asset_tier == "crown_jewel" else "2"
        r = check(self.http.post("/api/now/table/incident", auth=self.auth, json={
            "short_description": _summary(alert)[:160], "description": _body(alert), "urgency": urgency,
            "category": "security"}), "servicenow").json()
        num = (r.get("result") or {}).get("number")
        return Receipt(self.name, action, target, True, f"ServiceNow {num} created", undo={"number": num})
