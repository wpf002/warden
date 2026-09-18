"""Action connectors. Stage 7. Everything here is a mock that records what it would do.
Replace the body of each function with the real API call (Palo Alto, Okta, Jira, Slack)."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .config import settings
from .models import ActionResult, Alert, RecommendedAction

def _record(alert_id: str, res: ActionResult) -> None:
    log = settings.state_dir / "actions.jsonl"
    log.parent.mkdir(parents=True, exist_ok=True)
    with open(log, "a") as f:
        f.write(json.dumps({"alert": alert_id, **res.model_dump(mode="json")}) + "\n")


def firewall_block_ip(ip: str) -> str:
    return f"[mock firewall] deny rule added for {ip} (ttl 24h)"


def iam_lock_user(user: str) -> str:
    return f"[mock IAM] account {user} locked, sessions revoked, reset required"


def ticket_create(alert: Alert) -> str:
    return f"[mock ITSM] ticket SEC-{alert.id[-4:]} created: {alert.title}"


def notify(target: str, alert: Alert) -> str:
    return f"[mock notify] {target} paged: {alert.title}"


def generate_report(alert: Alert) -> str:
    path = settings.state_dir / f"report-{alert.id}.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"# {alert.title}\n\n{alert.model_dump_json(indent=2)}\n")
    return f"report written to {path}"


def execute(alert: Alert, action: RecommendedAction) -> ActionResult:
    try:
        if action.action == "block_ip":
            detail = firewall_block_ip(action.target)
        elif action.action == "lock_user":
            detail = iam_lock_user(action.target)
        elif action.action == "create_ticket":
            detail = ticket_create(alert)
        elif action.action == "notify":
            detail = notify(action.target or "soc", alert)
        elif action.action == "generate_report":
            detail = generate_report(alert)
        else:
            raise ValueError(f"unknown action {action.action}")
        res = ActionResult(action=action.action, target=action.target, status="executed", detail=detail,
                           ts=datetime.now(timezone.utc))
    except Exception as e:  # noqa: BLE001
        res = ActionResult(action=action.action, target=action.target, status="failed", detail=str(e),
                           ts=datetime.now(timezone.utc))
    _record(alert.id, res)
    return res
