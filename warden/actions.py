"""Stage 7: execute an approved action through its connector and record the receipt.

The connector for each action comes from WARDEN_CONNECTORS (see warden/connectors). The
receipt carries what rollback needs, and is stored on the case with the result."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from . import connectors
from .config import settings
from .models import ActionResult, Alert, RecommendedAction


def _record(alert_id: str, res: ActionResult) -> None:
    log = settings.state_dir / "actions.jsonl"
    log.parent.mkdir(parents=True, exist_ok=True)
    with open(log, "a") as f:
        f.write(json.dumps({"alert": alert_id, **res.model_dump(mode="json")}) + "\n")


def execute(alert: Alert, action: RecommendedAction) -> ActionResult:
    try:
        conn = connectors.for_action(action.action)
        r = conn.execute(action.action, action.target or ("soc" if action.action == "notify" else ""), alert)
        res = ActionResult(action=action.action, target=action.target, status="executed" if r.ok else "failed",
                           detail=r.detail, ts=datetime.now(timezone.utc), connector=r.connector,
                           dry_run=r.dry_run, receipt=r.as_dict())
    except Exception as e:  # noqa: BLE001 - a failed connector is a failed action, not a crashed pipeline
        res = ActionResult(action=action.action, target=action.target, status="failed", detail=f"{type(e).__name__}: {e}",
                           ts=datetime.now(timezone.utc))
    _record(alert.id, res)
    return res


def rollback(alert: Alert, res: ActionResult) -> ActionResult:
    if res.status != "executed" or not res.receipt:
        raise ValueError("only executed actions with a receipt can be rolled back")
    conn = connectors.for_action(res.action)
    receipt = connectors.Receipt(**res.receipt)
    try:
        r = conn.rollback(receipt)
        out = ActionResult(action=res.action, target=res.target, status="rolled_back" if r.ok else "failed",
                           detail=r.detail, ts=datetime.now(timezone.utc), connector=r.connector, dry_run=r.dry_run,
                           receipt=res.receipt)
    except Exception as e:  # noqa: BLE001
        out = ActionResult(action=res.action, target=res.target, status="failed", detail=f"rollback failed: {e}",
                           ts=datetime.now(timezone.utc), connector=res.connector, receipt=res.receipt)
    _record(alert.id, out)
    return out
