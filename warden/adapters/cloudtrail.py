"""AWS CloudTrail (the `{"Records": [...]}` files S3 delivers, or an event-history export).

Every record becomes a CloudAuditEvent. ConsoleLogin additionally yields an AuthEvent so
identity detections (impossible travel, spray against the console) see AWS sign-ins.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterator

from ..events import AuthEvent, CloudAuditEvent, Event
from ._util import clean_ip, dig, iter_json_records, parse_ts

NAME = "cloudtrail"


def sniff(head: str, path: Path) -> bool:
    return '"eventSource"' in head and '"eventName"' in head and ('"awsRegion"' in head or '"Records"' in head)


def _principal(rec: dict) -> str:
    ui = rec.get("userIdentity") or {}
    return ui.get("userName") or dig(ui, "sessionContext.sessionIssuer.userName") or \
        (ui.get("arn", "").split("/")[-1] if ui.get("arn") else "") or ui.get("principalId", "")


def parse(path: Path) -> Iterator[Event]:
    for rec in iter_json_records(path):
        if "CloudTrailEvent" in rec and isinstance(rec["CloudTrailEvent"], str):   # event-history export
            import json
            rec = json.loads(rec["CloudTrailEvent"])
        ts = parse_ts(rec["eventTime"])
        ip = clean_ip(rec.get("sourceIPAddress", ""))
        if ip and not ip[0].isdigit() and ":" not in ip:
            ip = ""   # "cloudformation.amazonaws.com" and friends are services, not addresses
        user = _principal(rec)
        name = rec.get("eventName", "")
        resource = ""
        rp = rec.get("requestParameters") or {}
        for k in ("bucketName", "userName", "roleName", "policyArn", "groupName", "instanceId", "trailName", "name"):
            if isinstance(rp, dict) and rp.get(k):
                resource = str(rp[k])
                break
        yield CloudAuditEvent(
            ts=ts, source="cloudtrail", user=user, source_ip=ip, host=rec.get("eventSource", ""),
            provider="aws", api_call=name, resource=resource, region=rec.get("awsRegion", ""),
            account_id=rec.get("recipientAccountId", "") or dig(rec, "userIdentity.accountId", ""),
            outcome="failure" if rec.get("errorCode") else "success", raw=rec,
        )
        if name == "ConsoleLogin":
            ok = dig(rec, "responseElements.ConsoleLogin") == "Success"
            yield AuthEvent(
                ts=ts, source="cloudtrail", user=user, source_ip=ip, host="aws-console",
                event_type="login_success" if ok else "login_failure",
                user_agent=rec.get("userAgent", ""), logon_type="console",
                mfa_factor="mfa" if dig(rec, "additionalEventData.MFAUsed") == "Yes" else "",
                outcome_reason=rec.get("errorMessage", ""), raw=rec,
            )
