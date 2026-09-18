"""Microsoft Entra ID sign-in logs and audit logs (Graph /auditLogs/signIns and
/auditLogs/directoryAudits, or a Log Analytics JSON export of either)."""
from __future__ import annotations

from pathlib import Path
from typing import Iterator

from ..events import AuthEvent, Event, IdentityChangeEvent
from ._util import clean_ip, country_code, dig, iter_json_records, parse_ts

NAME = "entra"

LOCKOUT_CODES = {50053}
MFA_CODES = {500121, 50074, 50076, 50158}


def sniff(head: str, path: Path) -> bool:
    return ('"userPrincipalName"' in head and ('"createdDateTime"' in head or '"conditionalAccessStatus"' in head)) \
        or ('"activityDisplayName"' in head and '"targetResources"' in head)


def _signin(rec: dict) -> Event:
    code = int(dig(rec, "status.errorCode") or 0)
    reason = dig(rec, "status.failureReason") or ""
    common = dict(
        ts=parse_ts(rec["createdDateTime"]), source="entra",
        user=rec.get("userPrincipalName", ""), source_ip=clean_ip(rec.get("ipAddress")),
        host=rec.get("appDisplayName", "") or "entra",
        geo=country_code(dig(rec, "location.countryOrRegion")),
        geo_lat=dig(rec, "location.geoCoordinates.latitude"), geo_lon=dig(rec, "location.geoCoordinates.longitude"),
        user_agent=rec.get("userAgent", "") or dig(rec, "deviceDetail.browser", ""),
        device_id=dig(rec, "deviceDetail.deviceId", "") or "",
        session_id=rec.get("correlationId", ""), outcome_reason=reason, raw=rec,
    )
    logon = "noninteractive" if rec.get("isInteractive") is False else "interactive"
    if code == 0:
        return AuthEvent(**common, event_type="login_success", logon_type=logon)
    if code in LOCKOUT_CODES:
        return AuthEvent(**common, event_type="lockout", logon_type=logon)
    if code in MFA_CODES:
        detail = " ".join(str(d.get("authenticationStepResultDetail", "")) for d in rec.get("authenticationDetails") or [])
        low = (detail + " " + reason).lower()
        etype = "mfa_timeout" if "timed out" in low or "timeout" in low else \
            "mfa_denied" if ("denied" in low or "declined" in low) else "mfa_challenge"
        return AuthEvent(**common, event_type=etype, mfa_factor="push", logon_type=logon)
    return AuthEvent(**common, event_type="login_failure", logon_type=logon)


def _audit(rec: dict) -> Event | None:
    act = (rec.get("activityDisplayName") or "").lower()
    if (rec.get("result") or "success").lower() != "success":
        return None
    kinds = [("add member to role", "group_add"), ("add eligible member to role", "group_add"),
             ("add member to group", "group_add"), ("remove member from", "group_remove"),
             ("add user", "account_created"), ("delete user", "account_deleted"),
             ("disable account", "account_disabled"), ("enable account", "account_enabled"),
             ("reset user password", "password_reset"), ("reset password", "password_reset"),
             ("user registered security info", "mfa_enrolled"), ("user deleted security info", "mfa_removed")]
    change = next((c for k, c in kinds if k in act), None)
    if not change:
        return None
    targets = rec.get("targetResources") or []
    user_t = next((t for t in targets if t.get("type") == "User"), {})
    grp_t = next((t for t in targets if t.get("type") in ("Group", "Role")), {})
    if not grp_t:
        for t in targets:
            for m in t.get("modifiedProperties") or []:
                if m.get("displayName") in ("Role.DisplayName", "Group.DisplayName"):
                    grp_t = {"displayName": (m.get("newValue") or "").strip('"')}
    actor = dig(rec, "initiatedBy.user.userPrincipalName") or dig(rec, "initiatedBy.app.displayName") or ""
    return IdentityChangeEvent(
        ts=parse_ts(rec["activityDateTime"]), source="entra", host="entra",
        user=actor, source_ip=clean_ip(dig(rec, "initiatedBy.user.ipAddress")),
        change_type=change, target_user=user_t.get("userPrincipalName", ""),
        group=grp_t.get("displayName", ""), raw=rec,
    )


def parse(path: Path) -> Iterator[Event]:
    for rec in iter_json_records(path):
        if "createdDateTime" in rec and "userPrincipalName" in rec:
            yield _signin(rec)
        elif "activityDisplayName" in rec:
            ev = _audit(rec)
            if ev:
                yield ev
