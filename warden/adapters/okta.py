"""Okta System Log (GET /api/v1/logs, or a JSON/NDJSON export of it).

Push-MFA outcomes are the reason this adapter matters: they are what `mfa_fatigue`
consumes, and Okta is where push bombing actually happens.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterator

from ..events import AuthEvent, Event, IdentityChangeEvent
from ._util import clean_ip, country_code, dig, iter_json_records, parse_ts

NAME = "okta"

SESSION = {"user.session.start", "user.authentication.sso", "user.authentication.authenticate",
           "user.authentication.verify", "policy.evaluate_sign_on"}
MFA = {"user.authentication.auth_via_mfa", "system.push.send_factor_verify_push",
       "user.mfa.okta_verify.deny_push", "user.mfa.okta_verify"}
IDENTITY = {
    "user.lifecycle.create": "account_created", "user.lifecycle.activate": "account_enabled",
    "user.lifecycle.reactivate": "account_enabled", "user.lifecycle.suspend": "account_disabled",
    "user.lifecycle.deactivate": "account_disabled", "user.lifecycle.delete.initiated": "account_deleted",
    "group.user_membership.add": "group_add", "group.user_membership.remove": "group_remove",
    "user.account.privilege.grant": "group_add", "user.account.reset_password": "password_reset",
    "user.mfa.factor.activate": "mfa_enrolled", "user.mfa.factor.update": "mfa_enrolled",
    "user.mfa.factor.deactivate": "mfa_removed", "user.mfa.factor.reset_all": "mfa_removed",
}


def sniff(head: str, path: Path) -> bool:
    return '"eventType"' in head and ('"published"' in head or '"actor"' in head)


def _target(rec: dict, kind: str) -> dict:
    return next((t for t in rec.get("target") or [] if t.get("type") == kind), {})


def to_event(rec: dict) -> Event | None:
    et = rec.get("eventType", "")
    result = (dig(rec, "outcome.result") or "").upper()
    reason = dig(rec, "outcome.reason") or ""
    actor = dig(rec, "actor.alternateId") or dig(rec, "actor.displayName") or ""
    geo = dig(rec, "client.geographicalContext") or {}
    common = dict(
        ts=parse_ts(rec["published"]), source="okta",
        user=actor, source_ip=clean_ip(dig(rec, "client.ipAddress")),
        host=dig(rec, "client.device") or "okta",
        geo=country_code(geo.get("country")),
        geo_lat=dig(geo, "geolocation.lat"), geo_lon=dig(geo, "geolocation.lon"),
        raw=rec,
    )
    ua = dig(rec, "client.userAgent.rawUserAgent") or ""
    sid = dig(rec, "authenticationContext.externalSessionId") or ""

    if et in SESSION:
        if result == "SUCCESS" and et in ("user.session.start", "user.authentication.sso"):
            return AuthEvent(**common, event_type="login_success", user_agent=ua, session_id=sid, logon_type="network")
        if result in ("FAILURE", "DENY"):
            locked = "LOCKED" in reason.upper()
            return AuthEvent(**common, event_type="lockout" if locked else "login_failure",
                             user_agent=ua, session_id=sid, outcome_reason=reason)
        return None
    if et == "user.account.lock":
        return AuthEvent(**common, event_type="lockout", user_agent=ua, outcome_reason=reason)
    if et in MFA:
        factor = "push" if "push" in et or "push" in reason.lower() or "okta_verify" in et else \
            (dig(rec, "debugContext.debugData.factor") or "").lower()
        if et == "system.push.send_factor_verify_push":
            etype = "mfa_challenge"
        elif et == "user.mfa.okta_verify.deny_push" or "reject" in reason.lower() or "denied" in reason.lower():
            etype = "mfa_denied"
        elif "timeout" in reason.lower() or "timed out" in reason.lower():
            etype = "mfa_timeout"
        elif result == "SUCCESS":
            etype = "mfa_success"
        else:
            etype = "mfa_denied"
        return AuthEvent(**common, event_type=etype, mfa_factor=factor or "push", user_agent=ua,
                         session_id=sid, outcome_reason=reason)
    if et in IDENTITY and result in ("SUCCESS", ""):
        user_t = _target(rec, "User")
        group_t = _target(rec, "UserGroup") or _target(rec, "Group") or _target(rec, "ROLE")
        return IdentityChangeEvent(**common, change_type=IDENTITY[et],
                                   target_user=user_t.get("alternateId") or actor,
                                   group=group_t.get("displayName", "") or dig(rec, "debugContext.debugData.privilegeGranted", ""))
    return None


def parse(path: Path) -> Iterator[Event]:
    for rec in iter_json_records(path):
        ev = to_event(rec)
        if ev is not None:
            yield ev
