"""Identity provider lockouts.

okta   lock_user: suspend the user and clear their sessions. Rollback: unsuspend.
       WARDEN_OKTA_ORG (https://acme.okta.com), WARDEN_OKTA_TOKEN (API token, SSWS)
entra  lock_user: accountEnabled=false and revoke sign-in sessions. Rollback: re-enable.
       WARDEN_ENTRA_TENANT, WARDEN_ENTRA_CLIENT_ID, WARDEN_ENTRA_CLIENT_SECRET
       (app registration with User.EnableDisableAccount.All + User.RevokeSessions.All)
"""
from __future__ import annotations

import os
from urllib.parse import quote

from . import Connector, Receipt, register
from ._http import check, client


@register
class Okta(Connector):
    name = "okta"
    actions = ("lock_user",)
    supports_rollback = True

    def __init__(self, dry_run=None, org: str | None = None, token: str | None = None, transport=None):
        super().__init__(dry_run)
        org = org or os.environ.get("WARDEN_OKTA_ORG", "")
        token = token or os.environ.get("WARDEN_OKTA_TOKEN", "")
        self.http = client(org, {"Authorization": f"SSWS {token}", "Accept": "application/json"}, transport)

    def _uid(self, login: str) -> str:
        return check(self.http.get(f"/api/v1/users/{quote(login, safe='')}"), "okta user lookup").json()["id"]

    def execute(self, action: str, target: str, alert) -> Receipt:
        uid = self._uid(target)
        if self.dry_run:
            return self._dry(action, target, f"suspend Okta user {uid} and clear sessions", {"uid": uid})
        check(self.http.post(f"/api/v1/users/{uid}/lifecycle/suspend"), "okta suspend")
        check(self.http.delete(f"/api/v1/users/{uid}/sessions"), "okta clear sessions")
        return Receipt(self.name, action, target, True, f"Okta user {uid} suspended, sessions cleared", undo={"uid": uid})

    def rollback(self, receipt: Receipt) -> Receipt:
        if receipt.dry_run:
            return Receipt(self.name, receipt.action, receipt.target, True, "[dry-run] nothing to roll back", dry_run=True)
        check(self.http.post(f"/api/v1/users/{receipt.undo['uid']}/lifecycle/unsuspend"), "okta unsuspend")
        return Receipt(self.name, receipt.action, receipt.target, True, f"Okta user {receipt.undo['uid']} unsuspended")


class _MsGraphBase(Connector):
    scope = ""
    base = ""

    def __init__(self, dry_run=None, tenant=None, client_id=None, secret=None, transport=None, token_transport=None):
        super().__init__(dry_run)
        self.tenant = tenant or os.environ.get("WARDEN_ENTRA_TENANT", "")
        self.client_id = client_id or os.environ.get("WARDEN_ENTRA_CLIENT_ID", "")
        self.secret = secret or os.environ.get("WARDEN_ENTRA_CLIENT_SECRET", "")
        self.transport, self.token_transport = transport, token_transport
        self._http = None

    @property
    def http(self):
        if self._http is None:
            auth = client("https://login.microsoftonline.com", transport=self.token_transport)
            tok = check(auth.post(f"/{self.tenant}/oauth2/v2.0/token", data={
                "grant_type": "client_credentials", "client_id": self.client_id, "client_secret": self.secret,
                "scope": self.scope}), "token").json()["access_token"]
            self._http = client(self.base, {"Authorization": f"Bearer {tok}"}, self.transport)
        return self._http


@register
class Entra(_MsGraphBase):
    name = "entra"
    actions = ("lock_user",)
    supports_rollback = True
    scope = "https://graph.microsoft.com/.default"
    base = "https://graph.microsoft.com"

    def execute(self, action: str, target: str, alert) -> Receipt:
        if self.dry_run:
            return self._dry(action, target, f"disable Entra user {target} and revoke sign-in sessions", {"upn": target})
        u = quote(target, safe="@")
        check(self.http.patch(f"/v1.0/users/{u}", json={"accountEnabled": False}), "entra disable")
        check(self.http.post(f"/v1.0/users/{u}/revokeSignInSessions"), "entra revoke")
        return Receipt(self.name, action, target, True, f"Entra user {target} disabled, sessions revoked", undo={"upn": target})

    def rollback(self, receipt: Receipt) -> Receipt:
        if receipt.dry_run:
            return Receipt(self.name, receipt.action, receipt.target, True, "[dry-run] nothing to roll back", dry_run=True)
        check(self.http.patch(f"/v1.0/users/{quote(receipt.undo['upn'], safe='@')}", json={"accountEnabled": True}),
              "entra enable")
        return Receipt(self.name, receipt.action, receipt.target, True, f"Entra user {receipt.target} re-enabled")
