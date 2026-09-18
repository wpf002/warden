"""Dashboard and API authentication.

WARDEN_AUTH selects the mode:
    none   local development only; every request is "local-dev" (refused unless bound to localhost)
    basic  HTTP basic auth against WARDEN_USERS = "name:pbkdf2hash:role,..."  (warden hash-password)
    proxy  OIDC handled by a reverse proxy (oauth2-proxy, Pomerium, ALB OIDC). Warden trusts the
           identity header only from WARDEN_TRUSTED_PROXIES.

Roles: `viewer` reads, `analyst` also approves/denies actions and records verdicts,
`admin` also reviews detection proposals and changes KB content.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import os
import secrets
from dataclasses import dataclass

from fastapi import HTTPException, Request

from .config import settings

ROLES = {"viewer": 0, "analyst": 1, "admin": 2}


@dataclass(frozen=True)
class User:
    name: str
    role: str = "analyst"
    tenant: str = "default"

    def can(self, role: str) -> bool:
        return ROLES.get(self.role, -1) >= ROLES[role]


def hash_password(pw: str, iterations: int = 390_000) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(pw: str, stored: str) -> bool:
    try:
        algo, it, salt, dk = stored.split("$")
    except ValueError:
        return False
    if algo != "pbkdf2_sha256":
        return False
    got = hashlib.pbkdf2_hmac("sha256", pw.encode(), base64.b64decode(salt), int(it))
    return hmac.compare_digest(got, base64.b64decode(dk))


def _users() -> dict[str, tuple[str, str, str]]:
    """name -> (hash, role, tenant). Entries: name:hash:role[:tenant], comma separated."""
    out = {}
    for entry in filter(None, (x.strip() for x in settings.users.split(","))):
        parts = entry.split(":")
        name, pw_hash = parts[0], parts[1]
        role = parts[2] if len(parts) > 2 else "analyst"
        tenant = parts[3] if len(parts) > 3 else settings.tenant
        out[name] = (pw_hash, role, tenant)
    return out


def _trusted(host: str | None) -> bool:
    if not host:
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    for net in filter(None, (n.strip() for n in settings.trusted_proxies.split(","))):
        if ip in ipaddress.ip_network(net, strict=False):
            return True
    return False


def _unauthorized(detail: str = "authentication required") -> HTTPException:
    return HTTPException(401, detail, headers={"WWW-Authenticate": 'Basic realm="warden"'})


def current_user(request: Request) -> User:
    mode = settings.auth_mode
    if mode == "none":
        host = request.client.host if request.client else ""
        if host not in ("127.0.0.1", "::1", "localhost", "testclient") and os.environ.get("WARDEN_ALLOW_NOAUTH", "").lower() not in ("1", "true", "yes"):
            raise HTTPException(403, "WARDEN_AUTH=none only serves localhost")
        return User("local-dev", "admin", settings.tenant)
    if mode == "basic":
        h = request.headers.get("authorization", "")
        if not h.lower().startswith("basic "):
            raise _unauthorized()
        try:
            name, _, pw = base64.b64decode(h[6:]).decode().partition(":")
        except Exception:  # noqa: BLE001
            raise _unauthorized("malformed credentials") from None
        rec = _users().get(name)
        if not rec or not verify_password(pw, rec[0]):
            raise _unauthorized("bad credentials")
        return User(name, rec[1], rec[2])
    if mode == "proxy":
        if not _trusted(request.client.host if request.client else None):
            raise HTTPException(403, "identity header not accepted from this address")
        name = request.headers.get(settings.proxy_user_header) or request.headers.get("x-forwarded-email")
        if not name:
            raise _unauthorized("proxy did not supply an identity")
        groups = {g.strip() for g in (request.headers.get(settings.proxy_groups_header) or "").split(",")}
        role = "admin" if settings.admin_group in groups else "analyst" if settings.analyst_group in groups \
            else settings.proxy_default_role
        return User(name, role, request.headers.get("x-warden-tenant") or settings.tenant)
    raise HTTPException(500, f"unknown WARDEN_AUTH mode {mode!r}")


def require(role: str):
    def dep(request: Request) -> User:
        u = current_user(request)
        if not u.can(role):
            raise HTTPException(403, f"{u.name} ({u.role}) cannot do this; needs {role}")
        return u
    return dep
