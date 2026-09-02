"""Typed event hierarchy. Every source normalizes into one of these.

Field names track the Elastic Common Schema where a sensible ECS field exists, so a
real SIEM export needs a rename map rather than a rewrite:

    ts -> @timestamp        host -> host.name        user -> user.name
    source -> event.dataset source_ip -> source.ip   geo -> source.geo.country_iso_code

`kind` is the discriminator. It is a real field, not a ClassVar, so events round-trip
through JSON without the loader having to guess the subclass.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

# Event kinds a detection can declare an appetite for.
KINDS = ("auth", "process", "network", "file", "identity", "cloud")


class Event(BaseModel):
    kind: str = "event"
    ts: datetime
    source: str = ""                 # "splunk", "okta", "sshd", "cloudtrail"
    host: str = ""
    user: str = ""
    source_ip: str = ""
    geo: str = ""                    # country code, or "internal"
    asset_tier: str = "unknown"      # crown_jewel | standard | unknown
    entity_ids: dict[str, str] = Field(default_factory=dict)  # session, device, process guid
    raw: dict = Field(default_factory=dict)

    def _discriminator(self) -> str:
        """Subclass-specific tail of the dedupe key."""
        return ""

    def dedupe_key(self) -> str:
        return f"{self.ts.isoformat()}|{self.source}|{self._discriminator()}|{self.user}|{self.source_ip}"


class AuthEvent(Event):
    kind: Literal["auth"] = "auth"
    event_type: Literal[
        "login_success", "login_failure", "lockout", "logout",
        "mfa_challenge", "mfa_denied", "mfa_timeout", "mfa_success",
    ]
    logon_type: str = ""             # interactive | remote_interactive | network | service | ""
    user_agent: str = ""
    mfa_factor: str = ""             # push | totp | sms | webauthn
    outcome_reason: str = ""         # "bad_password", "user_rejected", "timeout"

    def _discriminator(self) -> str:
        return self.event_type


class ProcessEvent(Event):
    kind: Literal["process"] = "process"
    process_name: str = ""
    command_line: str = ""
    parent_name: str = ""
    pid: int = 0
    ppid: int = 0
    sha256: str = ""

    def _discriminator(self) -> str:
        return f"proc:{self.process_name}:{self.pid}"


class NetworkEvent(Event):
    kind: Literal["network"] = "network"
    dest_ip: str = ""
    dest_port: int = 0
    protocol: str = ""
    domain: str = ""
    bytes_out: int = 0
    bytes_in: int = 0
    action: str = ""                 # allowed | blocked

    def _discriminator(self) -> str:
        return f"net:{self.dest_ip}:{self.dest_port}:{self.domain}"


class FileEvent(Event):
    kind: Literal["file"] = "file"
    path: str = ""
    action: Literal["create", "modify", "delete", "rename", "read"] = "modify"
    sha256: str = ""

    def _discriminator(self) -> str:
        return f"file:{self.action}:{self.path}"


class IdentityChangeEvent(Event):
    """Directory / IdP mutations. `user` is the actor, `target_user` the object."""
    kind: Literal["identity"] = "identity"
    change_type: Literal[
        "account_created", "account_enabled", "account_disabled", "account_deleted",
        "group_add", "group_remove", "password_reset", "mfa_enrolled", "mfa_removed",
    ]
    target_user: str = ""
    group: str = ""

    def _discriminator(self) -> str:
        return f"idc:{self.change_type}:{self.target_user}:{self.group}"


class CloudAuditEvent(Event):
    kind: Literal["cloud"] = "cloud"
    provider: str = ""               # aws | azure | gcp
    api_call: str = ""
    resource: str = ""
    region: str = ""
    account_id: str = ""
    outcome: str = ""                # success | failure

    def _discriminator(self) -> str:
        return f"cloud:{self.api_call}:{self.resource}"


EVENT_CLASSES: dict[str, type[Event]] = {
    "auth": AuthEvent,
    "process": ProcessEvent,
    "network": NetworkEvent,
    "file": FileEvent,
    "identity": IdentityChangeEvent,
    "cloud": CloudAuditEvent,
}


def parse_event(rec: dict) -> Event:
    """Build the right subclass from a dict. Defaults to auth for v0.1 log shapes."""
    cls = EVENT_CLASSES.get(rec.get("kind", "auth"), AuthEvent)
    return cls.model_validate(rec)
