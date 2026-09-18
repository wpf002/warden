"""Case-level models: alerts, LLM output, actions, cases.

Event types live in `warden.events` and are re-exported here so existing imports
(`from warden.models import AuthEvent`) keep working.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal, Optional

from pydantic import BaseModel, Field

from .events import (  # noqa: F401  (re-exported for convenience)
    AuthEvent,
    CloudAuditEvent,
    Event,
    FileEvent,
    IdentityChangeEvent,
    NetworkEvent,
    ProcessEvent,
    parse_event,
)


class Alert(BaseModel):
    """Output of one detection. Rule-specific facts go in `detail`; the top-level
    fields are the ones guardrails, retrieval, and the dashboard depend on."""
    id: str
    ts: datetime
    rule: str                        # detection id, e.g. "brute_force", "impossible_travel"
    title: str
    mitre: list[str] = Field(default_factory=list)   # technique ids, e.g. ["T1110.001"]
    playbook: str = ""               # knowledge base doc id

    # entities the alert is about. Guardrails bind actions to these.
    source_ip: str = ""
    related_ips: list[str] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)
    geo: str = ""
    asset_tier: str = "unknown"

    first_seen: datetime
    last_seen: datetime
    window_sec: int = 0

    # kept top-level because the brute-force family and the dashboard read them directly
    failed_attempts: int = 0
    success_after_failures: bool = False

    detail: dict = Field(default_factory=dict)
    evidence: list[dict] = Field(default_factory=list)
    # set on incidents built by correlate.py: the alerts this one merges
    members: list["Alert"] = Field(default_factory=list)

    @property
    def is_incident(self) -> bool:
        return bool(self.members)

    def rules(self) -> list[str]:
        return [m.rule for m in self.members] if self.members else [self.rule]

    def playbooks(self) -> list[str]:
        return [m.playbook for m in self.members if m.playbook] if self.members else ([self.playbook] if self.playbook else [])

    def all_ips(self) -> set[str]:
        return {ip for ip in [self.source_ip, *self.related_ips] if ip}


class RecommendedAction(BaseModel):
    action: Literal["block_ip", "lock_user", "isolate_host", "disable_access_key", "create_ticket", "notify",
                    "generate_report", "no_action"]
    target: str = ""
    reason: str = ""


class Analysis(BaseModel):
    """Structured LLM output. Schema is the contract; guardrails validate it."""
    explanation: str
    mitre_attack: str = Field(description="Technique id and name, e.g. T1110.001 Brute Force: Password Guessing")
    risk_score: int = Field(ge=0, le=100)
    severity: Literal["low", "medium", "high", "critical"]
    false_positive_likelihood: Literal["low", "medium", "high"]
    recommended_actions: list[RecommendedAction]
    citations: list[str] = Field(default_factory=list, description="Knowledge base doc ids used")


class ActionResult(BaseModel):
    action: str
    target: str
    status: Literal["executed", "pending_approval", "denied", "failed", "rolled_back"]
    detail: str = ""
    connector: str = ""
    dry_run: bool = False
    receipt: dict = Field(default_factory=dict)
    ts: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Case(BaseModel):
    """One alert's full lifecycle. This is what the dashboard shows."""
    alert: Alert
    retrieved_docs: list[dict] = Field(default_factory=list)
    analysis: Optional[Analysis] = None
    guardrail_log: list[str] = Field(default_factory=list)
    actions: list[ActionResult] = Field(default_factory=list)
    analyst_verdict: Optional[Literal["true_positive", "false_positive"]] = None
    analyst_note: str = ""
    analyst_reason: str = ""          # structured FP reason, see stats.FP_REASONS
    suppressed_by: Optional[int] = None   # exclusion id when an analyst rule muted this case
    status: Literal["open", "awaiting_approval", "closed"] = "open"
    incident_id: Optional[str] = None
    prompt_version: str = ""
    kb_snapshot: str = ""
    verification: list[str] = Field(default_factory=list)   # problems found checking the analysis
    spans: list[dict] = Field(default_factory=list)          # timed pipeline stages for this case (trace)
    model: str = ""
