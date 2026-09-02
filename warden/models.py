from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field


class AuthEvent(BaseModel):
    """Normalized auth event. Every source (SIEM, IAM, EDR) maps to this."""
    ts: datetime
    source: str                      # e.g. "splunk", "okta", "sshd"
    event_type: Literal["login_success", "login_failure", "lockout"]
    user: str
    source_ip: str
    host: str = ""
    geo: str = ""
    asset_tier: str = "unknown"      # crown_jewel | standard | unknown
    raw: dict = Field(default_factory=dict)

    def dedupe_key(self) -> str:
        return f"{self.ts.isoformat()}|{self.source}|{self.event_type}|{self.user}|{self.source_ip}"


class Alert(BaseModel):
    id: str
    ts: datetime
    rule: str                        # "brute_force" | "password_spray"
    title: str
    source_ip: str
    users: list[str]
    failed_attempts: int
    window_sec: int
    first_seen: datetime
    last_seen: datetime
    success_after_failures: bool = False
    hosts: list[str] = Field(default_factory=list)
    geo: str = ""
    asset_tier: str = "unknown"
    evidence: list[dict] = Field(default_factory=list)


class RecommendedAction(BaseModel):
    action: Literal["block_ip", "lock_user", "create_ticket", "notify", "generate_report", "no_action"]
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
    status: Literal["executed", "pending_approval", "denied", "failed"]
    detail: str = ""
    ts: datetime = Field(default_factory=datetime.utcnow)


class Case(BaseModel):
    """One alert's full lifecycle. This is what the dashboard shows."""
    alert: Alert
    retrieved_docs: list[dict] = Field(default_factory=list)
    analysis: Optional[Analysis] = None
    guardrail_log: list[str] = Field(default_factory=list)
    actions: list[ActionResult] = Field(default_factory=list)
    analyst_verdict: Optional[Literal["true_positive", "false_positive"]] = None
    analyst_note: str = ""
    status: Literal["open", "awaiting_approval", "closed"] = "open"
