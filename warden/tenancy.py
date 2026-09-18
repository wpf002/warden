"""Multi-tenancy. Phase 7.

Every event, case, audit row, model call, exclusion, and baseline already carries a tenant
column; CaseStore scopes every query by it. This module adds the two things that differ per
tenant beyond data:

  * policy   data/tenants/<tenant>/policy.json overrides guardrail settings for that tenant
  * content  data/tenants/<tenant>/knowledge/*.md layers over the global knowledge base; a
             tenant document with the same name as a global one replaces it in retrieval
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from .config import settings


@dataclass(frozen=True)
class Policy:
    tenant: str
    auto_action_min_risk: int
    rule_thresholds: dict = field(default_factory=dict)
    human_approval_actions: frozenset = frozenset()
    ip_safelist: frozenset = frozenset()
    auto_actions: frozenset = frozenset()
    notify_targets: frozenset = frozenset()
    connectors: str = ""

    def threshold(self, rule: str) -> int:
        return self.rule_thresholds.get(rule, self.auto_action_min_risk)


def tenant_dir(tenant: str) -> Path:
    return settings.data_dir / "tenants" / tenant


@lru_cache(maxsize=64)
def _policy_file(tenant: str, mtime: float) -> dict:
    p = tenant_dir(tenant) / "policy.json"
    return json.loads(p.read_text()) if p.exists() else {}


def policy(tenant: str | None = None) -> Policy:
    tenant = tenant or settings.tenant
    p = tenant_dir(tenant) / "policy.json"
    o = _policy_file(tenant, p.stat().st_mtime if p.exists() else 0.0)
    return Policy(
        tenant=tenant,
        auto_action_min_risk=int(o.get("auto_action_min_risk", settings.auto_action_min_risk)),
        rule_thresholds={**settings.rule_thresholds, **o.get("rule_thresholds", {})},
        human_approval_actions=frozenset(o.get("human_approval_actions", settings.human_approval_actions)),
        ip_safelist=frozenset(o.get("ip_safelist", settings.ip_safelist)),
        auto_actions=frozenset(o.get("auto_actions", settings.auto_actions)),
        notify_targets=frozenset(o.get("notify_targets", settings.notify_targets)),
        connectors=o.get("connectors", settings.connectors),
    )


def knowledge_dirs(tenant: str | None = None) -> list[tuple[str, Path]]:
    """[("global", data/knowledge), (tenant, data/tenants/<t>/knowledge)] for those that exist."""
    tenant = tenant or settings.tenant
    out = [("global", settings.knowledge_dir)]
    td = tenant_dir(tenant) / "knowledge"
    if td.exists():
        out.append((tenant, td))
    return out


def tenants() -> list[str]:
    root = settings.data_dir / "tenants"
    found = {p.name for p in root.iterdir() if p.is_dir()} if root.exists() else set()
    return sorted(found | {settings.tenant})
