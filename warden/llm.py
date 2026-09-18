"""LLM layer. Stage 6. Claude via the official anthropic SDK with structured output.
The mock provider is rule-based and exists so the pipeline runs and tests pass with no key."""
from __future__ import annotations

import json
from typing import Protocol

from .config import settings
from .models import Alert, Analysis, RecommendedAction

from .prompts import load as _load_prompt

PROMPT = _load_prompt("analyze")
SYSTEM_PROMPT = PROMPT.system
USER_TEMPLATE = PROMPT.user
PROMPT_VERSION = PROMPT.tag

# $ per million tokens (input, output). Used for the cost column in the model-call log.
PRICING = {
    "claude-fable-5-1": (10.0, 50.0), "claude-opus-5": (5.0, 25.0), "claude-opus-4-8": (5.0, 25.0),
    "claude-sonnet-5": (2.0, 10.0), "claude-sonnet-4-6": (3.0, 15.0), "claude-haiku-4-5": (1.0, 5.0),
}


def cost_usd(model: str, input_tokens: int, output_tokens: int, cache_read: int = 0) -> float:
    pin, pout = PRICING.get(model, (5.0, 25.0))
    return round(((input_tokens - cache_read) * pin + cache_read * pin * 0.1 + output_tokens * pout) / 1e6, 6)


def _format_context(docs: list[dict]) -> str:
    if not docs:
        return "(no documents retrieved)"
    return "\n\n".join(f"[{d['id']}]\n{d['text']}" for d in docs)


class Analyzer(Protocol):
    def analyze(self, alert: Alert, docs: list[dict], context: dict | None = None) -> Analysis: ...


def _track(context: dict | None) -> str:
    rec = (context or {}).get("track_record") or []
    return json.dumps(rec, indent=1) if rec else "(no analyst verdicts yet)"


def _alert_json(alert: Alert) -> str:
    """The alert as the model sees it. Incidents carry compact member summaries and the
    merged timeline instead of every member's full evidence."""
    if alert.is_incident:
        body = alert.model_dump(mode="json", exclude={"evidence", "members"})
        body["members"] = [{"id": m.id, "rule": m.rule, "title": m.title, "mitre": m.mitre,
                            "first_seen": m.first_seen.isoformat(), "detail": m.detail} for m in alert.members]
        body["timeline"] = alert.evidence[:40]
        return json.dumps(body, indent=2, default=str)
    return alert.model_dump_json(indent=2, exclude={"evidence", "members"}) + \
        f"\nevidence_sample: {json.dumps(alert.evidence[:12])}"


class AnthropicAnalyzer:
    """Claude via the official SDK. Structured output is parsed straight into `Analysis`.

    Security content can trip a model's safety classifiers, so requests opt into
    server-side fallbacks: a declined request is re-run on Anthropic's recommended
    fallback model inside the same call instead of coming back as a refusal.
    """

    FALLBACK_BETA = "server-side-fallback-2026-07-01"
    FALLBACK_MODELS = {"claude-opus-5", "claude-fable-5-1"}     # server-side refusal fallbacks

    def __init__(self, model: str | None = None, effort: str | None = None, client=None):
        import anthropic

        headers = {"anthropic-workspace-id": settings.anthropic_workspace_id} if settings.anthropic_workspace_id else None
        self.client = client or anthropic.Anthropic(api_key=settings.anthropic_api_key or None, max_retries=4,
                                                    default_headers=headers)
        self.model = model or settings.model
        self.effort = effort or settings.effort
        self.last_usage: dict = {}

    def analyze(self, alert: Alert, docs: list[dict], context: dict | None = None) -> Analysis:
        user = USER_TEMPLATE.format(
            alert_json=_alert_json(alert),
            context=_format_context(docs),
            track_record=_track(context),
        )
        kw = {}
        if self.model in self.FALLBACK_MODELS:
            kw = {"betas": [self.FALLBACK_BETA], "fallbacks": "default"}
        resp = self.client.beta.messages.parse(
            model=self.model,
            max_tokens=16000,
            system=[{"type": "text", "text": SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": user}],
            output_format=Analysis,
            output_config={"effort": self.effort},
            thinking={"type": "adaptive"},
            **kw,
        )
        u = resp.usage
        cache_read = getattr(u, "cache_read_input_tokens", 0) or 0
        # input_tokens excludes cache reads; add them back so cost_usd can price both parts
        self.last_usage = {"model": resp.model, "input_tokens": u.input_tokens + cache_read,
                           "output_tokens": u.output_tokens, "cache_read_input_tokens": cache_read,
                           "stop_reason": resp.stop_reason,
                           "cost_usd": cost_usd(resp.model, u.input_tokens + cache_read, u.output_tokens, cache_read)}
        if resp.stop_reason == "refusal" or resp.parsed_output is None:
            raise RuntimeError(f"model returned no analysis (stop_reason={resp.stop_reason})")
        return resp.parsed_output


class MockAnalyzer:
    """Deterministic. Mirrors what the playbooks say so the demo is coherent offline."""

    model = "mock"
    last_usage: dict = {}

    def analyze(self, alert: Alert, docs: list[dict], context: dict | None = None) -> Analysis:
        an = self._incident(alert, docs) if alert.is_incident else self._single(alert, docs)
        # a rule analysts keep rejecting gets its score pulled down, as the real prompt asks the model to do
        recs = {r["rule"]: r for r in (context or {}).get("track_record", [])}
        worst = max((r.get("false_positive_rate_30d") or 0 for r in recs.values()
                     if (r.get("analyst_verdicts_30d") or 0) >= settings.fp_prior_min_verdicts), default=0)
        if worst >= 0.5:
            an.risk_score = max(0, an.risk_score - int(30 * worst))
            an.false_positive_likelihood = "high"
            an.explanation += f" Analysts rejected {worst:.0%} of this rule's recent alerts."
        return an

    # rule -> (technique, risk, severity, fp likelihood, actions). Mirrors the playbooks.
    TABLE = {
        "credential_stuffing": ("T1110.004 Brute Force: Credential Stuffing", 76, "high", "low", ["block_ip", "create_ticket", "notify"]),
        "new_geo_login": ("T1078 Valid Accounts", 55, "medium", "medium", ["create_ticket", "notify"]),
        "mfa_method_change": ("T1556.006 Modify Authentication Process: Multi-Factor Authentication", 86, "critical", "low",
                              ["lock_user", "create_ticket", "notify"]),
        "dormant_account": ("T1078 Valid Accounts", 62, "medium", "medium", ["lock_user", "create_ticket", "notify"]),
        "service_account_interactive": ("T1078.002 Valid Accounts: Domain Accounts", 70, "high", "medium",
                                        ["create_ticket", "notify"]),
        "privileged_group_add": ("T1098 Account Manipulation", 84, "critical", "low", ["create_ticket", "notify"]),
        "account_create_then_privilege": ("T1136 Create Account", 90, "critical", "low", ["lock_user", "create_ticket", "notify"]),
        "session_anomaly": ("T1550.004 Use Alternate Authentication Material: Web Session Cookie", 85, "critical", "low",
                            ["lock_user", "block_ip", "create_ticket", "notify"]),
        "password_reset_abuse": ("T1098 Account Manipulation", 72, "high", "medium", ["create_ticket", "notify"]),
        "lockout_storm": ("T1110 Brute Force", 68, "high", "low", ["create_ticket", "notify"]),
        "suspicious_parent_child": ("T1204.002 User Execution: Malicious File", 84, "critical", "low",
                                    ["isolate_host", "create_ticket", "notify"]),
        "lolbin_abuse": ("T1218 System Binary Proxy Execution", 80, "high", "low", ["isolate_host", "create_ticket", "notify"]),
        "encoded_powershell": ("T1059.001 Command and Scripting Interpreter: PowerShell", 78, "high", "medium",
                               ["isolate_host", "create_ticket", "notify"]),
        "credential_dumping": ("T1003.001 OS Credential Dumping: LSASS Memory", 92, "critical", "low",
                               ["isolate_host", "create_ticket", "notify"]),
        "persistence_mechanism": ("T1543.003 Create or Modify System Process: Windows Service", 74, "high", "medium",
                                  ["create_ticket", "notify"]),
        "edr_alert": ("T1003 OS Credential Dumping", 88, "critical", "low", ["isolate_host", "create_ticket", "notify"]),
        "log_clearing": ("T1685.005 Indicator Removal: Clear Windows Event Logs", 82, "high", "low",
                         ["isolate_host", "create_ticket", "notify"]),
        "security_tool_tamper": ("T1685 Impair Defenses: Disable or Modify Tools", 85, "critical", "low",
                                 ["isolate_host", "create_ticket", "notify"]),
        "ransomware_precursor": ("T1490 Inhibit System Recovery", 95, "critical", "low", ["isolate_host", "create_ticket", "notify"]),
        "mass_file_encryption": ("T1486 Data Encrypted for Impact", 98, "critical", "low", ["isolate_host", "create_ticket", "notify"]),
        "beaconing": ("T1071 Application Layer Protocol", 76, "high", "medium", ["block_ip", "create_ticket", "notify"]),
        "dns_tunneling": ("T1071.004 Application Layer Protocol: DNS", 80, "high", "low", ["isolate_host", "create_ticket", "notify"]),
        "lateral_movement_fanout": ("T1021 Remote Services", 82, "high", "low", ["isolate_host", "create_ticket", "notify"]),
        "port_scan": ("T1046 Network Service Discovery", 55, "medium", "medium", ["create_ticket", "notify"]),
        "data_exfiltration": ("T1048 Exfiltration Over Alternative Protocol", 86, "critical", "medium",
                              ["block_ip", "isolate_host", "create_ticket", "notify"]),
        "intel_ioc_match": ("T1071 Application Layer Protocol", 82, "high", "low", ["block_ip", "create_ticket", "notify"]),
        "iam_admin_grant": ("T1098.003 Account Manipulation: Additional Cloud Roles", 84, "critical", "low",
                            ["create_ticket", "notify"]),
        "new_access_key": ("T1098.001 Account Manipulation: Additional Cloud Credentials", 80, "high", "low",
                           ["disable_access_key", "create_ticket", "notify"]),
        "public_bucket": ("T1530 Data from Cloud Storage", 83, "critical", "medium", ["create_ticket", "notify"]),
        "cloud_logging_disabled": ("T1685.002 Impair Defenses: Disable or Modify Cloud Logs", 88, "critical", "low",
                                   ["create_ticket", "notify"]),
        "unusual_region": ("T1535 Unused/Unsupported Cloud Regions", 72, "high", "medium", ["create_ticket", "notify"]),
        "console_login_no_mfa": ("T1078.004 Valid Accounts: Cloud Accounts", 62, "medium", "medium", ["create_ticket", "notify"]),
        "mailbox_forwarding_rule": ("T1114.003 Email Collection: Email Forwarding Rule", 86, "critical", "low",
                                    ["lock_user", "create_ticket", "notify"]),
    }

    def _from_table(self, alert: Alert, cites: list[str]) -> Analysis:
        tech, risk, sev, fp, acts = self.TABLE[alert.rule]
        d = alert.detail
        if alert.rule == "privileged_group_add" and d.get("in_change_window"):
            risk, sev, fp = 45, "medium", "high"
        if alert.asset_tier == "crown_jewel" and alert.rule in ("new_geo_login", "dormant_account"):
            risk += 15
        if d.get("succeeded_users") and "lock_user" not in acts:
            acts = ["lock_user", *acts]
        target_user = (d.get("member") or d.get("succeeded_users", [None])[0] if d.get("succeeded_users") or d.get("member")
                       else (alert.users[0] if alert.users else ""))
        recs = []
        for a in acts:
            ext = next((ip for ip in alert.related_ips if ip and not ip.startswith(("10.", "192.168.", "172.16."))), "")
            tgt = {"block_ip": ext or alert.source_ip, "lock_user": target_user, "create_ticket": alert.id, "notify": "soc",
                   "isolate_host": alert.hosts[0] if alert.hosts else "",
                   "disable_access_key": d.get("principal") or target_user}[a]
            if tgt:
                recs.append(RecommendedAction(action=a, target=tgt, reason=f"{alert.rule} playbook"))
        return Analysis(explanation=f"{alert.title}.", mitre_attack=tech, risk_score=min(100, risk),
                        severity=sev, false_positive_likelihood=fp, recommended_actions=recs, citations=cites)

    def _anomaly(self, alert: Alert, cites: list[str]) -> Analysis:
        d = alert.detail
        feats = {c["feature"] for c in d.get("contributions", [])}
        score = d.get("score", 0)
        recon = "processes_set" in feats and ("hosts" in feats or "distinct_hosts" in feats)
        tech = ("T1087 Account Discovery / T1018 Remote System Discovery" if recon else
                "T1078 Valid Accounts" if feats & {"geos", "src_nets", "hours"} else "no clear technique")
        risk = min(90, int(35 + 3 * score))
        acts = [RecommendedAction(action="create_ticket", target=alert.id, reason="investigate the deviation"),
                RecommendedAction(action="notify", target="soc", reason="anomaly review")]
        if d.get("entity_type") == "user" and risk >= 70:
            acts.insert(0, RecommendedAction(action="lock_user", target=d["entity"], reason="deviation consistent with misuse"))
        if d.get("entity_type") == "host" and risk >= 70:
            acts.insert(0, RecommendedAction(action="isolate_host", target=d["entity"], reason="deviation consistent with compromise"))
        why = "; ".join(c["why"] for c in d.get("contributions", [])[:4])
        return Analysis(explanation=f"No rule fired; {d.get('entity_type')} {d.get('entity')} departed from its "
                                    f"{d.get('baseline_days')}-day baseline: {why}. Closest technique: {tech}.",
                        mitre_attack=tech, risk_score=risk, severity="high" if risk >= 70 else "medium",
                        false_positive_likelihood="medium", recommended_actions=acts, citations=cites)

    SEV = ["low", "medium", "high", "critical"]
    FPL = ["low", "medium", "high"]

    def _incident(self, inc: Alert, docs: list[dict]) -> Analysis:
        """Each stage analyzed alone, then combined: a chain is worse than its worst link."""
        parts = [self._single(m, docs) for m in inc.members]
        stages = len(set(inc.rules()))
        risk = min(100, max(p.risk_score for p in parts) + 4 * (stages - 1))
        seen, actions = set(), []
        for p in parts:
            for a in p.recommended_actions:
                if a.action == "create_ticket":
                    a = RecommendedAction(action="create_ticket", target=inc.id, reason="one ticket for the incident")
                if (a.action, a.target) not in seen:
                    seen.add((a.action, a.target))
                    actions.append(a)
        return Analysis(
            explanation=f"{stages}-stage chain on {inc.detail.get('focus')}: "
                        + "; then ".join(m.title for m in inc.members) + ".",
            mitre_attack=", ".join(inc.mitre),
            risk_score=risk,
            severity=self.SEV[min(3, max(self.SEV.index(p.severity) for p in parts) + (1 if stages >= 3 else 0))],
            false_positive_likelihood=self.FPL[min(self.FPL.index(p.false_positive_likelihood) for p in parts)],
            recommended_actions=actions, citations=[d["id"] for d in docs[:3]])

    def _single(self, alert: Alert, docs: list[dict]) -> Analysis:
        cites = [d["id"] for d in docs[:3]]
        svc = any(u.startswith("svc-") for u in alert.users)
        internal = alert.geo == "internal"
        if svc and internal:
            return Analysis(
                explanation=f"{alert.failed_attempts} failures for service account(s) {', '.join(alert.users)} from internal IP "
                            f"{alert.source_ip}. Matches the INC-2026-0642 pattern: stale credential after rotation, not an attack.",
                mitre_attack="T1110.001 Brute Force: Password Guessing (likely benign)",
                risk_score=25, severity="low", false_positive_likelihood="high",
                recommended_actions=[RecommendedAction(action="create_ticket", target=alert.id, reason="platform team to fix credential"),
                                     RecommendedAction(action="notify", target="soc", reason="FYI")],
                citations=cites)
        if alert.rule.startswith("anomaly."):
            return self._anomaly(alert, cites)
        if alert.rule in self.TABLE:
            return self._from_table(alert, cites)
        if alert.rule == "impossible_travel":
            d = alert.detail
            return Analysis(
                explanation=f"{alert.users[0]} signed in successfully from {d.get('from_geo')} and again from {d.get('to_geo')} "
                            f"{d.get('elapsed_sec', 0) // 60} minutes later. That is {d.get('distance_km')} km apart, an implied "
                            f"{d.get('implied_kmh')} km/h against a {d.get('max_plausible_kmh')} km/h ceiling. Either a stolen session "
                            f"or a VPN/proxy the user did not declare."
                            + (" The user agent also changed between the two logins." if d.get("user_agent_changed") else ""),
                mitre_attack="T1078 Valid Accounts",
                risk_score=74, severity="high", false_positive_likelihood="medium",
                recommended_actions=[RecommendedAction(action="lock_user", target=alert.users[0], reason="revoke sessions pending confirmation"),
                                     RecommendedAction(action="create_ticket", target=alert.id, reason="confirm travel or VPN with the user"),
                                     RecommendedAction(action="notify", target="soc", reason="identity review")],
                citations=cites)
        if alert.rule == "mfa_fatigue":
            d = alert.detail
            approved = d.get("approved_after")
            return Analysis(
                explanation=f"{alert.failed_attempts} {d.get('factor', 'push')} prompts to {alert.users[0]} from {alert.source_ip} "
                            f"({alert.geo}) roughly every {d.get('prompt_interval_sec')}s. The attacker already holds valid credentials; "
                            f"only the second factor is holding."
                            + (" An approval landed right after the burst, so treat the account as compromised."
                               if approved else " No approval followed, so the push held."),
                mitre_attack="T1621 Multi-Factor Authentication Request Generation",
                risk_score=92 if approved else 68,
                severity="critical" if approved else "high",
                false_positive_likelihood="low",
                recommended_actions=([RecommendedAction(action="lock_user", target=alert.users[0], reason="approval after push bombing = presumed compromise")] if approved else [])
                                    + [RecommendedAction(action="block_ip", target=alert.source_ip, reason="stop the prompt source"),
                                       RecommendedAction(action="create_ticket", target=alert.id, reason="password reset and factor re-enrollment"),
                                       RecommendedAction(action="notify", target="soc", reason="contact the user out of band")],
                citations=cites)
        if alert.rule == "password_spray":
            return Analysis(
                explanation=f"{alert.failed_attempts} failed logins spread across {len(alert.users)} accounts from {alert.source_ip} ({alert.geo}) "
                            f"against {', '.join(alert.hosts)} in {alert.window_sec}s. Even spacing and many targets indicate password spraying "
                            f"against the identity provider.",
                mitre_attack="T1110.003 Brute Force: Password Spraying",
                risk_score=78, severity="high", false_positive_likelihood="low",
                recommended_actions=[RecommendedAction(action="block_ip", target=alert.source_ip, reason="PB-005 containment"),
                                     RecommendedAction(action="create_ticket", target=alert.id, reason="track investigation"),
                                     RecommendedAction(action="notify", target="soc", reason="check IdP for successes in last 24h")],
                citations=cites)
        risk = 88 if alert.success_after_failures else 72
        if alert.asset_tier == "crown_jewel":
            risk = min(100, risk + 7)
        actions = [RecommendedAction(action="block_ip", target=alert.source_ip, reason="PB-004 containment")]
        if alert.success_after_failures:
            actions.append(RecommendedAction(action="lock_user", target=alert.users[0], reason="success after burst = presumed compromise"))
        actions += [RecommendedAction(action="create_ticket", target=alert.id, reason="evidence attached"),
                    RecommendedAction(action="notify", target="soc", reason="on-call review")]
        return Analysis(
            explanation=f"{alert.failed_attempts} failed logins for {', '.join(alert.users)} from {alert.source_ip} ({alert.geo}) on "
                        f"{', '.join(alert.hosts)} within {alert.window_sec}s"
                        + (". A successful login followed the burst, so the account is presumed compromised." if alert.success_after_failures else ".")
                        + (" Target is a crown-jewel asset." if alert.asset_tier == "crown_jewel" else ""),
            mitre_attack="T1110.001 Brute Force: Password Guessing",
            risk_score=risk, severity="critical" if alert.success_after_failures else "high",
            false_positive_likelihood="low", recommended_actions=actions, citations=cites)


class OpenAICompatibleAnalyzer:
    """Any endpoint speaking the OpenAI chat-completions protocol with JSON-schema output:
    OpenAI itself, or a local model behind vLLM or Ollama. Same prompt, same schema, same
    guardrails downstream. WARDEN_LLM=openai, WARDEN_LLM_BASE_URL, WARDEN_LLM_API_KEY."""

    def __init__(self, model: str | None = None, base_url: str | None = None, api_key: str | None = None, transport=None):
        import httpx
        self.model = model or settings.model
        headers = {"Authorization": f"Bearer {api_key or settings.llm_api_key}"} if (api_key or settings.llm_api_key) else {}
        self.http = httpx.Client(base_url=(base_url or settings.llm_base_url or "https://api.openai.com/v1").rstrip("/"),
                                 headers=headers, timeout=httpx.Timeout(180.0, connect=10.0), transport=transport)
        self.last_usage: dict = {}

    def analyze(self, alert: Alert, docs: list[dict], context: dict | None = None) -> Analysis:
        user = USER_TEMPLATE.format(alert_json=_alert_json(alert), context=_format_context(docs), track_record=_track(context))
        r = self.http.post("/chat/completions", json={
            "model": self.model,
            "messages": [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": user}],
            "response_format": {"type": "json_schema",
                                "json_schema": {"name": "analysis", "schema": Analysis.model_json_schema(), "strict": False}},
        })
        if r.status_code >= 400:
            raise RuntimeError(f"{self.model}: HTTP {r.status_code} {r.text[:200]}")
        body = r.json()
        u = body.get("usage") or {}
        self.last_usage = {"model": body.get("model", self.model), "input_tokens": u.get("prompt_tokens"),
                           "output_tokens": u.get("completion_tokens"), "cost_usd": None}
        return Analysis.model_validate_json(body["choices"][0]["message"]["content"])


class RoutingAnalyzer:
    """Model per stage: incidents, crown-jewel assets, anomalies, and anything touching
    credentials or ransomware get the strong model; routine single alerts go to the
    cheaper triage model. Both share the prompt, schema, and guardrails."""

    STRONG_RULES = {"credential_dumping", "ransomware_precursor", "mass_file_encryption", "mfa_method_change",
                    "session_anomaly", "account_create_then_privilege", "cloud_logging_disabled"}

    def __init__(self, strong: Analyzer, triage: Analyzer):
        self.strong, self.triage = strong, triage
        self.last_usage: dict = {}
        self.model = getattr(strong, "model", "")

    def pick(self, alert: Alert) -> Analyzer:
        heavy = (alert.is_incident or alert.asset_tier == "crown_jewel" or alert.rule.startswith("anomaly.")
                 or alert.rule in self.STRONG_RULES)
        return self.strong if heavy else self.triage

    def analyze(self, alert: Alert, docs: list[dict], context: dict | None = None) -> Analysis:
        a = self.pick(alert)
        out = a.analyze(alert, docs, context)
        self.last_usage = {**(getattr(a, "last_usage", {}) or {}), "stage": "incident" if a is self.strong else "triage"}
        self.model = getattr(a, "model", "")
        return out


def get_analyzer(tenant: str | None = None) -> Analyzer:
    """Provider and models come from the tenant's policy.json "llm" block, else settings."""
    import json as _json

    from .tenancy import tenant_dir
    cfg = {}
    pf = tenant_dir(tenant or settings.tenant) / "policy.json"
    if pf.exists():
        cfg = _json.loads(pf.read_text()).get("llm", {})
    provider = cfg.get("provider", settings.llm_provider)
    strong, triage = cfg.get("model", settings.model), cfg.get("model_triage", settings.model_triage)
    if provider == "anthropic":
        if strong == triage:
            return AnthropicAnalyzer(strong)
        return RoutingAnalyzer(AnthropicAnalyzer(strong), AnthropicAnalyzer(triage))
    if provider == "openai":
        base = cfg.get("base_url", settings.llm_base_url)
        return RoutingAnalyzer(OpenAICompatibleAnalyzer(strong, base), OpenAICompatibleAnalyzer(triage, base)) \
            if strong != triage else OpenAICompatibleAnalyzer(strong, base)
    return MockAnalyzer()
