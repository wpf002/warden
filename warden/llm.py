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
    def analyze(self, alert: Alert, docs: list[dict]) -> Analysis: ...


class AnthropicAnalyzer:
    """Claude via the official SDK. Structured output is parsed straight into `Analysis`.

    Security content can trip a model's safety classifiers, so requests opt into
    server-side fallbacks: a declined request is re-run on Anthropic's recommended
    fallback model inside the same call instead of coming back as a refusal.
    """

    FALLBACK_BETA = "server-side-fallback-2026-07-01"

    def __init__(self, model: str | None = None, effort: str | None = None, client=None):
        import anthropic

        headers = {"anthropic-workspace-id": settings.anthropic_workspace_id} if settings.anthropic_workspace_id else None
        self.client = client or anthropic.Anthropic(api_key=settings.anthropic_api_key or None, max_retries=4,
                                                    default_headers=headers)
        self.model = model or settings.model
        self.effort = effort or settings.effort
        self.last_usage: dict = {}

    def analyze(self, alert: Alert, docs: list[dict]) -> Analysis:
        user = USER_TEMPLATE.format(
            alert_json=alert.model_dump_json(indent=2, exclude={"evidence"})
            + f"\nevidence_sample: {json.dumps(alert.evidence[:12])}",
            context=_format_context(docs),
        )
        resp = self.client.beta.messages.parse(
            model=self.model,
            max_tokens=16000,
            system=[{"type": "text", "text": SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": user}],
            output_format=Analysis,
            output_config={"effort": self.effort},
            thinking={"type": "adaptive"},
            betas=[self.FALLBACK_BETA],
            fallbacks="default",
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

    def analyze(self, alert: Alert, docs: list[dict]) -> Analysis:
        cites = [d["id"] for d in docs[:3]]
        svc = any(u.startswith("svc-") for u in alert.users)
        internal = alert.geo == "internal"
        if svc and internal:
            return Analysis(
                explanation=f"{alert.failed_attempts} failures for service account(s) {', '.join(alert.users)} from internal IP "
                            f"{alert.source_ip}. Matches the INC-2026-0642 pattern: stale credential after rotation, not an attack.",
                mitre_attack="T1110.001 Brute Force: Password Guessing (likely benign)",
                risk_score=25, severity="low", false_positive_likelihood="high",
                recommended_actions=[RecommendedAction(action="create_ticket", target=alert.source_ip, reason="platform team to fix credential"),
                                     RecommendedAction(action="notify", target="soc", reason="FYI")],
                citations=cites)
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


def get_analyzer() -> Analyzer:
    if settings.llm_provider == "anthropic":
        return AnthropicAnalyzer()
    return MockAnalyzer()
