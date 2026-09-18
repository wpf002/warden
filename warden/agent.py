"""LangGraph workflow. Stage 5.

    retrieve -> analyze -> guardrail -> act -> record

State is one Case. Each node is a plain function so it's testable without the graph."""
from __future__ import annotations

import time
from typing import TypedDict

from langgraph.graph import END, StateGraph

from . import actions, guardrails, obs
from .knowledge import KnowledgeBase
from .llm import PROMPT_VERSION, Analyzer
from .models import ActionResult, Alert, Case
from .store import CaseStore


class State(TypedDict):
    case: Case


def build_graph(kb: KnowledgeBase, analyzer: Analyzer, store: CaseStore, stats: dict | None = None):
    stats = stats or {}
    def retrieve(state: State) -> State:
        c = state["case"]
        with obs.span("retrieve", case=c.alert.id):
            c.retrieved_docs = kb.retrieve_for_alert(c.alert)
        return {"case": c}

    def analyze(state: State) -> State:
        """Every model output is logged with the alert id, retrieved context, prompt version,
        and KB snapshot. If it can't be replayed, it didn't happen (ROADMAP ground rule 3)."""
        c = state["case"]
        c.prompt_version = PROMPT_VERSION
        c.kb_snapshot = kb.snapshot_id()
        t0 = time.monotonic()
        err = None
        try:
            track = [stats[r].as_prior() for r in dict.fromkeys(c.alert.rules()) if r in stats]
            with obs.span("analyze", case=c.alert.id):
                c.analysis = analyzer.analyze(c.alert, c.retrieved_docs, {"track_record": track})
        except Exception as e:  # noqa: BLE001 - one failed call must not stop the run
            err = f"{type(e).__name__}: {e}"
            c.analysis = None
            c.guardrail_log.append(f"ANALYSIS FAILED {err[:300]}; case kept for an analyst, no actions taken")
            obs.log.warning("analysis failed", extra={"fields": {"case": c.alert.id, "error": err[:300]}})
        finally:
            u = getattr(analyzer, "last_usage", {}) or {}
            c.model = u.get("model") or getattr(analyzer, "model", "")
            elapsed = time.monotonic() - t0
            obs.LLM_SECONDS.labels(c.model or "unknown", u.get("stage", "analyze")).observe(elapsed)
            if u.get("cost_usd"):
                obs.LLM_COST.labels(c.model).inc(u["cost_usd"])
            for d in ("input_tokens", "output_tokens"):
                if u.get(d):
                    obs.LLM_TOKENS.labels(c.model, d.split("_")[0]).inc(u[d])
            store.log_llm_call(
                subject_id=c.alert.id, stage="analyze", prompt_version=PROMPT_VERSION, model=c.model,
                kb_snapshot=c.kb_snapshot, retrieved=[d["id"] for d in c.retrieved_docs],
                input_tokens=u.get("input_tokens"), output_tokens=u.get("output_tokens"),
                cost_usd=u.get("cost_usd"), latency_ms=int((time.monotonic() - t0) * 1000),
                output=c.analysis.model_dump(mode="json") if c.analysis else None, error=err)
        return {"case": c}

    def guardrail(state: State) -> State:
        c = state["case"]
        if c.analysis is None:          # nothing to act on; a person picks it up from the queue
            c.status = "open"
            return {"case": c}
        from .stats import threshold_bump
        bump = max((threshold_bump(stats.get(r)) for r in c.alert.rules()), default=0)
        from .governance import verify, verify_with_model
        from .tenancy import policy
        c.verification = verify(c.alert, c.analysis, c.retrieved_docs)
        try:
            c.verification += verify_with_model(c.alert, c.analysis)
        except Exception as e:  # noqa: BLE001 - a failed second opinion is noted, not fatal
            c.guardrail_log.append(f"VERIFY second opinion unavailable: {type(e).__name__}")
        for v in c.verification:
            c.guardrail_log.append(f"VERIFY   {v}")
        decisions = guardrails.evaluate(c.alert, c.analysis, bump=bump, policy=policy(store.tenant),
                                        verified=not c.verification)
        c.guardrail_log = [*c.guardrail_log, *(d.log_line() for d in decisions)]
        c.actions = []
        for d in decisions:
            if d.verdict == "execute":
                c.actions.append(actions.execute(c.alert, d.action))
            elif d.verdict == "approve":
                c.actions.append(ActionResult(action=d.action.action, target=d.action.target,
                                              status="pending_approval", detail=d.why))
            else:
                c.actions.append(ActionResult(action=d.action.action, target=d.action.target,
                                              status="denied", detail=d.why))
        c.status = "awaiting_approval" if any(a.status == "pending_approval" for a in c.actions) else "open"
        return {"case": c}

    def record(state: State) -> State:
        store.save(state["case"])
        return state

    g = StateGraph(State)
    g.add_node("retrieve", retrieve)
    g.add_node("analyze", analyze)
    g.add_node("guardrail", guardrail)
    g.add_node("record", record)
    g.set_entry_point("retrieve")
    g.add_edge("retrieve", "analyze")
    g.add_edge("analyze", "guardrail")
    g.add_edge("guardrail", "record")
    g.add_edge("record", END)
    return g.compile()


def run_alert(alert: Alert, kb: KnowledgeBase, analyzer: Analyzer, store: CaseStore, stats: dict | None = None) -> Case:
    graph = build_graph(kb, analyzer, store, stats)
    tok = obs.new_trace(alert.id)
    try:
        with obs.collect_spans() as spans:
            out = graph.invoke({"case": Case(alert=alert, incident_id=alert.id if alert.is_incident else None)})
        case = out["case"]
        case.spans = spans
        for r in case.actions:
            obs.ACTIONS.labels(r.action, r.status).inc()
        obs.CASES.labels("incident" if alert.is_incident else "alert").inc()
        store.save(case)
        obs.event("case analyzed", case=alert.id, rules=alert.rules(), risk=case.analysis.risk_score if case.analysis else None,
                  status=case.status, model=case.model, ms=sum(s["ms"] for s in spans))
        return case
    finally:
        obs._trace.reset(tok)
