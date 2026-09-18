"""LangGraph workflow. Stage 5.

    retrieve -> analyze -> guardrail -> act -> record

State is one Case. Each node is a plain function so it's testable without the graph."""
from __future__ import annotations

import time
from typing import TypedDict

from langgraph.graph import END, StateGraph

from . import actions, guardrails
from .knowledge import KnowledgeBase
from .llm import PROMPT_VERSION, Analyzer
from .models import ActionResult, Alert, Case
from .store import CaseStore


class State(TypedDict):
    case: Case


def build_graph(kb: KnowledgeBase, analyzer: Analyzer, store: CaseStore):
    def retrieve(state: State) -> State:
        c = state["case"]
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
            c.analysis = analyzer.analyze(c.alert, c.retrieved_docs)
        except Exception as e:  # noqa: BLE001 - logged, then re-raised
            err = f"{type(e).__name__}: {e}"
            raise
        finally:
            u = getattr(analyzer, "last_usage", {}) or {}
            c.model = u.get("model") or getattr(analyzer, "model", "")
            store.log_llm_call(
                subject_id=c.alert.id, stage="analyze", prompt_version=PROMPT_VERSION, model=c.model,
                kb_snapshot=c.kb_snapshot, retrieved=[d["id"] for d in c.retrieved_docs],
                input_tokens=u.get("input_tokens"), output_tokens=u.get("output_tokens"),
                cost_usd=u.get("cost_usd"), latency_ms=int((time.monotonic() - t0) * 1000),
                output=c.analysis.model_dump(mode="json") if c.analysis else None, error=err)
        return {"case": c}

    def guardrail(state: State) -> State:
        c = state["case"]
        decisions = guardrails.evaluate(c.alert, c.analysis)
        c.guardrail_log = [d.log_line() for d in decisions]
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


def run_alert(alert: Alert, kb: KnowledgeBase, analyzer: Analyzer, store: CaseStore) -> Case:
    graph = build_graph(kb, analyzer, store)
    out = graph.invoke({"case": Case(alert=alert, incident_id=alert.id if alert.is_incident else None)})
    return out["case"]
