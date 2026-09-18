"""SOC dashboard. FastAPI + server-rendered HTML. No build step."""
from __future__ import annotations

import html
from functools import lru_cache

import hmac
import json

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from . import feedback
from .auth import User, require
from .knowledge import KnowledgeBase
from .llm import get_analyzer
from .pipeline import run
from .store import CaseStore

app = FastAPI(title="Warden SOC")


@lru_cache(maxsize=1)
def _kb() -> KnowledgeBase:
    kb = KnowledgeBase()
    kb.sync()
    return kb


store = CaseStore()

CSS = """
body{font:14px/1.45 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;background:#0b1020;color:#dfe6f3;margin:0}
a{color:#7cc4ff;text-decoration:none} .wrap{max-width:1100px;margin:0 auto;padding:24px}
h1{font-size:20px;margin:0 0 16px} h2{font-size:15px;margin:22px 0 8px;color:#9fb3d1;text-transform:uppercase;letter-spacing:.06em}
table{width:100%;border-collapse:collapse} th,td{padding:8px 10px;text-align:left;border-bottom:1px solid #1e2a44;vertical-align:top}
th{color:#9fb3d1;font-weight:600} .card{background:#121a30;border:1px solid #1e2a44;border-radius:8px;padding:16px;margin-bottom:14px}
.pill{display:inline-block;padding:2px 8px;border-radius:10px;font-size:12px;font-weight:600}
.critical{background:#5b1020;color:#ffb3c1}.high{background:#5a2e0a;color:#ffd39b}.medium{background:#4a4210;color:#fff0a3}.low{background:#0f3d2e;color:#a8f0cf}
.executed{color:#7be0a8}.pending_approval{color:#ffd166}.denied{color:#ff7b8a}.failed{color:#ff7b8a}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;white-space:pre-wrap}
button{background:#1f6feb;color:#fff;border:0;padding:6px 12px;border-radius:6px;cursor:pointer;margin-right:6px}
button.secondary{background:#2c3550} form{display:inline} input[type=text]{background:#0b1020;color:#dfe6f3;border:1px solid #2c3550;border-radius:6px;padding:6px 8px;width:60%}
.kpi{display:inline-block;margin-right:28px}.kpi b{display:block;font-size:24px}.doc{border-left:3px solid #2c3550;padding-left:10px;margin:8px 0}
"""


def _page(title: str, body: str) -> HTMLResponse:
    return HTMLResponse(f"<!doctype html><title>{html.escape(title)}</title><style>{CSS}</style><div class=wrap>{body}</div>")


def _sev(s: str) -> str:
    return f'<span class="pill {s}">{s}</span>'


@app.get("/", response_class=HTMLResponse)
def index(user: User = Depends(require("viewer"))):
    cases = store.all()
    n_open = sum(c.status != "closed" for c in cases)
    n_pending = sum(a.status == "pending_approval" for c in cases for a in c.actions)
    n_exec = sum(a.status == "executed" for c in cases for a in c.actions)
    n_tp = sum(c.analyst_verdict == "true_positive" for c in cases)
    n_fp = sum(c.analyst_verdict == "false_positive" for c in cases)
    rows = "".join(
        f"<tr><td><a href='/case/{c.alert.id}'>{c.alert.id}</a></td><td>{html.escape(c.alert.title)}</td>"
        f"<td>{c.alert.rule}</td>"
        f"<td>{_sev(c.analysis.severity) if c.analysis else ''}</td><td>{c.analysis.risk_score if c.analysis else ''}</td>"
        f"<td>{html.escape(c.analysis.mitre_attack) if c.analysis else ''}</td><td>{c.status}</td>"
        f"<td>{c.analyst_verdict or ''}</td></tr>"
        for c in cases
    )
    body = f"""
    <h1>Warden SOC <span style='color:#5c6f91;font-weight:400'>/ alerts</span></h1>
    <div class=card>
      <span class=kpi><b>{len(cases)}</b>alerts</span><span class=kpi><b>{n_open}</b>open</span>
      <span class=kpi><b>{n_pending}</b>awaiting approval</span><span class=kpi><b>{n_exec}</b>actions executed</span>
      <span class=kpi><b>{n_tp}/{n_fp}</b>TP / FP</span>
      <a href=/detections>detections</a> · <a href=/exclusions>exclusions</a> · <a href=/audit>audit</a>
      <form method=post action=/run style='float:right'><button>Run pipeline</button></form>
      <form method=post action=/reindex style='float:right'><button class=secondary>Reindex KB</button></form>
    </div>
    <table><tr><th>ID</th><th>Alert</th><th>Rule</th><th>Severity</th><th>Risk</th><th>MITRE</th><th>Status</th><th>Verdict</th></tr>{rows}</table>
    """
    return _page("Warden SOC", body)


@app.get("/case/{alert_id}", response_class=HTMLResponse)
def case_view(alert_id: str, user: User = Depends(require("viewer"))):
    c = store.get(alert_id)
    if not c:
        raise HTTPException(404)
    a, an = c.alert, c.analysis
    detail = " · ".join(f"{k}: <b>{html.escape(str(v))}</b>" for k, v in a.detail.items() if v is not None)
    acts = ""
    for i, r in enumerate(c.actions):
        ctl = ""
        if r.status == "pending_approval" and c.status != "closed":
            ctl = (f"<form method=post action='/case/{a.id}/action/{i}/approve'><button>Approve</button></form>"
                   f"<form method=post action='/case/{a.id}/action/{i}/deny'><button class=secondary>Deny</button></form>")
        elif r.status == "executed" and r.receipt:
            ctl = f"<form method=post action='/case/{a.id}/action/{i}/rollback'><button class=secondary>Roll back</button></form>"
        acts += f"<tr><td class={r.status}>{r.status}</td><td>{r.action}</td><td>{html.escape(r.target)}</td><td>{html.escape(r.detail)}</td><td>{ctl}</td></tr>"
    docs = "".join(f"<div class=doc><b>{html.escape(d['id'])}</b> <span style='color:#5c6f91'>dist {d['distance']}</span>"
                   f"<div class=mono>{html.escape(d['text'][:600])}</div></div>" for d in c.retrieved_docs)
    recs = "".join(f"<li><b>{x.action}</b> {html.escape(x.target)} <span style='color:#9fb3d1'>{html.escape(x.reason)}</span></li>"
                   for x in (an.recommended_actions if an else []))
    from .stats import FP_REASONS
    reasons = "".join(f"<option value={k}>{html.escape(v)}</option>" for k, v in FP_REASONS.items())
    verdict = (f"<p>Analyst verdict: <b>{c.analyst_verdict}</b> {html.escape(c.analyst_reason)} {html.escape(c.analyst_note)}</p>"
               if c.analyst_verdict else
               f"<form method=post action='/case/{a.id}/verdict'><input type=text name=note placeholder='note (optional)'> "
               f"<button name=verdict value=true_positive>True positive</button><br><br>"
               f"<select name=reason><option value=''>FP reason...</option>{reasons}</select> "
               f"<label><input type=checkbox name=suppress value=1> mute this rule for this entity for 30 days</label> "
               f"<button name=verdict value=false_positive class=secondary>False positive</button></form>")
    body = f"""
    <p><a href=/>&larr; alerts</a></p>
    <h1>{a.id} <span style='color:#5c6f91;font-weight:400'>{html.escape(a.title)}</span></h1>
    <div class=card>
      {_sev(an.severity) if an else ''} risk <b>{an.risk_score if an else '?'}</b> &nbsp; {html.escape(an.mitre_attack) if an else ''}
      &nbsp; FP likelihood: <b>{an.false_positive_likelihood if an else '?'}</b> &nbsp; status: <b>{c.status}</b>
      <p>{html.escape(an.explanation) if an else ''}</p>
      <h2>Recommended by model</h2><ul>{recs}</ul>
      <div style='color:#5c6f91'>citations: {', '.join(html.escape(x) for x in (an.citations if an else []))}</div>
    </div>
    <h2>Guardrail decisions and actions</h2>
    <div class=card>
      <div class=mono>{html.escape(chr(10).join(c.guardrail_log))}</div>
      <table><tr><th>Status</th><th>Action</th><th>Target</th><th>Detail</th><th></th></tr>{acts}</table>
    </div>
    <h2>Analyst feedback</h2><div class=card>{verdict}</div>
    <h2>Evidence</h2>
    <div class=card>
      rule <b>{a.rule}</b> {html.escape(' '.join(a.mitre))} · source {html.escape(', '.join(sorted(a.all_ips())) or '-')} ({a.geo})
      · users {html.escape(', '.join(a.users))} · hosts {html.escape(', '.join(a.hosts) or '-')} · asset {a.asset_tier}
      · {a.first_seen:%H:%M:%S} to {a.last_seen:%H:%M:%S} ({a.window_sec}s window)
      <div style='color:#9fb3d1;margin-top:6px'>{detail}</div>
      <div class=mono>{html.escape(chr(10).join(f"{e['ts']}  {e['type']:14} {e['user']:12} {e['host']}" for e in a.evidence))}</div>
    </div>
    <h2>Retrieved context (RAG)</h2><div class=card>{docs}</div>
    """
    return _page(a.id, body)


@app.post("/run")
def run_pipeline(user: User = Depends(require("analyst"))):
    run(kb=_kb(), analyzer=get_analyzer(), store=store)
    return RedirectResponse("/", status_code=303)


@app.post("/reindex")
def reindex(user: User = Depends(require("admin"))):
    _kb().sync()
    return RedirectResponse("/", status_code=303)


@app.post("/case/{alert_id}/action/{idx}/approve")
def approve(alert_id: str, idx: int, user: User = Depends(require("analyst"))):
    c = store.get(alert_id) or _404()
    feedback.approve_action(c, idx, store, actor=user.name)
    return RedirectResponse(f"/case/{alert_id}", status_code=303)


@app.post("/case/{alert_id}/action/{idx}/rollback")
def rollback(alert_id: str, idx: int, user: User = Depends(require("analyst"))):
    c = store.get(alert_id) or _404()
    try:
        feedback.rollback_action(c, idx, store, actor=user.name)
    except ValueError as e:
        raise HTTPException(422, str(e)) from None
    return RedirectResponse(f"/case/{alert_id}", status_code=303)


@app.post("/case/{alert_id}/action/{idx}/deny")
def deny(alert_id: str, idx: int, user: User = Depends(require("analyst"))):
    c = store.get(alert_id) or _404()
    feedback.deny_action(c, idx, store, actor=user.name)
    return RedirectResponse(f"/case/{alert_id}", status_code=303)


@app.post("/case/{alert_id}/verdict")
def verdict(alert_id: str, verdict: str = Form(...), note: str = Form(""), reason: str = Form(""),
            suppress: str = Form(""), user: User = Depends(require("analyst"))):
    if verdict not in ("true_positive", "false_positive"):
        raise HTTPException(422, "verdict must be true_positive or false_positive")
    c = store.get(alert_id) or _404()
    try:
        feedback.record_verdict(c, verdict, note, store, _kb(), actor=user.name, reason=reason, suppress=bool(suppress))
    except ValueError as e:
        raise HTTPException(422, str(e)) from None
    return RedirectResponse(f"/case/{alert_id}", status_code=303)


@app.post("/services/collector/event")
async def hec_event(request: Request):
    """Splunk HTTP Event Collector compatible. Point a forwarder or a Splunk HEC output here
    with `Authorization: Splunk <WARDEN_HEC_TOKEN>`. Accepts one JSON object or several
    concatenated, each shaped {"time":..., "sourcetype":..., "event": <str|dict>}."""
    from .adapters.splunk import from_result
    from .config import settings
    from .ingest import normalize

    token = request.headers.get("authorization", "")
    if not settings.hec_token or not hmac.compare_digest(token, f"Splunk {settings.hec_token}"):
        raise HTTPException(401, {"text": "Invalid token", "code": 4})
    body = (await request.body()).decode("utf-8", "replace")
    dec, i, out = json.JSONDecoder(), 0, []
    while i < len(body):
        while i < len(body) and body[i].isspace():
            i += 1
        if i >= len(body):
            break
        try:
            obj, i = dec.raw_decode(body, i)
        except json.JSONDecodeError:
            raise HTTPException(400, {"text": "Invalid data format", "code": 6}) from None
        ev = obj.get("event")
        raw = ev if isinstance(ev, str) else json.dumps(ev)
        e = from_result({"_raw": raw, "_time": obj.get("time"), "sourcetype": obj.get("sourcetype", "hec"),
                         "host": obj.get("host", "")})
        if e is not None:
            out.append(e)
    added = store.add_events(normalize(out))
    return {"text": "Success", "code": 0, "accepted": len(out), "stored": added}


@app.get("/detections", response_class=HTMLResponse)
def detections_view(user: User = Depends(require("viewer"))):
    from .detect import load_all
    from .stats import detection_stats, threshold_bump
    st = detection_stats(store)
    rows = ""
    for d in sorted(load_all().values(), key=lambda d: d.id):
        s = st.get(d.id)
        spark = " ".join(str(w["fired"]) for w in s.weekly) if s else ""
        fpr = f"{s.fp_rate:.0%}" if s and s.fp_rate is not None else "-"
        rows += (f"<tr><td>{d.id}</td><td>{', '.join(d.mitre)}</td><td>{s.fired if s else 0}</td>"
                 f"<td>{s.tp if s else 0}</td><td>{s.fp if s else 0}</td><td>{fpr}</td>"
                 f"<td>{'+' + str(threshold_bump(s)) if threshold_bump(s) else ''}</td>"
                 f"<td>{html.escape(', '.join(s.fp_reasons)) if s else ''}</td><td class=mono>{spark}</td></tr>")
    return _page("Detections", "<p><a href=/>&larr; alerts</a></p><h1>Detection health (30 days)</h1>"
                 "<table><tr><th>Rule</th><th>MITRE</th><th>Fired</th><th>TP</th><th>FP</th><th>FP rate</th>"
                 f"<th>Threshold bump</th><th>FP reasons</th><th>Weekly (oldest first)</th></tr>{rows}</table>")


@app.get("/exclusions", response_class=HTMLResponse)
def exclusions_view(user: User = Depends(require("viewer"))):
    rows = "".join(
        f"<tr><td>#{e['id']}</td><td>{e['rule']}</td><td>{e['field']}={html.escape(e['value'])}</td><td>{e['reason']}</td>"
        f"<td>{html.escape(e['created_by'] or '')}</td><td>{e['expires']:%Y-%m-%d}</td><td>{e['hits']}</td>"
        f"<td><form method=post action='/exclusions/{e['id']}/expire'><button class=secondary>Expire</button></form></td></tr>"
        for e in store.exclusions())
    return _page("Exclusions", "<p><a href=/>&larr; alerts</a></p><h1>Active exclusions</h1><table><tr><th>Id</th>"
                 f"<th>Rule</th><th>Entity</th><th>Reason</th><th>By</th><th>Expires</th><th>Hits</th><th></th></tr>{rows}</table>")


@app.post("/exclusions/{ex_id}/expire")
def expire_exclusion(ex_id: int, user: User = Depends(require("analyst"))):
    store.expire_exclusion(ex_id, user.name)
    return RedirectResponse("/exclusions", status_code=303)


@app.get("/audit", response_class=HTMLResponse)
def audit_view(user: User = Depends(require("viewer"))):
    rows = "".join(f"<tr><td>{r['ts']:%Y-%m-%d %H:%M:%S}</td><td>{html.escape(r['actor'])}</td><td>{r['action']}</td>"
                   f"<td><a href='/case/{html.escape(r['target'])}'>{html.escape(r['target'])}</a></td>"
                   f"<td class=mono>{html.escape(str(r['detail']))}</td></tr>" for r in store.audit_log())
    return _page("Audit", f"<p><a href=/>&larr; alerts</a></p><h1>Audit log</h1>"
                          f"<table><tr><th>When</th><th>Who</th><th>Action</th><th>Case</th><th>Detail</th></tr>{rows}</table>")


@app.get("/api/cases")
def api_cases(user: User = Depends(require("viewer"))):
    return [c.model_dump(mode="json") for c in store.all()]


def _404():
    raise HTTPException(404)
