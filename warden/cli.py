from __future__ import annotations

import argparse
from pathlib import Path

from .config import settings


def cmd_gen_logs(a):
    from .ingest import generate_logs
    n = generate_logs(Path(a.out), events=a.events, attackers=a.attackers)
    print(f"wrote {n} events to {a.out}")


def cmd_index(a):
    from .knowledge import KnowledgeBase
    n = KnowledgeBase().index_dir()
    print(f"indexed {n} chunks from {settings.knowledge_dir}")


def cmd_run(a):
    from .pipeline import run
    only = [d.strip() for d in a.detections.split(',')] if a.detections else None
    cases = run(Path(a.log) if a.log else None, rerun=a.rerun, only=only)
    if not cases:
        print("no alerts")
        return
    for c in cases:
        al, an = c.alert, c.analysis
        print(f"\n=== {al.id}  {al.title}")
        print(f"    rule={al.rule} attempts={al.failed_attempts} users={al.users} hosts={al.hosts} geo={al.geo} asset={al.asset_tier}")
        print(f"    retrieved: {[d['id'] for d in c.retrieved_docs]}")
        print(f"    LLM: {an.mitre_attack} | risk {an.risk_score} | {an.severity} | FP {an.false_positive_likelihood}")
        print(f"         {an.explanation}")
        for line in c.guardrail_log:
            print(f"    guardrail: {line}")
        for r in c.actions:
            print(f"    action: {r.status:16} {r.action}({r.target}) {r.detail}")
        print(f"    status: {c.status}")


def cmd_detections(a):
    from .detect import load_all
    rows = sorted(load_all().values(), key=lambda d: d.id)
    print(f"{'id':<22}{'mitre':<22}{'kinds':<12}{'window':>8}  playbook")
    for d in rows:
        print(f"{d.id:<22}{','.join(d.mitre):<22}{','.join(d.event_kinds):<12}{d.window_sec:>8}  {d.playbook}")
    print(f"\n{len(rows)} detections registered")


def cmd_eval(a):
    import json as _json
    from . import evaluate
    root = Path(a.dir) if a.dir else None
    cases = evaluate.discover(root)
    if not cases:
        print(f"no eval cases found in {root or settings.eval_dir}")
        raise SystemExit(1)
    only = [d.strip() for d in a.detections.split(",")] if a.detections else None
    rep = evaluate.run(cases, with_llm=not a.no_llm, only=only)
    if a.json:
        print(_json.dumps(rep.to_dict(), indent=2))
    else:
        print(evaluate.format_report(rep, cases))
    if a.fail_under is not None and rep.overall.f1 < a.fail_under:
        print(f"\nFAIL: overall f1 {rep.overall.f1:.3f} < {a.fail_under}")
        raise SystemExit(1)


def cmd_attack_ingest(a):
    from .attack import ingest
    n_tech, n_chunks = ingest(url=a.url, file=Path(a.file) if a.file else None, index=not a.no_index)
    print(f"ingested {n_tech} techniques, {n_chunks} chunks")


def cmd_serve(a):
    import uvicorn
    uvicorn.run("warden.dashboard:app", host=a.host, port=a.port, reload=False)


def main(argv=None):
    p = argparse.ArgumentParser(prog="warden")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gen-logs", help="generate synthetic auth logs with embedded attacks")
    g.add_argument("--out", default=str(settings.log_file))
    g.add_argument("--events", type=int, default=600)
    g.add_argument("--attackers", type=int, default=2)
    g.set_defaults(fn=cmd_gen_logs)

    i = sub.add_parser("index", help="(re)build the knowledge base")
    i.set_defaults(fn=cmd_index)

    r = sub.add_parser("run", help="run detection -> RAG -> LLM -> guardrails -> actions")
    r.add_argument("--log", default=None)
    r.add_argument("--rerun", action="store_true", help="re-analyze alerts that already have cases")
    r.add_argument("--detections", default=None, help="comma list, restrict which rules run")
    r.set_defaults(fn=cmd_run)

    d = sub.add_parser("detections", help="list the registered detections")
    d.set_defaults(fn=cmd_detections)

    e = sub.add_parser("eval", help="score the pipeline against labeled fixtures")
    e.add_argument("--dir", default=None, help=f"eval case root (default {settings.eval_dir})")
    e.add_argument("--detections", default=None, help="comma list, restrict which rules run")
    e.add_argument("--no-llm", action="store_true", help="detection metrics only, skip RAG and the model")
    e.add_argument("--json", action="store_true")
    e.add_argument("--fail-under", type=float, default=None, help="exit 1 if overall f1 is below this")
    e.set_defaults(fn=cmd_eval)

    ai = sub.add_parser("attack-ingest", help="pull the MITRE ATT&CK STIX bundle into the knowledge base")
    ai.add_argument("--url", default=None, help="override the enterprise-attack bundle URL")
    ai.add_argument("--file", default=None, help="use a local bundle instead of downloading")
    ai.add_argument("--no-index", action="store_true", help="write docs to disk but skip embedding")
    ai.set_defaults(fn=cmd_attack_ingest)

    s = sub.add_parser("serve", help="start the SOC dashboard")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    s.set_defaults(fn=cmd_serve)

    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
