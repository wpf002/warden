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
    cases = run(Path(a.log) if a.log else None, rerun=a.rerun)
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
    r.set_defaults(fn=cmd_run)

    s = sub.add_parser("serve", help="start the SOC dashboard")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    s.set_defaults(fn=cmd_serve)

    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
