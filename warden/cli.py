from __future__ import annotations

import argparse
from pathlib import Path

from .config import settings


def _since(v):
    if not v:
        return None
    from datetime import datetime, timedelta, timezone
    units = {"m": "minutes", "h": "hours", "d": "days"}
    if v[-1] in units and v[:-1].isdigit():
        return datetime.now(timezone.utc) - timedelta(**{units[v[-1]]: int(v[:-1])})
    return datetime.fromisoformat(v)


def cmd_gen_logs(a):
    from .ingest import generate_logs
    n = generate_logs(Path(a.out), events=a.events, attackers=a.attackers)
    print(f"wrote {n} events to {a.out}")


def cmd_index(a):
    from .knowledge import KnowledgeBase
    r = KnowledgeBase().sync()
    print(f"re-embedded {len(r['indexed'])} docs, removed {len(r['removed'])}, from {settings.knowledge_dir}")


def cmd_run(a):
    from .pipeline import run
    only = [d.strip() for d in a.detections.split(',')] if a.detections else None
    if a.from_db:
        from .pipeline import run_stored
        cases = run_stored(since=_since(a.since), rerun=a.rerun, only=only)
    else:
        cases = run(Path(a.log) if a.log else None, rerun=a.rerun, only=only, fmt=a.format)
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
    root = Path(a.dir) if a.dir else (settings.data_dir / "eval-real" if a.real else None)
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


def cmd_hash_password(a):
    import getpass
    from .auth import hash_password
    pw = a.password or getpass.getpass("password: ")
    print(hash_password(pw))


def cmd_refresh(a):
    """Nightly job: ATT&CK, intel feeds, KB sync, snapshot. Safe to run unattended; a
    failing source is reported and skipped. Exit 1 only if every source failed."""
    import json as _json
    from . import intel
    from .attack import ingest
    from .knowledge import KnowledgeBase

    kb = KnowledgeBase()
    synced = kb.sync()
    report: dict = {"kb": {"reembedded": len(synced["indexed"]), "removed": len(synced["removed"])}}
    if not a.skip_attack:
        try:
            n_tech, n_chunks = ingest(kb=kb)
            report["attack"] = {"techniques": n_tech, "chunks": n_chunks}
        except Exception as e:  # noqa: BLE001
            report["attack"] = {"error": f"{type(e).__name__}: {e}"}
    if not a.skip_intel:
        report["intel"] = intel.refresh(kb=kb)
    report["snapshot"] = kb.record_snapshot()
    print(_json.dumps(report, indent=2, default=str))
    sources = [report.get("attack", {})] + list(report.get("intel", {}).values())
    if sources and all("error" in x for x in sources if x):
        raise SystemExit(1)


def cmd_replay(a):
    """Re-send a case's exact inputs (alert, retrieved text, prompt) and compare outputs."""
    from .llm import PROMPT_VERSION, get_analyzer
    from .stats import detection_stats
    from .store import CaseStore

    store = CaseStore()
    c = store.get(a.case_id)
    if not c or not c.analysis:
        raise SystemExit(f"no analyzed case {a.case_id}")
    if c.prompt_version != PROMPT_VERSION:
        print(f"note: case used {c.prompt_version}, current prompt is {PROMPT_VERSION}; "
              f"check out the matching commit for an exact replay")
    stats = detection_stats(store)
    track = [stats[r].as_prior() for r in dict.fromkeys(c.alert.rules()) if r in stats]
    new = get_analyzer().analyze(c.alert, c.retrieved_docs, {"track_record": track})
    old = c.analysis
    rows = [("risk", old.risk_score, new.risk_score), ("severity", old.severity, new.severity),
            ("fp likelihood", old.false_positive_likelihood, new.false_positive_likelihood),
            ("actions", sorted(f"{x.action}:{x.target}" for x in old.recommended_actions),
             sorted(f"{x.action}:{x.target}" for x in new.recommended_actions))]
    print(f"replay {c.alert.id}  kb {c.kb_snapshot}  prompt {c.prompt_version}  model {c.model}")
    for name, o, n in rows:
        print(f"  {'=' if o == n else '!'} {name:14} {o}  ->  {n}")


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
    r.add_argument("--format", default=None, help="force an adapter: windows, okta, entra, cloudtrail, splunk, elastic, sshd, generic")
    r.add_argument("--rerun", action="store_true", help="re-analyze alerts that already have cases")
    r.add_argument("--detections", default=None, help="comma list, restrict which rules run")
    r.add_argument("--from-db", action="store_true", help="detect over stored events (HEC, earlier imports)")
    r.add_argument("--since", default=None, help="with --from-db: e.g. 24h, 7d, or an ISO timestamp")
    r.set_defaults(fn=cmd_run)

    d = sub.add_parser("detections", help="list the registered detections")
    d.set_defaults(fn=cmd_detections)

    e = sub.add_parser("eval", help="score the pipeline against labeled fixtures")
    e.add_argument("--dir", default=None, help=f"eval case root (default {settings.eval_dir})")
    e.add_argument("--real", action="store_true", help="run the real-log suite in data/eval-real")
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

    rf = sub.add_parser("refresh", help="nightly: ATT&CK + intel feeds + KB sync + snapshot")
    rf.add_argument("--skip-attack", action="store_true")
    rf.add_argument("--skip-intel", action="store_true")
    rf.set_defaults(fn=cmd_refresh)

    rp = sub.add_parser("replay", help="re-run a case's analysis on its recorded inputs and diff")
    rp.add_argument("case_id")
    rp.set_defaults(fn=cmd_replay)

    hp = sub.add_parser("hash-password", help="hash a password for WARDEN_USERS")
    hp.add_argument("--password", default=None, help="omit to be prompted")
    hp.set_defaults(fn=cmd_hash_password)

    s = sub.add_parser("serve", help="start the SOC dashboard")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    s.set_defaults(fn=cmd_serve)

    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
