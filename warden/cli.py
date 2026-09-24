from __future__ import annotations

import argparse
import json
import os
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
    if a.check_attack:
        stale = attack_drift()
        for rule, tid in stale:
            print(f"STALE  {rule}: {tid} is not a current ATT&CK technique")
        print(f"{len(stale)} stale mapping(s) against {settings.attack_dir}")
        raise SystemExit(1 if stale else 0)
    print(f"{'id':<22}{'mitre':<22}{'kinds':<12}{'window':>8}  playbook")
    for d in rows:
        print(f"{d.id:<22}{','.join(d.mitre):<22}{','.join(d.event_kinds):<12}{d.window_sec:>8}  {d.playbook}")
    print(f"\n{len(rows)} detections registered")


def attack_drift() -> list[tuple[str, str]]:
    """Detection mappings that the ingested ATT&CK release no longer has (revoked or renamed)."""
    from .detect import load_all
    live = {p.stem for p in settings.attack_dir.glob("T*.md")}
    if not live:
        return []
    return [(d.id, t) for d in load_all().values() for t in d.mitre if t not in live]


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
    if a.record:
        import subprocess
        from . import db
        from .llm import get_analyzer
        from .store import CaseStore
        try:      # containers have no git; the image can carry the sha in WARDEN_GIT_SHA
            sha = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()[:40]
        except (OSError, subprocess.SubprocessError):
            sha = ""
        sha = sha or os.environ.get("WARDEN_GIT_SHA", "")[:40]
        an = "none" if a.no_llm else getattr(get_analyzer(), "model", "") or type(get_analyzer()).__name__
        with CaseStore().engine.begin() as c:
            c.execute(db.eval_runs.insert().values(ts=db.now(), suite="real" if a.real else "synthetic", git_sha=sha,
                                                   analyzer=an, metrics=rep.to_dict()))
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
    from .governance import retention
    from .store import CaseStore as _CS
    report["retention"] = retention(_CS())
    if not a.skip_baselines:
        from . import baselines
        from .store import CaseStore
        report["baselines"] = baselines.rebuild(CaseStore())
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


def cmd_coverage(a):
    from . import tdl
    c = tdl.coverage()
    if not c["available"]:
        raise SystemExit("no TDL index; run python scripts/sync_tdl.py")
    print(f"{c['covered']}/{c['techniques'] - c['revoked']} TDL techniques covered by {len(__import__('warden').detections.REGISTRY)} detections "
          f"({c['rules']} TDL rules, {c['revoked']} techniques revoked by ATT&CK)\n")
    print(f"{'tactic':24} {'covered':>8} {'techniques':>11} {'tdl rules':>10}")
    for t in c["tactics"]:
        print(f"{t['tactic']:24} {t['covered']:>8} {t['techniques'] - t['revoked']:>11} {t['tdl_rules']:>10}")
    print("\ntop gaps (TDL rules behind them):")
    for g in c["gaps"][:a.limit]:
        print(f"  {g['technique']:10} {g['name'][:44]:46} {g['tdl_rules']:>3}  {g['tactic']}")


def cmd_ingest(a):
    from .ingest import load_file
    from .store import CaseStore
    evs = load_file(Path(a.log), a.format)
    n = CaseStore().add_events(evs)
    span = f", {evs[0].ts:%Y-%m-%d} to {evs[-1].ts:%Y-%m-%d}" if evs else ""
    print(f"stored {n} of {len(evs)} events{span}")


def cmd_baseline(a):
    from . import baselines
    from .store import CaseStore
    store = CaseStore()
    if a.action == "rebuild":
        until = None
        if a.until == "latest":
            evs = store.events()
            until = evs[-1].ts if evs else None
        elif a.until:
            from datetime import datetime
            until = datetime.fromisoformat(a.until)
        n = baselines.rebuild(store, a.days, until)
        end = f"up to {until:%Y-%m-%d}" if until else "up to now"
        print(f"rebuilt {n} profiles from {a.days or settings.baseline_days} days of events {end}")
        return
    profiles = baselines.load_profiles(store)
    if a.entity:
        p = profiles.get((a.type, a.entity))
        if not p:
            raise SystemExit(f"no {a.type} profile for {a.entity}")
        print(f"{a.type} {a.entity}: {p.days} days")
        for n, vals in p.numeric.items():
            if vals:
                print(f"  {n:22} mean {sum(vals) / len(vals):8.1f}  last {vals[-1]:g}")
        for f, seen in p.seen.items():
            print(f"  {f:22} {len(seen)} known: {', '.join(sorted(seen, key=lambda v: -seen[v])[:8])}")
        return
    by = {}
    for (t, _), p in profiles.items():
        by.setdefault(t, []).append(p.days)
    for t, days in sorted(by.items()):
        print(f"{t:5} {len(days):5} profiles, median {sorted(days)[len(days) // 2]} days of history")


def cmd_propose(a):
    """Generate detection proposals with Claude. Needs a working ANTHROPIC_API_KEY."""
    from . import proposals
    from .store import CaseStore
    store = CaseStore()
    if a.gaps:
        for g in proposals.gaps(a.limit):
            print(f"{g['technique']:12} {g['title'][:60]:62} {g['tactics'][:30]:32} groups {g['groups']}")
        return
    todo = []
    if a.events:
        from .ingest import load_file
        todo.append(("hunt", load_file(Path(a.events)), a.note or "analyst-confirmed malicious activity; no rule fired",
                     [], a.events))
    if a.case:
        c = store.get(a.case)
        if not c:
            raise SystemExit(f"no case {a.case}")
        evs = [e for e in store.events(since=c.alert.first_seen, until=c.alert.last_seen)
               if (e.user and e.user in c.alert.users) or (e.host and e.host in c.alert.hosts)
               or (e.source_ip and e.source_ip in c.alert.all_ips())]
        todo.append(("anomaly_tp" if c.alert.rule.startswith("anomaly.") else "analyst_note", evs,
                     f"analyst confirmed true positive on {c.alert.id}: {c.alert.title}. {c.analyst_note}", c.alert.mitre, c.alert.id))
    if a.pending:
        for r in proposals.list_proposals(store.engine):
            if r["status"] == "requested":
                c = store.get(r["source"])
                if c:
                    evs = [e for e in store.events(since=c.alert.first_seen, until=c.alert.last_seen)
                           if (e.user and e.user in c.alert.users) or (e.host and e.host in c.alert.hosts)]
                    todo.append((r["trigger"], evs, f"{c.alert.title}. {c.analyst_note}", c.alert.mitre, c.alert.id))
    for t in a.technique or []:
        todo.append(("intel_gap", [], f"ATT&CK technique {t} has detection guidance and no Warden rule.", [t], t))
    for trigger, evs, why, techs, source in todo:
        pid = proposals.create(trigger, evs, context_query=why, techniques=techs, store=store, source=str(source))
        p = proposals.get(pid, store.engine)
        print(f"{pid}  {p['status']:18} {p['rule_id']}  ${p['cost_usd'] or 0:.3f}")


def cmd_proposals(a):
    from . import proposals
    from .store import CaseStore
    store = CaseStore()
    if a.id and a.decision == "recheck":
        print(proposals.recheck(a.id, store=store))
        return
    if a.id and a.decision:
        print(proposals.review(a.id, a.decision, a.actor, a.note or "", store=store, open_pr=not a.no_pr))
        return
    if a.id:
        p = proposals.get(a.id, store.engine)
        print(json.dumps({k: v for k, v in p.items() if k != "files"}, indent=2, default=str))
        for path, content in (p["files"] or {}).items():
            print(f"\n===== {path}\n{content}")
        return
    for p in proposals.list_proposals(store.engine):
        print(f"{p['id']}  {p['status']:18} {p['rule_id'] or '':32} {p['trigger']:13} {p['pr_url'] or ''}")


def cmd_demo(a):
    """Load a representative set of labeled scenarios into the store so the console has
    something real to show: identity chains, endpoint and cloud incidents, a planted
    anomaly, benign noise. Mock analyzer unless an API key is configured."""
    from . import evaluate
    from .ingest import load_file
    from .knowledge import KnowledgeBase
    from .llm import get_analyzer
    from .pipeline import run
    from .store import CaseStore
    store = CaseStore()
    kb = KnowledgeBase()
    kb.sync()
    picks = ["01-", "04-", "05-", "07-", "09-", "13-", "18-", "19-", "20-", "21-", "24-", "26-", "27-", "29-"]
    n = 0
    for c in evaluate.discover():
        if not any(c.events_file.parent.name.startswith(p) for p in picks):
            continue
        if c.history_file:
            store.add_events(load_file(c.history_file))
        n += len(run(events=load_file(c.events_file), kb=kb, analyzer=get_analyzer(), store=store))
    print(f"loaded {n} cases; start the console with `warden serve`")


def cmd_serve(a):
    import uvicorn
    uvicorn.run("warden.dashboard:app", host=a.host, port=a.port, reload=False)


def main(argv=None):
    p = argparse.ArgumentParser(prog="warden")
    p.add_argument("--tenant", default=None, help="tenant to act as (default WARDEN_TENANT)")
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
    r.add_argument("--format", default=None, help="force an adapter: windows, crowdstrike, okta, entra, cloudtrail, splunk, elastic, sshd, generic")
    r.add_argument("--rerun", action="store_true", help="re-analyze alerts that already have cases")
    r.add_argument("--detections", default=None, help="comma list, restrict which rules run")
    r.add_argument("--from-db", action="store_true", help="detect over stored events (HEC, earlier imports)")
    r.add_argument("--since", default=None, help="with --from-db: e.g. 24h, 7d, or an ISO timestamp")
    r.set_defaults(fn=cmd_run)

    d = sub.add_parser("detections", help="list the registered detections")
    d.add_argument("--check-attack", action="store_true", help="exit 1 if any mapping is not a current ATT&CK technique")
    d.set_defaults(fn=cmd_detections)

    e = sub.add_parser("eval", help="score the pipeline against labeled fixtures")
    e.add_argument("--dir", default=None, help=f"eval case root (default {settings.eval_dir})")
    e.add_argument("--real", action="store_true", help="run the real-log suite in data/eval-real")
    e.add_argument("--detections", default=None, help="comma list, restrict which rules run")
    e.add_argument("--no-llm", action="store_true", help="detection metrics only, skip RAG and the model")
    e.add_argument("--json", action="store_true")
    e.add_argument("--fail-under", type=float, default=None, help="exit 1 if overall f1 is below this")
    e.add_argument("--record", action="store_true", help="store the result for the console's eval history")
    e.set_defaults(fn=cmd_eval)

    ai = sub.add_parser("attack-ingest", help="pull the MITRE ATT&CK STIX bundle into the knowledge base")
    ai.add_argument("--url", default=None, help="override the enterprise-attack bundle URL")
    ai.add_argument("--file", default=None, help="use a local bundle instead of downloading")
    ai.add_argument("--no-index", action="store_true", help="write docs to disk but skip embedding")
    ai.set_defaults(fn=cmd_attack_ingest)

    rf = sub.add_parser("refresh", help="nightly: ATT&CK + intel feeds + KB sync + snapshot")
    rf.add_argument("--skip-attack", action="store_true")
    rf.add_argument("--skip-intel", action="store_true")
    rf.add_argument("--skip-baselines", action="store_true")
    rf.set_defaults(fn=cmd_refresh)

    rp = sub.add_parser("replay", help="re-run a case's analysis on its recorded inputs and diff")
    rp.add_argument("case_id")
    rp.set_defaults(fn=cmd_replay)

    cv = sub.add_parser("coverage", help="ATT&CK coverage against the TDL library (scripts/sync_tdl.py)")
    cv.add_argument("--limit", type=int, default=10)
    cv.set_defaults(fn=cmd_coverage)

    ig = sub.add_parser("ingest", help="store a log file's events without detection or LLM calls")
    ig.add_argument("--log", required=True)
    ig.add_argument("--format", default=None)
    ig.set_defaults(fn=cmd_ingest)

    bl = sub.add_parser("baseline", help="behavioral baselines: rebuild (nightly) or show")
    bl.add_argument("action", choices=["rebuild", "show"])
    bl.add_argument("--days", type=int, default=None)
    bl.add_argument("--until", default=None, help="'latest' (last stored event) or an ISO time; default now")
    bl.add_argument("--type", choices=["user", "host"], default="user")
    bl.add_argument("--entity", default=None)
    bl.set_defaults(fn=cmd_baseline)

    pr = sub.add_parser("propose", help="have Claude propose a detection from evidence, a case, or an ATT&CK gap")
    pr.add_argument("--events", default=None, help="log file of confirmed-malicious activity no rule caught")
    pr.add_argument("--note", default=None)
    pr.add_argument("--case", default=None, help="a true-positive case id")
    pr.add_argument("--technique", action="append", help="ATT&CK id with no rule (repeatable)")
    pr.add_argument("--pending", action="store_true", help="process proposal requests queued by analyst verdicts")
    pr.add_argument("--gaps", action="store_true", help="list uncovered techniques that have detection guidance")
    pr.add_argument("--limit", type=int, default=20)
    pr.set_defaults(fn=cmd_propose)

    pq = sub.add_parser("proposals", help="list, show, approve, or reject detection proposals")
    pq.add_argument("id", nargs="?")
    pq.add_argument("decision", nargs="?", choices=["approve", "reject", "recheck"])
    pq.add_argument("--actor", default="cli")
    pq.add_argument("--note", default=None)
    pq.add_argument("--no-pr", action="store_true", help="approve without opening a pull request")
    pq.set_defaults(fn=cmd_proposals)

    dm = sub.add_parser("demo", help="load sample scenarios so the console has cases to show")
    dm.set_defaults(fn=cmd_demo)

    hp = sub.add_parser("hash-password", help="hash a password for WARDEN_USERS")
    hp.add_argument("--password", default=None, help="omit to be prompted")
    hp.set_defaults(fn=cmd_hash_password)

    s = sub.add_parser("serve", help="start the SOC dashboard")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    s.set_defaults(fn=cmd_serve)

    a = p.parse_args(argv)
    if a.tenant:
        settings.tenant = a.tenant
    a.fn(a)


if __name__ == "__main__":
    main()
