"""Two-week anomaly soak, simulated. Phase 5 exit criterion: FP rate trending down.

A 40-person organisation with 30 days of routine history, then 14 days scored one at a
time through the real pipeline (detect -> correlate -> analyze -> guardrails -> store).
Each day carries ordinary change that the baselines have never seen - people joining
projects, a software rollout, a sysadmin's maintenance window - and two days carry a
planted reconnaissance run. A simulated analyst closes every anomaly case: planted ones as
true positives, the rest as false positives with a reason. False positives teach the
baseline (absorb) and repeat offenders get muted.

    python scripts/soak_anomaly.py            # prints the daily table, writes data/soak/anomaly-soak.json

This is a simulation with scripted behaviour, not a production soak. It shows the
feedback loop works mechanically; real FP rates come from real logs.
"""
from __future__ import annotations

import json
import os
import random
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("WARDEN_LLM", "mock")
os.environ.setdefault("WARDEN_EMBEDDINGS", "hash")

from warden.config import settings  # noqa: E402

TMP = Path(tempfile.mkdtemp(prefix="warden-soak-"))
settings.data_dir = TMP
(TMP / "knowledge").mkdir(parents=True)

from warden import feedback  # noqa: E402
from warden.events import parse_event  # noqa: E402
from warden.ingest import normalize  # noqa: E402
from warden.knowledge import KnowledgeBase  # noqa: E402
from warden.llm import MockAnalyzer  # noqa: E402
from warden.pipeline import run  # noqa: E402
from warden.store import CaseStore  # noqa: E402

PEOPLE = [f"u{i:02d}" for i in range(40)]
SERVERS = [f"srv-{i:02d}" for i in range(30)]
APPS = ["outlook.exe", "chrome.exe", "teams.exe", "excel.exe", "winword.exe", "onedrive.exe"]
DAY0 = datetime(2026, 7, 1, tzinfo=timezone.utc)


def ev(kind, ts, **kw):
    return parse_event({"kind": kind, "ts": ts.isoformat(), "source": "sim", **kw})


class World:
    def __init__(self, seed=7):
        self.rng = random.Random(seed)
        self.home = {p: self.rng.sample(SERVERS, 2) for p in PEOPLE}
        self.apps = {p: set(APPS) for p in PEOPLE}

    def day(self, d: datetime, extra=()):
        r, out = self.rng, []
        for i, p in enumerate(PEOPLE):
            ws, ip = f"ws-{p}", f"10.1.{i // 250}.{i % 250 + 1}"
            for _ in range(r.randint(3, 6)):
                t = d + timedelta(hours=r.randint(8, 17), minutes=r.randint(0, 59))
                out.append(ev("auth", t, event_type="login_success", user=p, source_ip=ip, geo="internal",
                              host=r.choice([ws, ws, *self.home[p]]), logon_type="network"))
            for _ in range(r.randint(5, 9)):
                t = d + timedelta(hours=r.randint(8, 17), minutes=r.randint(0, 59))
                app = r.choice(sorted(self.apps[p]))
                out.append(ev("process", t, action="start", host=ws, user=p, parent_name="explorer.exe",
                              process_name=app, command_line=app, pid=r.randint(1000, 60000)))
        return out + list(extra)


def benign_change(w: World, d: datetime, k: int):
    """Ordinary change the baseline has not seen: project moves, a rollout, maintenance."""
    r, out = w.rng, []
    for p in r.sample(PEOPLE, 3):                               # joins a project: 4 new servers, a new tool
        new = r.sample([s for s in SERVERS if s not in w.home[p]], 4)
        for s in new:
            out.append(ev("auth", d + timedelta(hours=r.randint(9, 16)), event_type="login_success", user=p,
                          source_ip="10.1.0.200", geo="internal", host=s, logon_type="network"))
        out.append(ev("process", d + timedelta(hours=10), action="start", host=f"ws-{p}", user=p,
                      parent_name="explorer.exe", process_name="dbeaver.exe", command_line="dbeaver.exe", pid=77))
        w.home[p] += new[:2]                                    # half of it becomes their new normal
    if k in (3, 4):                                             # a rollout lands on a third of the staff
        for p in PEOPLE[: 14 if k == 3 else 28]:
            w.apps[p].add("zoom.exe")
    if k % 5 == 2:                                              # the sysadmin's maintenance night
        for n, s in enumerate(r.sample(SERVERS, 10)):
            out.append(ev("auth", d + timedelta(hours=1, minutes=n * 3), event_type="login_success", user="u00",
                          source_ip="10.1.0.1", geo="internal", host=s, logon_type="network"))
    return out


def recon(d: datetime, who: str):
    out = []
    for n, s in enumerate(["dc-01", "dc-02", "ca-01", "fin-db-01", "hr-app-01", "vcenter-01", "backup-01"]):
        out.append(ev("auth", d + timedelta(hours=3, minutes=n * 3), event_type="login_success", user=who,
                      source_ip="10.1.0.66", geo="internal", host=s, logon_type="network"))
    for n, (name, cmd) in enumerate([("nltest.exe", "nltest /dclist:"), ("adfind.exe", "adfind -f objectcategory=computer"),
                                     ("net.exe", 'net group "domain admins" /domain')]):
        out.append(ev("process", d + timedelta(hours=3, minutes=2 + n * 5), action="start", host=f"ws-{who}", user=who,
                      parent_name="cmd.exe", process_name=name, command_line=cmd, pid=900 + n))
    return out


def main():
    w = World()
    store = CaseStore(TMP / "state")
    kb = KnowledgeBase(persist=False)
    kb.index_dir(ROOT / "data" / "knowledge")
    # 30 days of history straight into the event store, then baselines built from it
    history = []
    for n in range(30):
        history += w.day(DAY0 + timedelta(days=n))
    store.add_events(normalize(history))
    from warden import baselines
    baselines.save_profiles(store, baselines.build_profiles(store.events()))

    planted = {5: "u17", 11: "u29"}
    rows = []
    seen_fp: dict[str, int] = {}      # the analyst remembers who was a false positive before
    for k in range(14):
        d = DAY0 + timedelta(days=30 + k)
        extra = benign_change(w, d, k) + (recon(d, planted[k]) if k in planted else [])
        cases = run(events=normalize(w.day(d, extra)), kb=kb, analyzer=MockAnalyzer(), store=store)
        anomalies = [c for c in cases if any(r.startswith("anomaly.") for r in c.alert.rules()) and c.status != "closed"]
        tp = fp = 0
        for c in anomalies:
            ents = {m.detail.get("entity") for m in (c.alert.members or [c.alert])}
            is_attack = k in planted and (planted[k] in ents or f"ws-{planted[k]}" in ents)
            if is_attack:
                tp += 1
                feedback.record_verdict(c, "true_positive", "planted recon", store, kb, actor="sim-analyst")
            else:
                fp += 1
                repeat = any(seen_fp.get(e, 0) for e in ents)   # second time: mute it
                feedback.record_verdict(c, "false_positive", "project change", store, kb, actor="sim-analyst",
                                        reason="other", suppress=repeat)
                for e in ents:
                    seen_fp[e] = seen_fp.get(e, 0) + 1
        if os.environ.get("SOAK_DEBUG"):
            for c in anomalies:
                for m in (c.alert.members or [c.alert]):
                    if m.detail.get("source") == "anomaly":
                        print("     ", k + 1, m.detail["entity"], round(m.detail["score"], 1), " | ".join(x["why"][:60] for x in m.detail["contributions"][:3]))
        rows.append({"day": k + 1, "anomaly_cases": len(anomalies), "tp": tp, "fp": fp,
                     "planted_caught": (tp > 0) if k in planted else None})
        print(f"day {k + 1:2d}  anomaly cases {len(anomalies):3d}  TP {tp}  FP {fp:3d}"
              + (f"  planted recon {'CAUGHT' if tp else 'MISSED'}" if k in planted else ""))
    wk1 = sum(r["fp"] for r in rows[:7])
    wk2 = sum(r["fp"] for r in rows[7:])
    summary = {"week1_fp": wk1, "week2_fp": wk2, "planted": len(planted),
               "planted_caught": sum(1 for r in rows if r["planted_caught"]), "days": rows,
               "note": "simulated soak with scripted behaviour; see scripts/soak_anomaly.py"}
    out = ROOT / "data" / "soak"
    out.mkdir(parents=True, exist_ok=True)
    (out / "anomaly-soak.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"\nFP week 1: {wk1}   FP week 2: {wk2}   planted recon caught: {summary['planted_caught']}/{len(planted)}")
    return 0 if wk2 < wk1 and summary["planted_caught"] == len(planted) else 1


if __name__ == "__main__":
    raise SystemExit(main())
