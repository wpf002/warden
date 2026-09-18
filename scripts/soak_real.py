"""Two-week anomaly soak on real traffic: Phase 5's exit criterion without two weeks of wall
clock. Replays the real Loghub OpenSSH log (scripts/fetch_baseline_logs.py) one day at a
time through the full pipeline (detect -> correlate -> analyze -> guardrails -> store):
the first 10 days build the baselines, the last 14 are scored.

The traffic is real; the analyst is simulated. Two account takeovers are planted (a
regular user logging in from a new network at 03:00 after a password burst); every other
anomaly case is closed as a false positive, which absorbs it into the baseline, and a
repeat offender is muted. The mock analyzer is used, so this makes no API calls.

    python scripts/soak_real.py      # daily table, writes data/soak/anomaly-soak-real.json
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from collections import defaultdict
from datetime import datetime, time, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("WARDEN_LLM", "mock")
os.environ.setdefault("WARDEN_EMBEDDINGS", "hash")

from warden.config import settings  # noqa: E402

TMP = Path(tempfile.mkdtemp(prefix="warden-soak-real-"))
settings.data_dir = TMP
(TMP / "knowledge").mkdir(parents=True)

from warden import baselines, feedback  # noqa: E402
from warden.events import AuthEvent  # noqa: E402
from warden.ingest import load_file  # noqa: E402
from warden.knowledge import KnowledgeBase  # noqa: E402
from warden.llm import MockAnalyzer  # noqa: E402
from warden.pipeline import run  # noqa: E402
from warden.store import CaseStore  # noqa: E402

LOG = ROOT / "data" / "real" / "baseline" / "SSH.log"
PLANTED = {4: "curi", 10: "fztu"}          # soak day index -> user taken over


def takeover(day, user, host):
    at = datetime.combine(day, time(3, 0), tzinfo=datetime.now().astimezone().tzinfo).astimezone()
    ip = "45.155.205.17"
    evs = [AuthEvent(ts=at + timedelta(seconds=i), source="sshd", host=host, user=user, source_ip=ip,
                     event_type="login_failure", logon_type="remote_interactive") for i in range(40)]
    return evs + [AuthEvent(ts=at + timedelta(minutes=1), source="sshd", host=host, user=user, source_ip=ip,
                            event_type="login_success", logon_type="remote_interactive")]


def main() -> int:
    if not LOG.exists():
        print("run scripts/fetch_baseline_logs.py first", file=sys.stderr)
        return 2
    by = defaultdict(list)
    for e in load_file(LOG, "sshd"):
        by[e.ts.date()].append(e)
    days = sorted(by)
    base, soak = days[:-14], days[-14:]
    store = CaseStore(TMP / "state")
    kb = KnowledgeBase(persist=False)
    kb.index_dir(ROOT / "data" / "knowledge")
    store.add_events([e for d in base for e in by[d]])
    baselines.save_profiles(store, baselines.build_profiles(store.events()))
    print(f"baseline {base[0]} .. {base[-1]} ({len(base)} days), soak {soak[0]} .. {soak[-1]}")

    rows, seen_fp = [], {}
    host = by[days[0]][0].host
    for k, d in enumerate(soak):
        extra = takeover(d, PLANTED[k], host) if k in PLANTED else []
        evs = sorted(by[d] + [e.model_copy(update={"ts": e.ts.astimezone(by[d][0].ts.tzinfo)}) for e in extra],
                     key=lambda e: e.ts)
        cases = run(events=evs, kb=kb, analyzer=MockAnalyzer(), store=store)
        anomalies = [c for c in cases if any(r.startswith("anomaly.") for r in c.alert.rules()) and c.status != "closed"]
        tp = fp = 0
        for c in anomalies:
            ents = {m.detail.get("entity") for m in (c.alert.members or [c.alert]) if m.detail.get("entity")}
            if k in PLANTED and PLANTED[k] in ents:
                tp += 1
                feedback.record_verdict(c, "true_positive", "planted takeover", store, kb, actor="sim-analyst")
            else:
                fp += 1
                repeat = any(seen_fp.get(e, 0) for e in ents)
                feedback.record_verdict(c, "false_positive", "internet noise", store, kb, actor="sim-analyst",
                                        reason="other", suppress=repeat)
                for e in ents:
                    seen_fp[e] = seen_fp.get(e, 0) + 1
            if os.environ.get("SOAK_DEBUG"):
                for m in (c.alert.members or [c.alert]):
                    if m.detail.get("source") == "anomaly":
                        print("     ", m.detail["entity"], m.detail["score"],
                              " | ".join(x["why"][:60] for x in m.detail["contributions"][:3]))
        rows.append({"day": str(d), "events": len(evs), "anomaly_cases": len(anomalies), "tp": tp, "fp": fp,
                     "planted_caught": (tp > 0) if k in PLANTED else None})
        print(f"{d}  events {len(evs):6d}  anomaly cases {len(anomalies):2d}  TP {tp}  FP {fp:2d}"
              + (f"  planted takeover {'CAUGHT' if tp else 'MISSED'}" if k in PLANTED else ""))
    wk1, wk2 = sum(r["fp"] for r in rows[:7]), sum(r["fp"] for r in rows[7:])
    summary = {"week1_fp": wk1, "week2_fp": wk2, "planted": len(PLANTED),
               "planted_caught": sum(1 for r in rows if r["planted_caught"]), "days": rows,
               "note": "real Loghub OpenSSH traffic, simulated analyst; see scripts/soak_real.py"}
    out = ROOT / "data" / "soak"
    out.mkdir(parents=True, exist_ok=True)
    (out / "anomaly-soak-real.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"\nFP week 1: {wk1}   FP week 2: {wk2}   planted takeovers caught: {summary['planted_caught']}/{len(PLANTED)}")
    return 0 if wk2 <= wk1 and summary["planted_caught"] == len(PLANTED) else 1


if __name__ == "__main__":
    sys.exit(main())
