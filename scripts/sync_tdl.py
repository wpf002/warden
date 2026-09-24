"""Build the TDL coverage index Warden reads.

TDL (github.com/wpf002/tdl) is the Threat Detection Library: 800+ ATT&CK-mapped rules with
native queries for ten SIEMs. Warden doesn't run those queries; it uses their technique
mappings to show which of TDL's techniques its own detections cover, and to aim
`warden propose` at the gaps.

    python scripts/sync_tdl.py [--tdl ../tdl]

Writes data/tdl/index.json: one small record per TDL rule, no queries.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "tdl" / "index.json"
KEEP = ("rule_id", "name", "tactic", "tactic_id", "technique_id", "technique_name",
        "severity", "lifecycle", "platform", "data_sources")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tdl", default=str(ROOT.parent / "tdl"), help="path to the tdl checkout")
    a = ap.parse_args()
    import yaml
    src = Path(a.tdl) / "rules"
    if not src.is_dir():
        print(f"no rules directory at {src}", file=sys.stderr)
        return 2
    rules = []
    for f in sorted(src.rglob("*.yaml")):
        try:
            doc = yaml.safe_load(f.read_text())
        except yaml.YAMLError as e:
            print(f"skip {f.name}: {e}", file=sys.stderr)
            continue
        if not isinstance(doc, dict) or not doc.get("technique_id"):
            continue
        rules.append({k: doc.get(k) for k in KEEP})
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({"source": "tdl", "rules": rules}, indent=1, sort_keys=True) + "\n")
    techs = {r["technique_id"] for r in rules}
    print(f"{len(rules)} TDL rules, {len(techs)} techniques -> {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
