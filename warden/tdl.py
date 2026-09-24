"""Coverage against TDL, the Threat Detection Library (821 ATT&CK-mapped rules).

Warden does not run TDL's SIEM queries. It reads their technique mappings
(data/tdl/index.json, built by scripts/sync_tdl.py) to answer one question per technique:
does a Warden detection cover it? Uncovered techniques with TDL rules behind them are the
best-evidenced gaps, so `warden propose --gaps` ranks them first.
"""
from __future__ import annotations

import json
from collections import defaultdict
from functools import lru_cache
from pathlib import Path

from .config import settings


def index_path() -> Path:
    return Path(settings.data_dir) / "tdl" / "index.json"


@lru_cache(maxsize=1)
def _load(path: str, mtime: float) -> list[dict]:
    return json.loads(Path(path).read_text()).get("rules", [])


def rules() -> list[dict]:
    p = index_path()
    if not p.exists():
        return []
    return _load(str(p), p.stat().st_mtime)


def _revoked() -> set[str]:
    """Techniques ATT&CK has retired. TDL rules still mapped to one are not a Warden gap."""
    f = Path(settings.attack_dir) / "_revoked.json"
    if not f.exists():
        return set()
    return set(json.loads(f.read_text()))


def _covered() -> set[str]:
    """Technique ids Warden's own detections claim, plus their parents."""
    from .detections import REGISTRY, load_all
    load_all()
    out: set[str] = set()
    for d in REGISTRY.values():
        for t in d.mitre:
            out.add(t)
            out.add(t.split(".")[0])
    return out


def coverage() -> dict:
    """Per-tactic and per-technique coverage of TDL's library by Warden's detections."""
    from .detections import REGISTRY

    rows = rules()
    if not rows:
        return {"available": False, "rules": 0, "techniques": 0, "covered": 0, "tactics": [], "gaps": []}
    covered, revoked = _covered(), _revoked()
    by_tech: dict[str, dict] = {}
    for r in rows:
        tid = r["technique_id"]
        t = by_tech.setdefault(tid, {"technique": tid, "name": r.get("technique_name") or "",
                                     "tactic": r.get("tactic") or "", "tdl_rules": 0, "deployed": 0,
                                     "severities": defaultdict(int), "platforms": set()})
        t["tdl_rules"] += 1
        t["deployed"] += 1 if (r.get("lifecycle") or "").lower() == "deployed" else 0
        t["severities"][(r.get("severity") or "unknown").lower()] += 1
        t["platforms"].update(r.get("platform") or [])
    warden_by_tech: dict[str, list[str]] = defaultdict(list)
    for d in REGISTRY.values():
        for t in d.mitre:
            warden_by_tech[t].append(d.id)
            if "." in t:
                warden_by_tech[t.split(".")[0]].append(d.id)
    techs = []
    for tid, t in by_tech.items():
        hit = tid in covered or tid.split(".")[0] in covered
        techs.append({**t, "covered": hit, "revoked": tid in revoked,
                      "detections": sorted(set(warden_by_tech.get(tid, []))),
                      "severities": dict(t["severities"]), "platforms": sorted(t["platforms"])})
    tactics: dict[str, dict] = {}
    for t in techs:
        row = tactics.setdefault(t["tactic"], {"tactic": t["tactic"], "techniques": 0, "covered": 0,
                                                "revoked": 0, "tdl_rules": 0})
        row["techniques"] += 1
        row["covered"] += 1 if t["covered"] else 0
        row["revoked"] += 1 if t["revoked"] else 0
        row["tdl_rules"] += t["tdl_rules"]
    gaps = sorted((t for t in techs if not t["covered"] and not t["revoked"]), key=lambda t: -t["tdl_rules"])
    return {"available": True, "rules": len(rows), "techniques": len(techs),
            "covered": sum(1 for t in techs if t["covered"]),
            "revoked": sum(1 for t in techs if t["revoked"]),
            "tactics": sorted(tactics.values(), key=lambda r: -r["techniques"]),
            "techniques_detail": sorted(techs, key=lambda t: (t["covered"], -t["tdl_rules"])),
            "gaps": gaps}
