"""MITRE ATT&CK ingest. Phase 3.

Pulls the public Enterprise ATT&CK STIX bundle, flattens it into one document per
technique and sub-technique, and indexes those into the knowledge base tagged with the
technique id. Retrieval can then filter by the detection's mapped technique first and
widen from there (see `KnowledgeBase.retrieve_by_technique`).

Run it nightly:

    warden attack-ingest                    # download and index
    warden attack-ingest --file bundle.json # local copy, no network
    warden attack-ingest --no-index         # write docs only

Every ingest writes `_manifest.json` next to the docs: bundle version, object count,
and date. Cases record which snapshot they were analyzed against so replay is exact.
"""
from __future__ import annotations

import json
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from .config import settings

BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)
USES_TYPES = {"intrusion-set": "groups", "malware": "software", "tool": "software", "campaign": "campaigns"}


# ---------------------------------------------------------------- fetch
def fetch_bundle(url: str | None = None, file: Path | None = None, timeout: int = 120) -> dict:
    if file:
        return json.loads(Path(file).read_text())
    url = url or BUNDLE_URL
    with urllib.request.urlopen(url, timeout=timeout) as r:  # noqa: S310 - fixed, public URL
        return json.loads(r.read().decode())


# ---------------------------------------------------------------- parse
def _external_id(obj: dict) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return ""


def parse(bundle: dict) -> list[dict]:
    """Flatten the STIX graph into technique records with their mitigations and actors."""
    objects = bundle.get("objects", [])
    by_id = {o["id"]: o for o in objects if "id" in o}

    techniques: dict[str, dict] = {}
    for o in objects:
        if o.get("type") != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        tid = _external_id(o)
        if not tid:
            continue
        techniques[o["id"]] = {
            "id": tid,
            "base": tid.split(".")[0],
            "name": o.get("name", ""),
            "is_subtechnique": bool(o.get("x_mitre_is_subtechnique")),
            "description": (o.get("description") or "").strip(),
            "detection": (o.get("x_mitre_detection") or "").strip(),
            "platforms": o.get("x_mitre_platforms", []),
            "data_sources": o.get("x_mitre_data_sources", []),
            "tactics": [p.get("phase_name", "") for p in o.get("kill_chain_phases", [])
                        if p.get("kill_chain_name") == "mitre-attack"],
            "mitigations": [],
            "groups": [],
            "software": [],
            "campaigns": [],
        }

    related: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    # ATT&CK v18+: detection guidance moved from x_mitre_detection on the technique to
    # detection-strategy objects (linked by "detects") that reference analytics.
    analytics = {o["id"]: o for o in objects if o.get("type") == "x-mitre-analytic"}
    for o in objects:
        if o.get("type") != "relationship" or o.get("revoked"):
            continue
        tgt, src, rel = o.get("target_ref", ""), o.get("source_ref", ""), o.get("relationship_type")
        if tgt not in techniques:
            continue
        src_obj = by_id.get(src)
        if not src_obj or src_obj.get("revoked") or src_obj.get("x_mitre_deprecated"):
            continue
        name = src_obj.get("name", "")
        if rel == "detects" and src_obj.get("type") == "x-mitre-detection-strategy":
            lines = [f"Strategy: {src_obj.get('name', '')}"]
            for ref in src_obj.get("x_mitre_analytic_refs", []):
                an = analytics.get(ref)
                if not an or an.get("revoked") or an.get("x_mitre_deprecated"):
                    continue
                logs = ", ".join(sorted({f"{ls.get('name')}" for ls in an.get("x_mitre_log_source_references", [])}))
                plat = ", ".join(an.get("x_mitre_platforms", []))
                lines.append(f"- ({plat}) {(an.get('description') or '').strip()}" + (f" Log sources: {logs}." if logs else ""))
            related[tgt]["strategies"].append("\n".join(lines))
        elif rel == "mitigates" and src_obj.get("type") == "course-of-action":
            desc = (o.get("description") or "").strip().split("\n")[0]
            related[tgt]["mitigations"].append(f"{name}: {desc}" if desc else name)
        elif rel == "uses" and src_obj.get("type") in USES_TYPES:
            related[tgt][USES_TYPES[src_obj["type"]]].append(name)

    out = []
    for stix_id, t in techniques.items():
        for key, vals in related.get(stix_id, {}).items():
            if key == "strategies":
                strategy_text = "\n\n".join(vals)
                t["detection"] = (t["detection"] + "\n\n" + strategy_text).strip() if t["detection"] else strategy_text
            else:
                t[key] = sorted(set(vals))
        out.append(t)
    return sorted(out, key=lambda t: t["id"])


# ---------------------------------------------------------------- render
def render(t: dict) -> str:
    """One markdown doc per technique. Detection guidance gets its own heading so the
    chunker keeps it whole - that section is what the analyst prompt actually needs."""
    parts = [f"# {t['id']} {t['name']}", ""]
    if t["tactics"]:
        parts.append(f"Tactics: {', '.join(t['tactics'])}")
    if t["platforms"]:
        parts.append(f"Platforms: {', '.join(t['platforms'])}")
    if t["is_subtechnique"]:
        parts.append(f"Sub-technique of {t['base']}.")
    parts.append("")
    if t["description"]:
        parts += ["## Description", "", t["description"], ""]
    if t["detection"]:
        parts += [f"## Detection guidance for {t['id']}", "", t["detection"], ""]
    if t["data_sources"]:
        parts += [f"## Data sources for {t['id']}", "", "- " + "\n- ".join(t["data_sources"]), ""]
    if t["mitigations"]:
        parts += [f"## Mitigations for {t['id']}", "", "- " + "\n- ".join(t["mitigations"]), ""]
    for key, label in (("groups", "Associated groups"), ("software", "Associated software"),
                       ("campaigns", "Campaigns")):
        if t[key]:
            parts += [f"## {label} for {t['id']}", "", ", ".join(t[key]), ""]
    return "\n".join(parts)


# ---------------------------------------------------------------- index
def index_techniques(techniques: list[dict], kb=None, batch: int = 500) -> int:
    from .knowledge import KnowledgeBase, chunk

    kb = kb or KnowledgeBase()
    ids, docs, metas = [], [], []
    for t in techniques:
        for i, c in enumerate(chunk(render(t))):
            ids.append(f"attack-{t['id']}#{i}")
            docs.append(c)
            metas.append({"doc": f"attack-{t['id']}", "chunk": i, "kind": "attack",
                          "technique": t["id"], "technique_base": t["base"],
                          "techniques": t["id"], "name": t["name"]})
    for s in range(0, len(ids), batch):
        kb.col.upsert(ids=ids[s:s + batch], documents=docs[s:s + batch], metadatas=metas[s:s + batch])
    kb.invalidate()
    return len(ids)


def revoked_ids(bundle: dict) -> list[str]:
    return sorted({_external_id(o) for o in bundle.get("objects", [])
                   if o.get("type") == "attack-pattern" and (o.get("revoked") or o.get("x_mitre_deprecated")) and _external_id(o)})


def write_docs(techniques: list[dict], out: Path | None = None) -> Path:
    out = out or settings.attack_dir
    out.mkdir(parents=True, exist_ok=True)
    for t in techniques:
        (out / f"{t['id']}.md").write_text(render(t))
    return out


def ingest(url: str | None = None, file: Path | None = None, index: bool = True,
           out: Path | None = None, kb=None) -> tuple[int, int]:
    bundle = fetch_bundle(url, file)
    techniques = parse(bundle)
    out = write_docs(techniques, out)
    (out / "_revoked.json").write_text(json.dumps(revoked_ids(bundle)))
    n_chunks = index_techniques(techniques, kb) if index else 0
    (out / "_manifest.json").write_text(json.dumps({
        "source": str(file) if file else (url or BUNDLE_URL),
        "bundle_id": bundle.get("id", ""),
        "spec_version": bundle.get("spec_version", ""),
        "attack_version": next((o.get("x_mitre_version") for o in bundle.get("objects", [])
                                if o.get("type") == "x-mitre-collection"), ""),
        "objects": len(bundle.get("objects", [])),
        "techniques": len(techniques),
        "chunks": n_chunks,
        "fetched": datetime.now(timezone.utc).isoformat(),
    }, indent=2) + "\n")
    return len(techniques), n_chunks


def manifest(out: Path | None = None) -> dict | None:
    p = (out or settings.attack_dir) / "_manifest.json"
    return json.loads(p.read_text()) if p.exists() else None
