"""Threat intelligence. Phase 3.

Two destinations, on purpose:
  * Indicators (IPs, domains, hashes, CVE ids) go into the `iocs` lookup table. They are
    matched exactly during enrichment. Putting them in the vector store would make
    "is 203.0.113.9 known bad" a similarity search, which is the wrong tool.
  * Context (what a KEV entry is, what to do about it) goes into the knowledge base as
    `kind: intel` documents, reachable by retrieval when an alert is about that CVE.

Feeds, all public and keyless:
  cisa_kev     CISA Known Exploited Vulnerabilities
  feodo        abuse.ch Feodo Tracker botnet C2 IPs
  tor_exit     Tor Project bulk exit list (context, not maliciousness: confidence 30)
Optional:
  otx          AlienVault OTX subscribed pulses, when OTX_API_KEY is set
"""
from __future__ import annotations

import json
import urllib.request
from datetime import datetime, timezone
from typing import Callable, Iterable

from sqlalchemy import select, update, insert

from . import db
from .config import settings

UA = {"User-Agent": "warden-intel/0.2 (+https://github.com/wpf002/warden)"}


def _get(url: str, timeout: int = 60, headers: dict | None = None) -> bytes:
    req = urllib.request.Request(url, headers={**UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - fixed feed URLs
        return r.read()


def _dt(v) -> datetime | None:
    if not v:
        return None
    try:
        d = datetime.fromisoformat(str(v).replace("Z", "+00:00").replace(" ", "T", 1))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


# ---------------------------------------------------------------- feeds
def feed_cisa_kev(raw: bytes | None = None) -> tuple[list[dict], list[dict]]:
    data = json.loads(raw or _get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"))
    iocs, docs = [], []
    for v in data.get("vulnerabilities", []):
        cve = v["cveID"]
        ransomware = v.get("knownRansomwareCampaignUse", "Unknown")
        iocs.append({"type": "cve", "value": cve, "source": "cisa_kev", "confidence": 100,
                     "tags": {"vendor": v.get("vendorProject"), "product": v.get("product"),
                              "ransomware": ransomware, "due": v.get("dueDate")},
                     "first_seen": _dt(v.get("dateAdded"))})
        docs.append({"id": f"intel-kev-{cve}", "kind": "intel", "cve": cve, "added": v.get("dateAdded", ""),
                     "text": f"# {cve} {v.get('vulnerabilityName', '')}\n\n"
                             f"Known exploited (CISA KEV, added {v.get('dateAdded')}). Vendor: {v.get('vendorProject')}. "
                             f"Product: {v.get('product')}. Ransomware use: {ransomware}.\n\n"
                             f"{v.get('shortDescription', '')}\n\nRequired action: {v.get('requiredAction', '')}"})
    return iocs, docs


def feed_feodo(raw: bytes | None = None) -> tuple[list[dict], list[dict]]:
    rows = json.loads(raw or _get("https://feodotracker.abuse.ch/downloads/ipblocklist.json"))
    return [{"type": "ip", "value": r["ip_address"], "source": "feodo", "confidence": 90 if r.get("status") == "online" else 70,
             "tags": {"malware": r.get("malware"), "port": r.get("port"), "as_name": r.get("as_name"),
                      "country": r.get("country"), "status": r.get("status")},
             "first_seen": _dt(r.get("first_seen")), "last_seen": _dt(r.get("last_online"))} for r in rows], []


def feed_tor_exit(raw: bytes | None = None) -> tuple[list[dict], list[dict]]:
    text = (raw or _get("https://check.torproject.org/torbulkexitlist")).decode()
    now = datetime.now(timezone.utc)
    return [{"type": "ip", "value": ln.strip(), "source": "tor_exit", "confidence": 30,
             "tags": {"category": "anonymizer"}, "last_seen": now}
            for ln in text.splitlines() if ln.strip() and not ln.startswith("#")], []


def feed_otx(raw: bytes | None = None) -> tuple[list[dict], list[dict]]:
    key = settings.otx_api_key
    if not key and raw is None:
        return [], []
    data = json.loads(raw or _get("https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50",
                                  headers={"X-OTX-API-KEY": key}))
    types = {"IPv4": "ip", "domain": "domain", "hostname": "domain", "URL": "url", "FileHash-SHA256": "sha256", "CVE": "cve"}
    iocs, docs = [], []
    for p in data.get("results", []):
        for ind in p.get("indicators", []):
            t = types.get(ind.get("type"))
            if t:
                iocs.append({"type": t, "value": ind["indicator"], "source": "otx", "confidence": 60,
                             "tags": {"pulse": p.get("name"), "adversary": p.get("adversary")},
                             "first_seen": _dt(ind.get("created"))})
        if p.get("description"):
            docs.append({"id": f"intel-otx-{p['id']}", "kind": "intel", "added": p.get("modified", "")[:10],
                         "text": f"# {p.get('name')}\n\nAdversary: {p.get('adversary') or 'unknown'}. "
                                 f"Tags: {', '.join(p.get('tags', []))}.\n\n{p['description']}"})
    return iocs, docs


FEEDS: dict[str, Callable] = {"cisa_kev": feed_cisa_kev, "feodo": feed_feodo, "tor_exit": feed_tor_exit, "otx": feed_otx}


# ---------------------------------------------------------------- storage
def upsert_iocs(rows: Iterable[dict], engine=None) -> int:
    eng = engine or db.engine()
    rows = list(rows)
    if not rows:
        return 0
    now = db.now()
    n = 0
    with eng.begin() as c:
        existing = {(r.type, r.value, r.source): r.id for r in c.execute(
            select(db.iocs.c.id, db.iocs.c.type, db.iocs.c.value, db.iocs.c.source)
            .where(db.iocs.c.source.in_({r["source"] for r in rows})))}
        new = []
        for r in rows:
            k = (r["type"], r["value"], r["source"])
            vals = {**r, "updated": now}
            if k in existing:
                c.execute(update(db.iocs).where(db.iocs.c.id == existing[k]).values(**vals))
            else:
                new.append(vals)
                existing[k] = -1
            n += 1
        if new:
            c.execute(insert(db.iocs), new)
    return n


def lookup(values: Iterable[str], engine=None) -> dict[str, list[dict]]:
    vals = [v for v in set(values) if v]
    if not vals:
        return {}
    eng = engine or db.engine()
    out: dict[str, list[dict]] = {}
    with eng.connect() as c:
        for r in c.execute(select(db.iocs).where(db.iocs.c.value.in_(vals))):
            out.setdefault(r.value, []).append({"type": r.type, "source": r.source, "confidence": r.confidence,
                                                "tags": r.tags})
    return out


def enrich(alerts, engine=None):
    """Attach intel matches for every IP an alert names. Detection already happened;
    this adds context the analyst and the model both see."""
    hits = lookup((ip for a in alerts for ip in a.all_ips()), engine)
    for a in alerts:
        found = {ip: hits[ip] for ip in a.all_ips() if ip in hits}
        if found:
            a.detail["intel"] = found
        for m in a.members:
            mf = {ip: hits[ip] for ip in m.all_ips() if ip in hits}
            if mf:
                m.detail["intel"] = mf
    return alerts


def refresh(feeds: list[str] | None = None, kb=None, engine=None, raw: dict[str, bytes] | None = None) -> dict:
    """Pull every feed, upsert IOCs, index intel documents. One failing feed does not stop
    the others; the result says which ones failed and why."""
    report: dict = {}
    docs_all: list[dict] = []
    for name in feeds or list(FEEDS):
        try:
            iocs, docs = FEEDS[name]((raw or {}).get(name))
            report[name] = {"iocs": upsert_iocs(iocs, engine), "docs": len(docs)}
            docs_all += docs
        except Exception as e:  # noqa: BLE001 - reported, not raised
            report[name] = {"error": f"{type(e).__name__}: {e}"}
    if docs_all and kb is not None:
        for s in range(0, len(docs_all), 500):
            b = docs_all[s:s + 500]
            kb.col.upsert(ids=[d["id"] for d in b], documents=[d["text"] for d in b],
                          metadatas=[{"doc": d["id"], "chunk": 0, "kind": "intel", "cve": d.get("cve", ""),
                                      "added": d.get("added", "")} for d in b])
        kb.invalidate()
    return report
