"""Entity baselines and anomaly scoring. Phase 5.

Per user and per host, one feature vector per day:
    numeric   counts and volumes (logins, failures, hosts touched, bytes out, ...)
    sets      categorical values seen that day (hosts, source /24s, countries, login hours,
              processes, parent->child pairs, outbound destinations)

A profile is 30 days of those: mean and spread for each numeric feature, and how many days
each categorical value appeared. Scoring a new day produces an explicit list of
contributions - "logged in to 9 hosts, baseline 1.2 +/- 0.4 (z=19)", "first time running
nltest.exe" - and the alert shows every one of them. Isolation Forest over the numeric
vectors is a second opinion that can add weight; it never fires an alert on its own.

Profiles are stored in the `baselines` table (warden baseline rebuild), updated as days are
scored, and fall back to computing from stored events when no profile exists yet.
"""
from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import date

from .config import settings
from .detections._identity import norm_user
from .events import AuthEvent, Event, FileEvent, IdentityChangeEvent, NetworkEvent, ProcessEvent

USER_NUMERIC = ("logins", "failures", "distinct_hosts", "distinct_src_nets", "processes", "distinct_processes",
                "mfa_denials", "directory_changes")
USER_SETS = ("hosts", "src_nets", "geos", "hours", "processes_set")
HOST_NUMERIC = ("process_starts", "distinct_processes", "connections_out", "distinct_destinations", "bytes_out_mb",
                "internal_destinations", "dns_queries", "file_writes")
HOST_SETS = ("processes_set", "parent_child", "destinations", "users")

# weight of one never-seen value, and the cap per feature
RARITY = {"hosts": (1.5, 6), "src_nets": (1.0, 3), "geos": (3.0, 6), "hours": (0.75, 3), "processes_set": (1.5, 6),
          "parent_child": (1.0, 4), "destinations": (0.75, 3), "users": (1.0, 3)}
DESCRIBE = {"hosts": ("host", "hosts"), "src_nets": ("source network", "source networks"), "geos": ("country", "countries"),
            "hours": ("login hour (UTC)", "login hours (UTC)"), "processes_set": ("process", "processes"),
            "parent_child": ("parent->child pair", "parent->child pairs"), "destinations": ("destination", "destinations"),
            "users": ("user", "users")}
SYSTEMISH = {"system", "local service", "network service", ""}


def _net(ip: str) -> str:
    return ".".join(ip.split(".")[:3]) + ".0/24" if ip.count(".") == 3 else ip


def _dest(e: NetworkEvent) -> str:
    from .detections._network import is_internal, parent_domain
    if e.domain:
        return parent_domain(e.domain)
    return "" if is_internal(e.dest_ip) else _net(e.dest_ip)


# ---------------------------------------------------------------- daily features
def daily_features(events: list[Event]) -> dict[tuple[str, str, date], dict]:
    """{(entity_type, entity, day): {"num": {...}, "sets": {...}}}"""
    from .detections._network import is_internal

    out: dict = defaultdict(lambda: {"num": Counter(), "sets": defaultdict(set)})
    for e in events:
        day = e.ts.date()
        u = norm_user(e.user)
        if isinstance(e, AuthEvent) and u:
            f = out[("user", u, day)]
            if e.event_type == "login_success":
                f["num"]["logins"] += 1
                f["sets"]["hosts"].add(e.host)
                if e.source_ip:
                    f["sets"]["src_nets"].add(_net(e.source_ip))
                if e.geo and e.geo != "internal":
                    f["sets"]["geos"].add(e.geo)
                f["sets"]["hours"].add(str(e.ts.hour))
            elif e.event_type in ("login_failure", "lockout"):
                f["num"]["failures"] += 1
            elif e.event_type in ("mfa_denied", "mfa_timeout"):
                f["num"]["mfa_denials"] += 1
        elif isinstance(e, IdentityChangeEvent) and u:
            out[("user", u, day)]["num"]["directory_changes"] += 1
        elif isinstance(e, ProcessEvent) and e.action == "start":
            if u and u not in SYSTEMISH and not u.endswith("$"):
                f = out[("user", u, day)]
                f["num"]["processes"] += 1
                f["sets"]["processes_set"].add(e.process_name)
            if e.host:
                h = out[("host", e.host.lower(), day)]
                h["num"]["process_starts"] += 1
                h["sets"]["processes_set"].add(e.process_name)
                if e.parent_name:
                    h["sets"]["parent_child"].add(f"{e.parent_name}>{e.process_name}")
                if u and u not in SYSTEMISH:
                    h["sets"]["users"].add(u)
        elif isinstance(e, NetworkEvent) and e.host:
            h = out[("host", e.host.lower(), day)]
            if e.protocol == "dns":
                h["num"]["dns_queries"] += 1
            else:
                h["num"]["connections_out"] += 1
                h["num"]["bytes_out_mb"] += e.bytes_out / 1e6
                if e.dest_ip and is_internal(e.dest_ip):
                    h["sets"]["_internal"].add(e.dest_ip)
            d = _dest(e)
            if d:
                h["sets"]["destinations"].add(d)
        elif isinstance(e, FileEvent) and e.host and e.action in ("create", "modify", "rename"):
            out[("host", e.host.lower(), day)]["num"]["file_writes"] += 1
    for (etype, _, _), f in out.items():
        s, n = f["sets"], f["num"]
        if etype == "user":
            n["distinct_hosts"] = len(s["hosts"])
            n["distinct_src_nets"] = len(s["src_nets"])
            n["distinct_processes"] = len(s["processes_set"])
        else:
            n["distinct_processes"] = len(s["processes_set"])
            n["distinct_destinations"] = len(s["destinations"])
            n["internal_destinations"] = len(s.pop("_internal", set()))
    return out


# ---------------------------------------------------------------- profiles
@dataclass
class Profile:
    entity_type: str
    entity: str
    days: int = 0
    numeric: dict[str, list[float]] = field(default_factory=dict)       # per-day values, most recent last
    seen: dict[str, dict[str, int]] = field(default_factory=dict)       # value -> days seen

    def add_day(self, feats: dict) -> None:
        self.days += 1
        names = USER_NUMERIC if self.entity_type == "user" else HOST_NUMERIC
        for n in names:
            self.numeric.setdefault(n, []).append(float(feats["num"].get(n, 0)))
            self.numeric[n] = self.numeric[n][-settings.baseline_days:]
        for k, vals in feats["sets"].items():
            bucket = self.seen.setdefault(k, {})
            for v in vals:
                bucket[v] = bucket.get(v, 0) + 1
        self.days = min(self.days, settings.baseline_days)

    def to_json(self) -> dict:
        return {"entity_type": self.entity_type, "entity": self.entity, "days": self.days,
                "numeric": self.numeric, "seen": self.seen}

    @classmethod
    def from_json(cls, d: dict) -> "Profile":
        return cls(d["entity_type"], d["entity"], d["days"], d["numeric"], d["seen"])


def build_profiles(events: list[Event]) -> dict[tuple[str, str], Profile]:
    feats = daily_features(events)
    profiles: dict[tuple[str, str], Profile] = {}
    for (etype, ent, day) in sorted(feats, key=lambda k: k[2]):
        profiles.setdefault((etype, ent), Profile(etype, ent)).add_day(feats[(etype, ent, day)])
    return profiles


# ---------------------------------------------------------------- scoring
@dataclass
class Contribution:
    feature: str
    kind: str             # "volume" | "new_value" | "iforest"
    score: float
    text: str
    value: object = None

    def as_dict(self) -> dict:
        return {"feature": self.feature, "kind": self.kind, "score": round(self.score, 2), "why": self.text,
                "value": self.value}


PEER_FEATURES = {"hosts", "processes_set", "parent_child", "destinations"}


def population(profiles: dict[tuple[str, str], Profile]) -> dict[tuple[str, str], Counter]:
    """How many entities of each type already have each value. A server new to one person
    but used by five colleagues is weaker evidence than a server nobody has ever touched."""
    pop: dict[tuple[str, str], Counter] = defaultdict(Counter)
    for (t, _), p in profiles.items():
        for feat, vals in p.seen.items():
            if feat in PEER_FEATURES:
                pop[(t, feat)].update(vals.keys())
    return pop


def score_day(profile: Profile, feats: dict, suppressed: set[str] | None = None,
              peers: dict[tuple[str, str], Counter] | None = None) -> list[Contribution]:
    suppressed = suppressed or set()
    peers = peers or {}
    out: list[Contribution] = []
    names = USER_NUMERIC if profile.entity_type == "user" else HOST_NUMERIC
    for n in names:
        if n in suppressed:
            continue
        hist = profile.numeric.get(n, [])
        x = float(feats["num"].get(n, 0))
        if len(hist) < 3 or x == 0:
            continue
        mean = statistics.mean(hist)
        sd = statistics.pstdev(hist)
        floor = max(1.0, 0.1 * mean)       # a feature that never varied is not infinitely surprising
        z = (x - mean) / max(sd, floor)
        if z >= settings.anomaly_min_z:
            out.append(Contribution(n, "volume", min(z, 10.0),
                                    f"{n.replace('_', ' ')} {x:g}, baseline {mean:.1f} +/- {sd:.1f} (z={z:.1f})", x))
    # volume features overlap (more logins usually means more hosts): the strongest counts in
    # full, the rest at half weight, so one busy day is not scored three times
    vol = sorted((c for c in out if c.kind == "volume"), key=lambda c: -c.score)
    for c in vol[1:]:
        c.score *= 0.5
    for k, vals in feats["sets"].items():
        if k not in RARITY or k in suppressed:
            continue
        seen = profile.seen.get(k, {})
        new = sorted(v for v in vals if v and seen.get(v, 0) == 0)
        if not new:
            continue
        w, cap = RARITY[k]
        pop = peers.get((profile.entity_type, k), Counter())
        common = [v for v in new if pop.get(v, 0) >= settings.peer_common]
        rare = [v for v in new if v not in common]
        score = w * len(rare) + w * settings.peer_weight * len(common)
        text = f"first {DESCRIBE[k][len(new) > 1]}: {', '.join((rare + common)[:6])}" + \
            (f" (+{len(new) - 6} more)" if len(new) > 6 else "")
        if common and k in PEER_FEATURES:
            text += f"; {len(common)} already used by {settings.peer_common}+ peers" if rare else "; all already used by peers"
        out.append(Contribution(k, "new_value", min(cap, score), text, new[:20]))
    return sorted(out, key=lambda c: -c.score)


def iforest_outliers(profiles: dict[tuple[str, str], Profile], today: dict[tuple[str, str], dict]) -> dict:
    """Second opinion: Isolation Forest fit on every entity's baseline days of one type.
    Returns {(etype, entity): decision_score} for today's vectors flagged as outliers."""
    try:
        import numpy as np
        from sklearn.ensemble import IsolationForest
    except ImportError:          # optional dependency; the explainable scorer stands alone
        return {}
    flagged = {}
    for etype, names in (("user", USER_NUMERIC), ("host", HOST_NUMERIC)):
        rows = []
        for (t, _), p in profiles.items():
            if t != etype or not p.numeric:
                continue
            n_days = max(len(v) for v in p.numeric.values())
            for i in range(n_days):
                rows.append([p.numeric[n][i] if i < len(p.numeric.get(n, [])) else 0.0 for n in names])
        if len(rows) < 30:
            continue
        model = IsolationForest(n_estimators=200, contamination="auto", random_state=7).fit(np.array(rows))
        keys = [k for k in today if k[0] == etype]
        if not keys:
            continue
        X = np.array([[float(today[k]["num"].get(n, 0)) for n in names] for k in keys])
        for k, pred, sc in zip(keys, model.predict(X), model.decision_function(X)):
            if pred == -1:
                flagged[k] = float(sc)
    return flagged


# ---------------------------------------------------------------- persistence
def load_profiles(store) -> dict[tuple[str, str], Profile]:
    from sqlalchemy import select

    from . import db
    with store.engine.connect() as c:
        rows = c.execute(select(db.baselines.c.profile).where(db.baselines.c.tenant == store.tenant)).all()
    return {(r[0]["entity_type"], r[0]["entity"]): Profile.from_json(r[0]) for r in rows}


def save_profiles(store, profiles: dict[tuple[str, str], Profile]) -> int:
    from sqlalchemy import delete, insert

    from . import db
    with store.engine.begin() as c:
        for (t, e), p in profiles.items():
            c.execute(delete(db.baselines).where(db.baselines.c.tenant == store.tenant,
                                                 db.baselines.c.entity_type == t, db.baselines.c.entity == e))
            c.execute(insert(db.baselines).values(tenant=store.tenant, entity_type=t, entity=e, days=p.days,
                                                  profile=p.to_json(), updated=db.now()))
    return len(profiles)


def rebuild(store, days: int | None = None, until=None) -> int:
    """Nightly: recompute every profile from the stored events of the N days before `until`
    (default now). Pass the last event time to build from historical logs."""
    from datetime import datetime, timedelta, timezone
    until = until or datetime.now(timezone.utc)
    since = until - timedelta(days=days or settings.baseline_days)
    profiles = build_profiles(store.events(since=since, until=until + timedelta(seconds=1)))
    return save_profiles(store, profiles)


def update(store, profiles: dict[tuple[str, str], Profile], events: list[Event], skip: set[tuple[str, str, str]]) -> None:
    """Fold the batch's days into the profiles, except entity-days that raised an anomaly:
    an attack day must not become tomorrow's normal."""
    feats = daily_features(events)
    touched = {}
    for (t, e, d) in sorted(feats, key=lambda k: k[2]):
        if (t, e, d.isoformat()) in skip:
            continue
        prof = profiles.setdefault((t, e), Profile(t, e))
        prof.add_day(feats[(t, e, d)])
        touched[(t, e)] = prof
    if touched:
        save_profiles(store, touched)


def absorb(store, alert) -> int:
    """An analyst called an anomaly benign: the values it flagged as new become known, so
    the same novelty does not fire again. Returns how many values were absorbed."""
    profiles = load_profiles(store)
    n = 0
    for a in (alert.members or [alert]):
        d = a.detail
        if d.get("source") != "anomaly":
            continue
        key = (d["entity_type"], d["entity"])
        prof = profiles.get(key)
        if not prof:
            continue
        for c in d.get("contributions", []):
            if c["kind"] == "new_value" and isinstance(c.get("value"), list):
                bucket = prof.seen.setdefault(c["feature"], {})
                for v in c["value"]:
                    bucket[v] = max(1, bucket.get(v, 0))
                    n += 1
        save_profiles(store, {key: prof})
    return n
