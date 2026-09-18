"""Anomaly detection as a Detection: the baseline comes from `prior`, the day being scored
from the batch. Stays deterministic - same events, same profile, same alert."""
from __future__ import annotations

from collections import defaultdict

from ..baselines import Profile, build_profiles, daily_features, iforest_outliers, population, score_day
from ..config import settings
from ..events import Event
from ..models import Alert
from . import Detection


class AnomalyDetection(Detection):
    entity_type = ""
    event_kinds = ("auth", "process", "network", "file", "identity")
    window_sec = 86400
    playbook = "playbook-anomaly"
    needs_history = True
    mitre: list[str] = []
    # {(entity, feature)} analysts muted; set per run by run_all from exclusions
    suppressed_features: set[tuple[str, str]] = set()
    stored_profiles: dict = {}

    def run(self, events: list[Event]) -> list[Alert]:
        profiles: dict[tuple[str, str], Profile] = dict(self.stored_profiles) or build_profiles(self.prior)
        today = daily_features(events)
        per_entity = {(t, e): f for (t, e, _), f in today.items() if t == self.entity_type}
        second = iforest_outliers(profiles, per_entity)
        peers = population(profiles)
        days_by_entity = defaultdict(list)
        for (t, e, d) in today:
            if t == self.entity_type:
                days_by_entity[e].append(d)
        out = []
        for (etype, ent, day), feats in sorted(today.items(), key=lambda kv: kv[0][2]):
            if etype != self.entity_type:
                continue
            prof = profiles.get((etype, ent))
            if not prof or prof.days < settings.baseline_min_days:
                continue
            muted = {f for (e, f) in self.suppressed_features if e == ent}
            contribs = score_day(prof, feats, muted, peers)
            base = sum(c.score for c in contribs)
            if (etype, ent) in second and base > 0:
                from ..baselines import Contribution
                contribs.append(Contribution("iforest", "iforest", 2.0,
                                             f"Isolation Forest also flags this day (score {second[(etype, ent)]:.3f})"))
            total = sum(c.score for c in contribs)
            if total < settings.anomaly_threshold or not any(c.kind != "iforest" for c in contribs):
                continue
            evs = [e for e in events if e.ts.date() == day and (
                (etype == "user" and e.user and e.user.lower().split("@")[0].split("\\")[-1] == ent)
                or (etype == "host" and e.host.lower() == ent))]
            evs.sort(key=lambda e: e.ts)
            if not evs:
                continue
            top = contribs[:5]
            out.append(self.new_alert(
                key=f"{ent}|{day.isoformat()}", first_seen=evs[0].ts, ts=evs[-1].ts,
                title=f"Unusual day for {etype} {ent}: " + "; ".join(c.text for c in top[:2]),
                source_ip=next((e.source_ip for e in evs if e.source_ip), ""),
                users=[ent] if etype == "user" else sorted({e.user for e in evs if e.user})[:5],
                hosts=sorted({e.host for e in evs if e.host})[:10] if etype == "user" else [ent],
                last_seen=evs[-1].ts, window_sec=int((evs[-1].ts - evs[0].ts).total_seconds()),
                detail={"entity_type": etype, "entity": ent, "day": day.isoformat(), "score": round(total, 2),
                        "baseline_days": prof.days, "contributions": [c.as_dict() for c in contribs],
                        "source": "anomaly"},
                evidence=[{"ts": e.ts.isoformat(), "user": e.user, "host": e.host,
                           "type": getattr(e, "event_type", "") or getattr(e, "action", "") or e.kind,
                           "detail": getattr(e, "process_name", "") or getattr(e, "dest_ip", "")} for e in evs[:25]],
            ))
        return out
