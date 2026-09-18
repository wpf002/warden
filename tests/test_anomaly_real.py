"""Anomaly detection on a real 4-week SSH log (Loghub OpenSSH, fetched by
scripts/fetch_baseline_logs.py): three weeks of baseline, the last week held out.
Measures the alert rate on real traffic and checks an injected takeover is still caught."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, time, timedelta
from pathlib import Path

import pytest

from warden.detections.anomaly_host import HostAnomaly
from warden.detections.anomaly_user import UserAnomaly
from warden.events import AuthEvent
from warden.ingest import load_file

LOG = Path(__file__).resolve().parents[1] / "data" / "real" / "baseline" / "SSH.log"


@pytest.fixture(scope="module")
def days():
    if not LOG.exists():
        pytest.skip("run scripts/fetch_baseline_logs.py")
    by = defaultdict(list)
    for e in load_file(LOG, "sshd"):
        by[e.ts.date()].append(e)
    return by


def _alerts(days, day, extra=()):
    prior = [e for d, evs in days.items() if d < day and (day - d).days <= 30 for e in evs]
    out = []
    for cls in (UserAnomaly, HostAnomaly):
        det = cls()
        det.prior, det.stored_profiles = prior, {}
        out += det.run(sorted([*days[day], *extra], key=lambda e: e.ts))
    return out


def test_holdout_week_alert_rate(days):
    week = sorted(days)[-7:]
    alerts = [a for d in week for a in _alerts(days, d)]
    # 1,700+ user entities, ~110k events in the week: the baseline must stay quiet
    assert len(alerts) <= 7, [a.title for a in alerts]


def test_injected_takeover_is_caught(days):
    day = sorted(days)[-2]
    at = datetime.combine(day, time(3, 0), tzinfo=next(iter(days[day])).ts.tzinfo)
    ip, host = "45.155.205.17", days[day][0].host
    attack = [AuthEvent(ts=at + timedelta(seconds=i), source="sshd", host=host, user="curi", source_ip=ip,
                        event_type="login_failure", logon_type="remote_interactive") for i in range(40)]
    attack.append(AuthEvent(ts=at + timedelta(minutes=1), source="sshd", host=host, user="curi", source_ip=ip,
                            event_type="login_success", logon_type="remote_interactive"))
    hits = [a for a in _alerts(days, day, attack) if a.detail.get("entity") == "curi"]
    assert hits, "takeover of a regular user from a new network at 03:00 was not flagged"
    why = {c["feature"] for c in hits[0].detail["contributions"]}
    assert {"src_nets", "hours"} & why
