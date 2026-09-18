"""Tests for the proposed machine_account_creates_account detection."""
from __future__ import annotations

import datetime as dt

import pytest

from warden.detect import detect
from warden.events import IdentityChangeEvent
from warden.ingest import normalize

RULE = "machine_account_creates_account"
T0 = dt.datetime(2020, 9, 16, 9, 31, 19, 133272, tzinfo=dt.timezone.utc)


def _idc(ts, user, target, host="host-01", change="account_created", tier="unknown"):
    return IdentityChangeEvent(
        ts=ts,
        source="windows",
        host=host,
        user=user,
        asset_tier=tier,
        change_type=change,
        target_user=target,
    )


def test_positive_machine_account_creates_two_accounts():
    events = [
        _idc(T0, "machine-01$", "$"),
        _idc(T0 + dt.timedelta(seconds=54), "machine-01$", "$"),
    ]
    alerts = detect(normalize(events), only=[RULE])
    assert len(alerts) == 1
    a = alerts[0]
    assert a.rule == RULE
    assert "machine-01$" in a.users
    assert "host-01" in a.hosts
    assert a.detail["created_count"] == 2
    assert a.detail["actor_is_machine_account"] is True
    assert a.first_seen == T0


def test_near_miss_service_account_bulk_domain_join():
    base = dt.datetime(2020, 9, 16, 10, 5, 0, tzinfo=dt.timezone.utc)
    events = [
        _idc(base, "svc-domainjoin", "wks-4411$", host="host-02", tier="standard"),
        _idc(base + dt.timedelta(seconds=90), "svc-domainjoin", "wks-4412$", host="host-02", tier="standard"),
    ]
    assert detect(normalize(events), only=[RULE]) == []


def test_near_miss_single_creation_and_machine_password_reset():
    base = dt.datetime(2020, 9, 16, 10, 40, 0, tzinfo=dt.timezone.utc)
    events = [
        _idc(base, "machine-07$", "wks-9001$", host="host-04"),
        _idc(base + dt.timedelta(minutes=20), "machine-09$", "machine-09$",
             host="host-03", change="password_reset"),
    ]
    assert detect(normalize(events), only=[RULE]) == []


def test_deterministic_repeat_run():
    events = [
        _idc(T0, "machine-01$", "$"),
        _idc(T0 + dt.timedelta(seconds=54), "machine-01$", "$"),
    ]
    first = detect(normalize(events), only=[RULE])
    second = detect(normalize(events), only=[RULE])
    assert [x.id for x in first] == [x.id for x in second]


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__])
