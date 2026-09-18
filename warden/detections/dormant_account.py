"""T1078 Valid Accounts: a successful login on an account with no activity for
WARDEN_DORMANT_DAYS (default 60). Forgotten accounts keep old passwords and nobody
notices when they wake up."""
from __future__ import annotations

from ..config import settings
from ..events import AuthEvent
from ..models import Alert
from . import Detection, register
from ._identity import History, norm_user


@register
class DormantAccount(Detection):
    id = "dormant_account"
    name = "Dormant account reactivated"
    mitre = ["T1078"]
    event_kinds = ("auth",)
    window_sec = 0
    playbook = "playbook-dormant-account"
    needs_history = True

    def run(self, events: list[AuthEvent]) -> list[Alert]:
        hist = History(self.prior)
        out: list[Alert] = []
        fired: set[str] = set()
        for e in sorted(events, key=lambda e: e.ts):
            u = norm_user(e.user)
            last = hist.last_seen.get(u)
            if e.event_type == "login_success" and last and u not in fired:
                idle = (e.ts - last).days
                if idle >= settings.dormant_days:
                    fired.add(u)
                    out.append(self.new_alert(
                        key=u, first_seen=e.ts, ts=e.ts,
                        title=f"{e.user} signed in after {idle} days of inactivity",
                        source_ip=e.source_ip, users=[e.user], hosts=[e.host] if e.host else [], geo=e.geo,
                        asset_tier=e.asset_tier, last_seen=e.ts,
                        detail={"idle_days": idle, "last_seen": last.isoformat(), "threshold_days": settings.dormant_days},
                        evidence=[{"ts": e.ts.isoformat(), "user": e.user, "host": e.host,
                                   "type": f"login_success after {idle}d idle"}],
                    ))
            hist.observe(e)
        return out
