"""T1621 Multi-Factor Authentication Request Generation (push bombing).

The attacker has the password and hammers the push factor until the user taps approve
to make it stop. Signal: a run of denials or timeouts for one account in a short window,
scored much higher when an approval lands right after.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from ..config import settings
from ..events import AuthEvent
from ..models import Alert
from . import Detection, register

PUSH_REJECTS = {"mfa_denied", "mfa_timeout"}


@register
class MFAFatigue(Detection):
    id = "mfa_fatigue"
    name = "MFA push bombing"
    mitre = ["T1621"]
    event_kinds = ("auth",)
    window_sec = 900
    playbook = "playbook-mfa-fatigue"

    def run(self, events: list[AuthEvent], threshold: int | None = None, window_sec: int | None = None) -> list[Alert]:
        threshold = threshold or settings.mfa_threshold
        window_sec = window_sec or self.window_sec
        window = timedelta(seconds=window_sec)

        by_user: dict[str, list[AuthEvent]] = defaultdict(list)
        for e in events:
            by_user[e.user].append(e)

        out: list[Alert] = []
        for user, evs in by_user.items():
            evs.sort(key=lambda e: e.ts)
            rejects = [e for e in evs if e.event_type in PUSH_REJECTS]
            if len(rejects) < threshold:
                continue
            i = 0
            while i < len(rejects):
                j = i
                while j + 1 < len(rejects) and rejects[j + 1].ts - rejects[i].ts <= window:
                    j += 1
                burst = rejects[i:j + 1]
                i = j + 1
                if len(burst) < threshold:
                    continue
                last = burst[-1].ts
                approval = next(
                    (e for e in evs if e.event_type == "mfa_success" and last <= e.ts <= last + window), None
                )
                ips = sorted({e.source_ip for e in burst if e.source_ip})
                out.append(self.new_alert(
                    key=f"{user}|{ips[0] if ips else ''}", first_seen=burst[0].ts, ts=last,
                    title=f"MFA push bombing against {user} ({len(burst)} denied/timed-out prompts)"
                          + (" ending in an APPROVAL" if approval else ""),
                    source_ip=ips[0] if ips else "", related_ips=ips[1:], users=[user],
                    hosts=sorted({e.host for e in burst if e.host}),
                    geo=burst[0].geo, asset_tier=max((e.asset_tier for e in burst),
                                                     key=lambda t: {"crown_jewel": 2, "standard": 1}.get(t, 0)),
                    last_seen=last, window_sec=window_sec,
                    failed_attempts=len(burst), success_after_failures=approval is not None,
                    detail={"denied": sum(e.event_type == "mfa_denied" for e in burst),
                            "timed_out": sum(e.event_type == "mfa_timeout" for e in burst),
                            "approved_after": approval is not None,
                            "approved_at": approval.ts.isoformat() if approval else None,
                            "factor": burst[0].mfa_factor or "push",
                            "prompt_interval_sec": round(
                                (last - burst[0].ts).total_seconds() / max(1, len(burst) - 1))},
                    evidence=[{"ts": e.ts.isoformat(), "user": e.user, "host": e.host, "type": e.event_type}
                              for e in burst[:25]]
                             + ([{"ts": approval.ts.isoformat(), "user": user, "host": approval.host,
                                  "type": "mfa_success"}] if approval else []),
                ))
        return out
