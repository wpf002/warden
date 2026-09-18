"""T1098 Account Manipulation: helpdesk resets clustered on one target, or one operator
resetting many accounts in a short window. Social-engineered helpdesks are how several
large 2023-2024 intrusions started."""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from ..config import settings
from ..events import IdentityChangeEvent
from ..models import Alert
from . import Detection, register
from ._identity import is_privileged_group, norm_user


@register
class PasswordResetAbuse(Detection):
    id = "password_reset_abuse"
    name = "Clustered password resets"
    mitre = ["T1098"]
    event_kinds = ("identity",)
    window_sec = 3600
    playbook = "playbook-password-reset-abuse"

    def run(self, events: list[IdentityChangeEvent]) -> list[Alert]:
        window = timedelta(seconds=self.window_sec)
        resets = sorted((e for e in events if e.change_type in ("password_reset", "mfa_removed")), key=lambda e: e.ts)
        out: list[Alert] = []
        for mode in ("target", "operator"):
            groups: dict[str, list[IdentityChangeEvent]] = defaultdict(list)
            for e in resets:
                k = norm_user(e.target_user if mode == "target" else e.user)
                if k:
                    groups[k].append(e)
            for k, evs in groups.items():
                i = 0
                while i < len(evs):
                    j = i
                    while j + 1 < len(evs) and evs[j + 1].ts - evs[i].ts <= window:
                        j += 1
                    burst = evs[i:j + 1]
                    distinct = {norm_user(e.user if mode == "target" else e.target_user) for e in burst}
                    n = len(burst) if mode == "target" else len(distinct)
                    if n >= settings.reset_cluster:
                        targets = sorted({e.target_user for e in burst})
                        out.append(self.new_alert(
                            key=f"{mode}|{k}", first_seen=burst[0].ts, ts=burst[-1].ts,
                            title=(f"{len(burst)} resets of {targets[0]} in {self.window_sec // 60} min"
                                   if mode == "target" else
                                   f"{burst[0].user} reset {len(distinct)} accounts in {self.window_sec // 60} min"),
                            source_ip=burst[-1].source_ip, users=sorted({*targets, *(e.user for e in burst)} - {""}),
                            hosts=sorted({e.host for e in burst if e.host}), geo=burst[0].geo,
                            asset_tier="crown_jewel" if any(is_privileged_group(e.group) for e in burst) else "unknown",
                            last_seen=burst[-1].ts, failed_attempts=len(burst),
                            detail={"mode": mode, "resets": len(burst), "operators": sorted({e.user for e in burst}),
                                    "targets": targets[:20], "includes_mfa_removal": any(e.change_type == "mfa_removed" for e in burst)},
                            evidence=[{"ts": e.ts.isoformat(), "user": e.user, "host": e.host,
                                       "type": f"{e.change_type} {e.target_user}"} for e in burst[:25]],
                        ))
                        i = j + 1
                    else:
                        i += 1
        return out
