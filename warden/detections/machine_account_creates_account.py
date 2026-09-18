"""T1136.002 Create Account: Domain Account, performed *by* a computer account.

Domain joins and provisioning run under a human or service identity. A computer
account (sAMAccountName ending in "$") showing up as the actor on an account
creation is the fingerprint of MachineAccountQuota / computer-object abuse: an
attacker holding one host's machine credentials spawns extra computer objects to
set up resource-based constrained delegation or sAMAccountName spoofing
(noPac, CVE-2021-42278 / CVE-2021-42287).

Narrow on purpose: the actor must be a machine account, and it must create at
least two accounts inside the window on the same host. Bulk provisioning by a
service account, a single pre-created computer object, and machine password
rotation are all ignored.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from ..events import IdentityChangeEvent
from ..models import Alert
from . import Detection, register


def _norm_name(name: str) -> str:
    """Lowercase, strip DOMAIN\\ prefix and @realm suffix. Keeps a trailing '$'."""
    n = (name or "").strip()
    if "\\" in n:
        n = n.split("\\")[-1]
    if "@" in n:
        n = n.split("@")[0]
    return n.lower()


def _is_machine_account(name: str) -> bool:
    return _norm_name(name).endswith("$")


@register
class MachineAccountCreatesAccount(Detection):
    id = "machine_account_creates_account"
    name = "Computer account creating domain accounts"
    mitre = ["T1136.002", "T1098"]
    event_kinds = ("identity",)
    window_sec = 900
    playbook = "playbook-machine-account-creates-account"

    min_creates = 2
    max_listed = 10

    def run(self, events: list[IdentityChangeEvent]) -> list[Alert]:
        window = timedelta(seconds=self.window_sec)
        creates = sorted(
            [
                e
                for e in self._select(events)
                if e.change_type == "account_created" and _is_machine_account(e.user)
            ],
            key=lambda e: (e.ts, _norm_name(e.user), _norm_name(e.target_user), e.host),
        )
        if not creates:
            return []

        groups: dict[tuple[str, str], list[IdentityChangeEvent]] = defaultdict(list)
        for e in creates:
            groups[(_norm_name(e.user), e.host)].append(e)

        out: list[Alert] = []
        for (actor, host), evs in sorted(groups.items()):
            i = 0
            while i < len(evs):
                j = i + 1
                while j < len(evs) and (evs[j].ts - evs[i].ts) <= window:
                    j += 1
                burst = evs[i:j]
                if len(burst) < self.min_creates:
                    i += 1
                    continue

                first = burst[0]
                last = burst[-1]
                targets = [b.target_user for b in burst if b.target_user]
                machine_targets = [t for t in targets if _is_machine_account(t)]
                span = (last.ts - first.ts).total_seconds()
                tiers = {b.asset_tier for b in burst}
                tier = "crown_jewel" if "crown_jewel" in tiers else first.asset_tier

                out.append(
                    self.new_alert(
                        key=f"{actor}|{host}|{first.ts.isoformat()}",
                        first_seen=first.ts,
                        ts=last.ts,
                        last_seen=last.ts,
                        title=(
                            f"Computer account {first.user} created {len(burst)} domain "
                            f"account(s) in {int(span)}s on {host or 'unknown host'}"
                        ),
                        source_ip=first.source_ip,
                        users=sorted({b.user for b in burst} | set(targets) - {""}),
                        hosts=sorted({b.host for b in burst} - {""}),
                        geo=first.geo,
                        asset_tier=tier,
                        detail={
                            "actor": first.user,
                            "actor_is_machine_account": True,
                            "created_count": len(burst),
                            "created_targets": targets[: self.max_listed],
                            "machine_account_targets": len(machine_targets),
                            "span_seconds": round(span, 1),
                            "window_sec": self.window_sec,
                            "why": (
                                "Account creation is normally performed by a user or "
                                "service identity. A computer account acting as the "
                                "creator suggests stolen machine credentials being used "
                                "against MachineAccountQuota to add computer objects for "
                                "RBCD or sAMAccountName spoofing (noPac)."
                            ),
                            "next_step": (
                                "Confirm in Security 4741/4720 who the caller was, check "
                                "msDS-AllowedToActOnBehalfOfOtherIdentity on nearby "
                                "servers, and treat the actor host as compromised."
                            ),
                        },
                        evidence=[
                            {
                                "ts": b.ts.isoformat(),
                                "user": b.user,
                                "host": b.host,
                                "type": f"account_created -> {b.target_user or '(unnamed)'}",
                            }
                            for b in burst[: self.max_listed]
                        ],
                    )
                )
                i = j
        return out
