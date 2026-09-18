"""T1078 Valid Accounts: first successful login for a user from a new country or a new
device, once the user has enough history for "new" to mean something.

Weighted by asset tier: a new country on the VPN gateway matters more than on a wiki.
"""
from __future__ import annotations

from ..config import settings
from ..events import AuthEvent
from ..models import Alert
from . import Detection, register
from ._identity import History, device_fingerprint, norm_user


@register
class NewGeoLogin(Detection):
    id = "new_geo_login"
    name = "Login from a first-seen country or device"
    mitre = ["T1078"]
    event_kinds = ("auth",)
    window_sec = 0
    playbook = "playbook-new-geo-login"
    needs_history = True

    def run(self, events: list[AuthEvent]) -> list[Alert]:
        hist = History([e for e in self.prior if e.kind == "auth"])
        out: list[Alert] = []
        for e in sorted(events, key=lambda e: e.ts):
            u = norm_user(e.user)
            if e.event_type == "login_success" and u and hist.logins[u] >= settings.new_geo_min_history:
                # users seen only on the internal network are baselined to the org's home countries
                known = hist.geos[u] or set(settings.home_countries.upper().split(","))
                new_geo = bool(e.geo) and e.geo != "internal" and e.geo not in known
                fp = device_fingerprint(e)
                new_dev = bool(fp) and bool(hist.devices[u]) and fp not in hist.devices[u]
                if new_geo:   # a new device alone is too noisy to alert on; it raises a new geo
                    out.append(self.new_alert(
                        key=f"{u}|{e.geo}", first_seen=e.ts, ts=e.ts,
                        title=f"{e.user} signed in from {e.geo} for the first time"
                              + (" on a new device" if new_dev else ""),
                        source_ip=e.source_ip, users=[e.user], hosts=[e.host] if e.host else [],
                        geo=e.geo, asset_tier=e.asset_tier, last_seen=e.ts,
                        detail={"known_geos": sorted(known), "new_device": new_dev,
                                "device": fp, "prior_logins": hist.logins[u],
                                "asset_weight": {"crown_jewel": 3, "standard": 1}.get(e.asset_tier, 1)},
                        evidence=[{"ts": e.ts.isoformat(), "user": e.user, "host": e.host,
                                   "type": f"login_success from {e.geo} ({e.source_ip})"}],
                    ))
            hist.observe(e)
        return out
