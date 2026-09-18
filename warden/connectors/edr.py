"""EDR host containment.

crowdstrike  isolate_host: Falcon network containment. Rollback: lift containment.
             WARDEN_CS_BASE (default https://api.crowdstrike.com), WARDEN_CS_CLIENT_ID, WARDEN_CS_SECRET
defender     isolate_host: Microsoft Defender for Endpoint full isolation. Rollback: release.
             uses the WARDEN_ENTRA_* app registration with Machine.Isolate
"""
from __future__ import annotations

import os

from . import Connector, Receipt, register
from ._http import check, client
from .identity import _MsGraphBase


@register
class CrowdStrike(Connector):
    name = "crowdstrike"
    actions = ("isolate_host",)
    supports_rollback = True

    def __init__(self, dry_run=None, base=None, client_id=None, secret=None, transport=None):
        super().__init__(dry_run)
        self.base = base or os.environ.get("WARDEN_CS_BASE", "https://api.crowdstrike.com")
        self.cid = client_id or os.environ.get("WARDEN_CS_CLIENT_ID", "")
        self.secret = secret or os.environ.get("WARDEN_CS_SECRET", "")
        self.transport = transport
        self._http = None

    @property
    def http(self):
        if self._http is None:
            tok = check(client(self.base, transport=self.transport).post(
                "/oauth2/token", data={"client_id": self.cid, "client_secret": self.secret}), "falcon token").json()
            self._http = client(self.base, {"Authorization": f"Bearer {tok['access_token']}"}, self.transport)
        return self._http

    def _device(self, host: str) -> str:
        ids = check(self.http.get("/devices/queries/devices/v1", params={"filter": f"hostname:'{host}'"}),
                    "falcon device lookup").json().get("resources") or []
        if not ids:
            raise RuntimeError(f"no Falcon device with hostname {host}")
        return ids[0]

    def _act(self, name: str, device: str) -> None:
        check(self.http.post("/devices/entities/devices-actions/v2", params={"action_name": name},
                             json={"ids": [device]}), f"falcon {name}")

    def execute(self, action: str, target: str, alert) -> Receipt:
        dev = self._device(target)
        if self.dry_run:
            return self._dry(action, target, f"contain Falcon device {dev}", {"device": dev})
        self._act("contain", dev)
        return Receipt(self.name, action, target, True, f"Falcon device {dev} contained", undo={"device": dev})

    def rollback(self, receipt: Receipt) -> Receipt:
        if receipt.dry_run:
            return Receipt(self.name, receipt.action, receipt.target, True, "[dry-run] nothing to roll back", dry_run=True)
        self._act("lift_containment", receipt.undo["device"])
        return Receipt(self.name, receipt.action, receipt.target, True, f"containment lifted on {receipt.undo['device']}")


@register
class Defender(_MsGraphBase):
    name = "defender"
    actions = ("isolate_host",)
    supports_rollback = True
    scope = "https://api.securitycenter.microsoft.com/.default"
    base = "https://api.securitycenter.microsoft.com"

    def _machine(self, host: str) -> str:
        for flt in (f"computerDnsName eq '{host}'", f"startswith(computerDnsName,'{host}.')"):
            vals = check(self.http.get("/api/machines", params={"$filter": flt}), "mde lookup").json().get("value") or []
            if vals:
                return vals[0]["id"]
        raise RuntimeError(f"no Defender machine named {host}")

    def execute(self, action: str, target: str, alert) -> Receipt:
        mid = self._machine(target)
        if self.dry_run:
            return self._dry(action, target, f"fully isolate MDE machine {mid}", {"machine": mid})
        check(self.http.post(f"/api/machines/{mid}/isolate",
                             json={"Comment": f"Warden {alert.id}: {alert.title}"[:1000], "IsolationType": "Full"}),
              "mde isolate")
        return Receipt(self.name, action, target, True, f"MDE machine {mid} isolated", undo={"machine": mid})

    def rollback(self, receipt: Receipt) -> Receipt:
        if receipt.dry_run:
            return Receipt(self.name, receipt.action, receipt.target, True, "[dry-run] nothing to roll back", dry_run=True)
        check(self.http.post(f"/api/machines/{receipt.undo['machine']}/unisolate",
                             json={"Comment": "Warden rollback"}), "mde release")
        return Receipt(self.name, receipt.action, receipt.target, True, f"MDE machine {receipt.undo['machine']} released")
