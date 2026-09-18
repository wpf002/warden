"""Firewall blocks.

paloalto  block_ip: tag the IP through the PAN-OS User-ID XML API so a dynamic address
          group referenced by a deny rule picks it up; the tag carries a timeout.
          Rollback: unregister the tag. WARDEN_PANOS_HOST, WARDEN_PANOS_KEY, WARDEN_PANOS_TAG
"""
from __future__ import annotations

import os
from xml.sax.saxutils import quoteattr

from . import Connector, Receipt, register
from ._http import check, client


@register
class PaloAlto(Connector):
    name = "paloalto"
    actions = ("block_ip",)
    supports_rollback = True

    def __init__(self, dry_run=None, host=None, key=None, tag=None, ttl: int = 86400, transport=None):
        super().__init__(dry_run)
        self.key = key or os.environ.get("WARDEN_PANOS_KEY", "")
        self.tag = tag or os.environ.get("WARDEN_PANOS_TAG", "warden-block")
        self.ttl = ttl
        self.http = client(host or os.environ.get("WARDEN_PANOS_HOST", ""), transport=transport)

    def _uid(self, verb: str, ip: str) -> None:
        timeout = f' timeout="{self.ttl}"' if verb == "register" else ""
        cmd = (f"<uid-message><version>2.0</version><type>update</type><payload><{verb}>"
               f"<entry ip={quoteattr(ip)}><tag><member{timeout}>{self.tag}</member></tag></entry>"
               f"</{verb}></payload></uid-message>")
        r = check(self.http.post("/api/", data={"type": "user-id", "key": self.key, "cmd": cmd}), f"pan-os {verb}")
        if 'status="success"' not in r.text:
            raise RuntimeError(f"pan-os {verb}: {r.text[:200]}")

    def execute(self, action: str, target: str, alert) -> Receipt:
        if self.dry_run:
            return self._dry(action, target, f"tag {target} with {self.tag} for {self.ttl}s")
        self._uid("register", target)
        return Receipt(self.name, action, target, True, f"{target} tagged {self.tag} (ttl {self.ttl}s)",
                       undo={"ip": target, "tag": self.tag})

    def rollback(self, receipt: Receipt) -> Receipt:
        if receipt.dry_run:
            return Receipt(self.name, receipt.action, receipt.target, True, "[dry-run] nothing to roll back", dry_run=True)
        self._uid("unregister", receipt.undo["ip"])
        return Receipt(self.name, receipt.action, receipt.target, True, f"{receipt.undo['ip']} untagged")
