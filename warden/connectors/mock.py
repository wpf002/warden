"""Records what it would do. The default for every action until a real connector is mapped."""
from __future__ import annotations

from ..config import settings
from . import Connector, Receipt, register


@register
class Mock(Connector):
    name = "mock"
    actions = ("block_ip", "lock_user", "isolate_host", "disable_access_key", "create_ticket", "notify", "generate_report")
    supports_rollback = True

    def execute(self, action: str, target: str, alert) -> Receipt:
        if action == "generate_report":
            path = settings.state_dir / f"report-{alert.id}.md"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"# {alert.title}\n\n{alert.model_dump_json(indent=2)}\n")
            return Receipt(self.name, action, target, True, f"report written to {path}", undo={"path": str(path)})
        what = {"block_ip": f"[mock firewall] deny rule added for {target} (ttl 24h)",
                "lock_user": f"[mock IAM] account {target} locked, sessions revoked, reset required",
                "isolate_host": f"[mock EDR] host {target} network-contained",
                "disable_access_key": f"[mock cloud IAM] access keys for {target} deactivated",
                "create_ticket": f"[mock ITSM] ticket SEC-{alert.id[-4:]} created: {alert.title}",
                "notify": f"[mock notify] {target or 'soc'} paged: {alert.title}"}[action]
        return Receipt(self.name, action, target, True, what, undo={"mock": True})

    def rollback(self, receipt: Receipt) -> Receipt:
        return Receipt(self.name, receipt.action, receipt.target, True, f"[mock] rolled back {receipt.action} on {receipt.target}")
