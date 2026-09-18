"""T1490 Inhibit System Recovery: shadow copies deleted, backups wiped, recovery mode
disabled. Ransomware does this minutes before encrypting; it is the last good moment to
isolate the host."""
from __future__ import annotations

from ..events import ProcessEvent
from ..models import Alert
from . import Detection, register
from ._endpoint import proc_alert, rx

CMD = rx(r"vssadmin(\.exe)?\s+(delete\s+shadows|resize\s+shadowstorage)", r"wmic(\.exe)?\s+shadowcopy\s+delete",
         r"win32_shadowcopy.*\.delete\(", r"get-wmiobject\s+win32_shadowcopy.*remove-wmiobject",
         r"wbadmin(\.exe)?\s+delete\s+(catalog|systemstatebackup|backup)",
         r"bcdedit(\.exe)?.*recoveryenabled\s+no", r"bcdedit(\.exe)?.*bootstatuspolicy\s+ignoreallfailures",
         r"diskshadow.*delete\s+shadows")


@register
class RansomwarePrecursor(Detection):
    id = "ransomware_precursor"
    name = "Backups or shadow copies destroyed"
    mitre = ["T1490"]
    event_kinds = ("process",)
    window_sec = 0
    playbook = "playbook-ransomware"

    def run(self, events: list[ProcessEvent]) -> list[Alert]:
        return [proc_alert(self, e, f"Recovery inhibited on {e.host}: {e.command_line[:80]}")
                for e in events if e.action in ("start", "script_block") and CMD.search(e.command_line)]
