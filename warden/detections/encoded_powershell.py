"""T1059.001 PowerShell: encoded commands, hidden windows with download cradles, and
in-memory execution. Script-block logging (4104) catches the decoded content too."""
from __future__ import annotations

from ..events import ProcessEvent
from ..models import Alert
from . import Detection, register
from ._endpoint import proc_alert, rx

ENCODED = rx(r"\s-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{20,}")
CRADLE = rx(r"downloadstring\s*\(", r"downloadfile\s*\(", r"invoke-webrequest.*\|\s*iex", r"\biex\s*\(",
            r"invoke-expression", r"net\.webclient", r"frombase64string", r"start-bitstransfer",
            r"reflection\.assembly\]::load", r"virtualalloc", r"\[io\.compression\.")
HIDDEN = rx(r"-w(indowstyle)?\s+hid", r"-nop\b", r"-noni\b", r"-ep\s+bypass", r"-exec(utionpolicy)?\s+bypass")


@register
class EncodedPowerShell(Detection):
    id = "encoded_powershell"
    name = "Obfuscated or download-cradle PowerShell"
    mitre = ["T1059.001", "T1027"]
    event_kinds = ("process",)
    window_sec = 0
    playbook = "playbook-encoded-powershell"

    def run(self, events: list[ProcessEvent]) -> list[Alert]:
        out = []
        for e in events:
            cmd = e.command_line
            ps = e.process_name in ("powershell.exe", "pwsh.exe") or "powershell" in cmd.lower()
            if not ps or e.action not in ("start", "script_block"):
                continue
            signals = [n for n, p in (("encoded", ENCODED), ("download_cradle", CRADLE), ("hidden", HIDDEN)) if p.search(cmd)]
            # hidden flags alone are common in admin scripts; need encoding or a cradle
            if "encoded" in signals or "download_cradle" in signals:
                out.append(proc_alert(self, e, f"PowerShell {' + '.join(signals)} on {e.host}", signals=signals))
        return out
