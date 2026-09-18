"""T1218 System Binary Proxy Execution and friends: signed Windows binaries used to
fetch or run attacker content. Each pattern is specific enough that the binary's
normal use does not match."""
from __future__ import annotations

from ..events import ProcessEvent
from ..models import Alert
from . import Detection, register
from ._endpoint import USER_WRITABLE, proc_alert, rx

PATTERNS = [
    ("mshta.exe", rx(r"https?:", r"javascript:", r"vbscript:", r"\.hta\b"), "T1218.005", "mshta running remote or HTA content"),
    ("rundll32.exe", rx(r"javascript:", r"url\.dll", r"ieframe\.dll", r"shdocvw\.dll", r"zipfldr\.dll", r"advpack\.dll",
                        r"pcwutl\.dll", r"shell32\.dll.*control_rundll", r"\.(jpg|jpeg|png|gif|dat|txt|tmp|bin|log)\b\s*,",
                        r"\\users\\public\\"), "T1218.011", "rundll32 proxying execution"),
    ("regsvr32.exe", rx(r"/i:\s*https?:", r"scrobj\.dll", r"\.sct\b"), "T1218.010", "regsvr32 loading a scriptlet"),
    ("certutil.exe", rx(r"-urlcache", r"-decode\b", r"-decodehex", r"-f\s+https?:", r"verifyctl.*https?:"), "T1105",
     "certutil downloading or decoding a payload"),
    ("bitsadmin.exe", rx(r"/transfer", r"/addfile", r"/setnotifycmdline"), "T1197", "BITS job fetching content"),
    ("msiexec.exe", rx(r"/q.*https?:", r"https?:.*/q"), "T1218.007", "msiexec installing from a URL silently"),
    ("wmic.exe", rx(r"/format:\s*\"?https?:", r"/format:.*\.xsl"), "T1220", "wmic running a remote XSL stylesheet"),
    ("installutil.exe", rx(r"/u\b", r"/logfile="), "T1218.004", "InstallUtil executing an assembly"),
    ("regasm.exe", rx(r"/u\b"), "T1218.009", "RegAsm executing an assembly"),
    ("cmstp.exe", rx(r"/s\b.*\.inf", r"/au\b"), "T1218.003", "CMSTP executing an INF"),
    ("hh.exe", rx(r"https?:", r"\.chm\b"), "T1218.001", "compiled HTML help running content"),
]


@register
class LolbinAbuse(Detection):
    id = "lolbin_abuse"
    name = "Living-off-the-land binary abuse"
    mitre = ["T1218", "T1105", "T1197", "T1220"]
    event_kinds = ("process",)
    window_sec = 0
    playbook = "playbook-lolbin-abuse"

    def run(self, events: list[ProcessEvent]) -> list[Alert]:
        out = []
        for e in events:
            if e.action != "start":
                continue
            for binary, pat, tech, what in PATTERNS:
                if e.process_name == binary and pat.search(e.command_line):
                    out.append(proc_alert(self, e, f"{what} on {e.host}", [tech], pattern=binary,
                                          user_writable_path=bool(USER_WRITABLE.search(e.command_line))))
                    break
        return out
