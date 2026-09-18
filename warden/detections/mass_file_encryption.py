"""T1486 Data Encrypted for Impact: one process renaming or rewriting many files on one
host in a minute, most of them gaining the same unfamiliar extension, or dropping ransom
notes."""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import timedelta

from ..config import settings
from ..events import FileEvent
from ..models import Alert
from . import Detection, register
from ._endpoint import rx

NOTE = rx(r"(readme|read_me|how_to|how-to|restore|recover|decrypt|help_decrypt)[^\\]*\.(txt|html?|hta)$")
COMMON = {".tmp", ".log", ".txt", ".docx", ".xlsx", ".pdf", ".jpg", ".png", ".dll", ".exe", ".dat", ".json", ".xml",
          ".etl", ".db", ".ini", ".lnk", ".cache", ".bak", ".zip", ".pf"}


def _ext(p: str) -> str:
    name = p.replace("/", "\\").rsplit("\\", 1)[-1]
    return "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""


@register
class MassFileEncryption(Detection):
    id = "mass_file_encryption"
    name = "Mass file encryption or ransom notes"
    mitre = ["T1486"]
    event_kinds = ("file",)
    window_sec = 60
    playbook = "playbook-ransomware"

    def run(self, events: list[FileEvent]) -> list[Alert]:
        window = timedelta(seconds=self.window_sec)
        groups: dict[tuple, list[FileEvent]] = defaultdict(list)
        for e in events:
            if e.action in ("rename", "modify", "create"):
                groups[(e.host, e.process_name)].append(e)
        out = []
        for (host, proc), evs in groups.items():
            evs.sort(key=lambda e: e.ts)
            notes = [e for e in evs if NOTE.search(e.path)]
            i = 0
            while i < len(evs):
                j = i
                while j + 1 < len(evs) and evs[j + 1].ts - evs[i].ts <= window:
                    j += 1
                burst = evs[i:j + 1]
                exts = Counter(_ext(e.path) for e in burst if e.action in ("rename", "create"))
                top, n = exts.most_common(1)[0] if exts else ("", 0)
                if len(burst) >= settings.encryption_min_files and top not in COMMON and n >= len(burst) * 0.5:
                    out.append(self.new_alert(
                        key=f"{host}|{proc}|{burst[0].ts.isoformat()}", first_seen=burst[0].ts, ts=burst[-1].ts,
                        title=f"{proc or 'A process'} rewrote {len(burst)} files to '{top}' on {host} in "
                              f"{int((burst[-1].ts - burst[0].ts).total_seconds())}s"
                              + (f"; {len(notes)} ransom notes" if notes else ""),
                        source_ip=burst[0].source_ip, users=sorted({e.user for e in burst if e.user}), hosts=[host],
                        asset_tier=burst[0].asset_tier, last_seen=burst[-1].ts,
                        detail={"files": len(burst), "extension": top, "process": proc,
                                "ransom_notes": [e.path for e in notes[:5]], "sample": [e.path for e in burst[:5]]},
                        evidence=[{"ts": e.ts.isoformat(), "user": e.user, "host": host, "type": f"{e.action} {e.path}"}
                                  for e in burst[:20]],
                    ))
                    i = j + 1
                else:
                    i += 1
            if notes and not any(a.hosts == [host] for a in out):
                e = notes[0]
                out.append(self.new_alert(
                    key=f"{host}|{proc}|note", first_seen=e.ts, ts=notes[-1].ts,
                    title=f"Ransom note dropped on {host}: {e.path.rsplit(chr(92), 1)[-1]}",
                    users=[e.user] if e.user else [], hosts=[host], last_seen=notes[-1].ts,
                    detail={"ransom_notes": [n.path for n in notes[:10]], "process": proc},
                    evidence=[{"ts": n.ts.isoformat(), "user": n.user, "host": host, "type": f"create {n.path}"}
                              for n in notes[:10]]))
        return out
