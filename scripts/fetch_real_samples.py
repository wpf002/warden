"""Download the real-world log samples the `data/eval-real` suite runs on.

The samples are public attack recordings from EVTX-ATTACK-SAMPLES
(github.com/sbousseaden/EVTX-ATTACK-SAMPLES, GPL-3.0). They are not vendored into this
repo; this script fetches them into data/real/ (gitignored) and checks each hash.

    python scripts/fetch_real_samples.py
"""
from __future__ import annotations

import hashlib
import sys
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "real"
BASE = "https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/master/"

SAMPLES = {name: (f"{folder}/{name}", digest) for folder, name, digest in [
    ("Credential Access", "kerberos_pwd_spray_4771.evtx", "4a0a1c7132e216dbc704c806e9429df9ae3ac00485d5238e50c776e3099ae11d"),
    ("Credential Access", "CA_4624_4625_LogonType2_LogonProc_chrome.evtx", "75f199b68d473172705bf874720b01820317fdd7aa4843545c98720dd6de197f"),
    ("Persistence", "Network_Service_Guest_added_to_admins_4732.evtx", "9619b9d9d7bb8a277080167ff639fd9162e3d88d61d674cf1606beadce17ea5a"),
    ("Defense Evasion", "DE_Fake_ComputerAccount_4720.evtx", "8b0c2b1998bbd6292fbd23c2fbd954ed2a0db5ae38f39493e718262b215b4da9"),
    ("Credential Access", "sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx", "9a1689574ed08c1fb18e7ff3f3bed612109aedcb7bf8efbf3537d756e669e96f"),
    ("Defense Evasion", "DE_1102_security_log_cleared.evtx", "a0615707b547a2ac254688fd725c3c590f62440fc9b7947c2843dd40498a39e8"),
    ("Defense Evasion", "DE_104_system_log_cleared.evtx", "5579cdca073ee4864ea82d656aa2d25400b5c1e85b8e688db5d85f6dc558c2af"),
    ("Execution", "exec_sysmon_lobin_regsvr32_sct.evtx", "d6978888a7dead4523c01df417aa7ea6ad2599a5bbf1acd05d89882aac956442"),
    ("Execution", "sysmon_mshta_sharpshooter_stageless_meterpreter.evtx", "a2c396ac66aed02c0e36c6e467db3c3b83a57d003604ca79eb2a33175efcbad1"),
    ("Execution", "temp_scheduled_task_4698_4699.evtx", "a7decf0fbabc340e37de7e7c39fddd5398a7106a4f6acded0ea1d2ffa6bf8b70"),
    ("Lateral Movement", "LM_Remote_Service02_7045.evtx", "af758eb492b6d5ab6665f7e4c44b31490f57be78c37dc0a8b1da714bb0d3d458"),
    ("Other", "maldoc_mshta_via_shellbrowserwind_rundll32.evtx", "fd59102d39891a81ee0e002bec2a855998c57e6439a10608fd9f4b12861e34a5"),
    ("Lateral Movement", "LM_sysmon_psexec_smb_meterpreter.evtx", "18ffdda9c24e593d6b1414b6e05c7f7a5dbffb8588a387c165431b61ab52d76f"),
]}


def sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    bad = 0
    for name, (remote, digest) in SAMPLES.items():
        dest = OUT / name
        if dest.exists() and sha256(dest) == digest:
            print(f"ok       {name}")
            continue
        url = BASE + urllib.parse.quote(remote)
        with urllib.request.urlopen(url, timeout=60) as r:  # noqa: S310 - pinned public URL
            dest.write_bytes(r.read())
        if sha256(dest) != digest:
            print(f"MISMATCH {name}: hash differs from the pinned sample", file=sys.stderr)
            dest.unlink()
            bad += 1
        else:
            print(f"fetched  {name}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
