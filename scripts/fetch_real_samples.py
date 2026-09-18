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

SAMPLES = {
    "kerberos_pwd_spray_4771.evtx": (
        "Credential Access/kerberos_pwd_spray_4771.evtx",
        "4a0a1c7132e216dbc704c806e9429df9ae3ac00485d5238e50c776e3099ae11d"),
    "CA_4624_4625_LogonType2_LogonProc_chrome.evtx": (
        "Credential Access/CA_4624_4625_LogonType2_LogonProc_chrome.evtx",
        "75f199b68d473172705bf874720b01820317fdd7aa4843545c98720dd6de197f"),
    "Network_Service_Guest_added_to_admins_4732.evtx": (
        "Persistence/Network_Service_Guest_added_to_admins_4732.evtx",
        "9619b9d9d7bb8a277080167ff639fd9162e3d88d61d674cf1606beadce17ea5a"),
    "DE_Fake_ComputerAccount_4720.evtx": (
        "Defense Evasion/DE_Fake_ComputerAccount_4720.evtx",
        "8b0c2b1998bbd6292fbd23c2fbd954ed2a0db5ae38f39493e718262b215b4da9"),
}


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
