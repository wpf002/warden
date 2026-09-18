"""Download a real multi-week log for building behavioral baselines.

OpenSSH auth log from a real internet-facing server, about 4 weeks (Dec 10 to Jan 7), from
Loghub (He et al., "Loghub: A Large Collection of System Log Datasets", zenodo.org/records/8196385).
Not vendored; fetched into data/real/baseline/ (gitignored) and checked against a pinned hash.

    python scripts/fetch_baseline_logs.py
    warden ingest --log data/real/baseline/SSH.log --format sshd
    warden baseline rebuild --days 30 --until latest
"""
from __future__ import annotations

import hashlib
import io
import sys
import tarfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "real" / "baseline"
URL = "https://zenodo.org/records/8196385/files/SSH.tar.gz?download=1"
SHA256 = ""  # pinned after the first verified fetch


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    dest = OUT / "SSH.log"
    if dest.exists():
        print(f"ok       {dest.relative_to(ROOT)}")
        return 0
    with urllib.request.urlopen(URL, timeout=120) as r:  # noqa: S310 - pinned public URL
        blob = r.read()
    digest = hashlib.sha256(blob).hexdigest()
    if SHA256 and digest != SHA256:
        print(f"MISMATCH SSH.tar.gz: {digest}", file=sys.stderr)
        return 1
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as t:
        member = next(m for m in t.getmembers() if m.name.endswith("SSH.log"))
        dest.write_bytes(t.extractfile(member).read())
    print(f"fetched  {dest.relative_to(ROOT)}  sha256 {digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
