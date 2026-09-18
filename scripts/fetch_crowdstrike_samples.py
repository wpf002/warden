"""Download CrowdStrike Falcon sample logs for the `crowdstrike` adapter.

The samples are the pipeline test inputs in Elastic's integrations repo
(github.com/elastic/integrations, packages/crowdstrike, Elastic License 2.0): FDR sensor
telemetry for Windows, Linux and macOS, and Streaming API detection summaries. Field values
are anonymized. Not vendored; fetched into data/real/crowdstrike/ (gitignored) at a pinned
commit and checked against pinned hashes.

    python scripts/fetch_crowdstrike_samples.py
    warden run --log data/real/crowdstrike/fdr-test-windows.log
"""
from __future__ import annotations

import hashlib
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "real" / "crowdstrike"
COMMIT = "1161c101c7cc011b527532913cd7702011113464"
BASE = f"https://raw.githubusercontent.com/elastic/integrations/{COMMIT}/packages/crowdstrike/data_stream/"

SAMPLES = {
    "fdr-test-windows.log": ("fdr/_dev/test/pipeline/test-windows.log", "6e8116e1f24b7318df544bcf542a690f128509ad428d943b6c4b919f5c47efef"),
    "fdr-test-fdr.log": ("fdr/_dev/test/pipeline/test-fdr.log", "45215e9f99830efca7eb55f116ec619d66eb4ae39a192c6e4d5676ca604103e0"),
    "fdr-test-linux.log": ("fdr/_dev/test/pipeline/test-linux.log", "0b6c73550dc835ea2ea01f3594bb46d6a9f63c89b8144fa974ae1b1c893c1e53"),
    "fdr-test-macos.log": ("fdr/_dev/test/pipeline/test-macos.log", "b3141674cc64b44b65083d63a4e3c4c158f51c105d7b52549e41fc2f291306bc"),
    "falcon-test-falcon-detection-summary.log": ("falcon/_dev/test/pipeline/test-falcon-detection-summary.log", "80b32d49d283c42de0ea175acc8e444d9538102d26e064d67760da96b4260e2c"),
    "falcon-test-falcon-epp-detection-summary.log": ("falcon/_dev/test/pipeline/test-falcon-epp-detection-summary.log", "186f81f19312f831609eca0de7d3744ecc21c4719d81a26d8e1db919877a2b75"),
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
        with urllib.request.urlopen(BASE + remote, timeout=60) as r:  # noqa: S310 - pinned public URL
            dest.write_bytes(r.read())
        if sha256(dest) != digest:
            print(f"MISMATCH {name}: hash differs from the pinned sample", file=sys.stderr)
            dest.unlink()
            bad += 1
        else:
            print(f"fetched  {name}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
