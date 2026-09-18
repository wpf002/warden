"""Download the vendor API definitions the connector contract tests check against.

Free stand-ins for sandbox tenants: every request the Okta and CrowdStrike connectors
make is validated against the vendor's own published API definition.

    okta     OpenAPI 3 spec, github.com/okta/okta-management-openapi-spec (Apache-2.0)
    falcon   crowdstrike-falconpy wheel from PyPI (Unlicense); its _endpoint modules list
             every Falcon API operation with method, path and parameters

    python scripts/fetch_api_specs.py
    pytest tests/test_api_contracts.py
"""
from __future__ import annotations

import hashlib
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "specs"
FILES = {
    "okta-management-2026.08.4.yaml": (
        "https://raw.githubusercontent.com/okta/okta-management-openapi-spec/master/dist/2026.08.4/"
        "management-oneOfInheritance-noExamples.yaml",
        "ac1e43e149ae37ea863c42c3af5c2d290d4ae7f4e0a17314790f66db9d0d862f"),
    "crowdstrike_falconpy-1.6.5-py3-none-any.whl": (
        "https://files.pythonhosted.org/packages/py3/c/crowdstrike-falconpy/crowdstrike_falconpy-1.6.5-py3-none-any.whl",
        "60010b5f79ab6628831edbdcf6bf855af00bc6fd46f34fa3c9b139e7495766d4"),
}


def sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    bad = 0
    for name, (url, digest) in FILES.items():
        dest = OUT / name
        if dest.exists() and sha256(dest) == digest:
            print(f"ok       {name}")
            continue
        with urllib.request.urlopen(url, timeout=120) as r:  # noqa: S310 - pinned public URL
            dest.write_bytes(r.read())
        if sha256(dest) != digest:
            print(f"MISMATCH {name}", file=sys.stderr)
            dest.unlink()
            bad += 1
        else:
            print(f"fetched  {name}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
