"""Contract tests: every HTTP request a connector makes must exist in the vendor's published
API definition, with the right method, a declared path, declared query parameters, and the
required ones present. Specs come from scripts/fetch_api_specs.py; skipped when absent."""
from __future__ import annotations

import ast
import json
import re
import zipfile
from pathlib import Path

import httpx
import pytest

from warden.connectors.edr import CrowdStrike
from warden.connectors.identity import Okta
from warden.models import Alert

SPECS = Path(__file__).resolve().parents[1] / "data" / "specs"
OKTA = SPECS / "okta-management-2026.08.4.yaml"
FALCON = SPECS / "crowdstrike_falconpy-1.6.5-py3-none-any.whl"
ALERT = Alert(id="a1", rule="credential_dumping", first_seen="2026-09-02T09:00:00Z", ts="2026-09-02T09:00:00Z", last_seen="2026-09-02T09:00:00Z",
              title="t", hosts=["ws-17"], users=["jlee"])


class Spec:
    """{(METHOD, path template): [{"name", "in", "required", "description"}]}"""

    def __init__(self, ops: dict[tuple[str, str], list[dict]]):
        self.ops = ops
        self._rx = [(m, p, re.compile("^" + re.sub(r"\{[^}]+\}", "[^/]+", p) + "$")) for (m, p) in ops]

    def match(self, method: str, path: str) -> tuple[str, list[dict]]:
        for m, p, rx in self._rx:
            if m == method and rx.match(path):
                return p, self.ops[(m, p)]
        near = sorted({f"{m} {p}" for m, p, rx in self._rx if rx.match(path)})
        raise AssertionError(f"{method} {path} is not in the vendor API (same path: {near or 'none'})")

    def check(self, req: httpx.Request, base_path: str = "") -> str:
        path = req.url.path[len(base_path):] if base_path else req.url.path
        tmpl, params = self.match(req.method, path)
        query = {p["name"]: p for p in params if p.get("in") == "query"}
        for k in req.url.params:
            assert k in query, f"{req.method} {tmpl}: query param {k!r} not declared ({sorted(query)})"
        for name, p in query.items():
            if p.get("required"):
                assert name in req.url.params, f"{req.method} {tmpl}: required query param {name!r} missing"
        if any(p.get("in") == "body" and p.get("required") for p in params):
            assert req.content, f"{req.method} {tmpl}: required body missing"
        return tmpl


@pytest.fixture(scope="module")
def okta_spec() -> Spec:
    if not OKTA.exists():
        pytest.skip("run scripts/fetch_api_specs.py")
    yaml = pytest.importorskip("yaml")
    doc = yaml.load(OKTA.read_text(), Loader=getattr(yaml, "CSafeLoader", yaml.SafeLoader))
    ops = {}
    for path, item in doc["paths"].items():
        shared = item.get("parameters", [])
        for method, op in item.items():
            if method in ("get", "post", "put", "patch", "delete"):
                ps = [p for p in shared + op.get("parameters", []) if "$ref" not in p]
                ops[(method.upper(), path)] = ps
    return Spec(ops)


@pytest.fixture(scope="module")
def falcon_spec() -> Spec:
    if not FALCON.exists():
        pytest.skip("run scripts/fetch_api_specs.py")
    ops = {}
    with zipfile.ZipFile(FALCON) as z:
        for name in z.namelist():
            if not re.match(r"falconpy/_endpoint/_[a-z0-9_]+\.py$", name):
                continue
            tree = ast.parse(z.read(name).decode())
            for node in tree.body:
                if isinstance(node, ast.Assign) and isinstance(node.value, ast.List):
                    for op in ast.literal_eval(node.value):
                        ops[(op[1], op[2].split("?")[0])] = op[5] if len(op) > 5 else []
    return Spec(ops)


class Recorder:
    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.calls.append(req)
        for (m, frag), resp in self.routes.items():
            if req.method == m and frag in req.url.path:
                return resp
        return httpx.Response(404, json={})


def test_okta_requests_match_the_okta_api(okta_spec):
    rec = Recorder({("GET", "/api/v1/users/"): httpx.Response(200, json={"id": "00u1"}),
                    ("POST", "/lifecycle/"): httpx.Response(200, json={}),
                    ("DELETE", "/sessions"): httpx.Response(204)})
    c = Okta(dry_run=False, org="https://acme.okta.com", token="t", transport=httpx.MockTransport(rec))
    c.rollback(c.execute("lock_user", "jlee@corp.example", ALERT))
    used = [okta_spec.check(r) for r in rec.calls]
    assert used == ["/api/v1/users/{id}", "/api/v1/users/{id}/lifecycle/suspend", "/api/v1/users/{userId}/sessions",
                    "/api/v1/users/{id}/lifecycle/unsuspend"], used


def test_falcon_requests_match_the_falcon_api(falcon_spec):
    rec = Recorder({("POST", "/oauth2/token"): httpx.Response(201, json={"access_token": "z"}),
                    ("GET", "/devices/queries/devices/v1"): httpx.Response(200, json={"resources": ["dev9"]}),
                    ("POST", "/devices/entities/devices-actions/v2"): httpx.Response(202, json={})})
    c = CrowdStrike(dry_run=False, base="https://api.crowdstrike.com", client_id="a", secret="b",
                    transport=httpx.MockTransport(rec))
    c.rollback(c.execute("isolate_host", "ws-17", ALERT))
    used = [falcon_spec.check(r) for r in rec.calls]
    assert "/devices/entities/devices-actions/v2" in used
    act = next(p for p in falcon_spec.ops[("POST", "/devices/entities/devices-actions/v2")] if p["name"] == "action_name")
    for r in rec.calls:
        if "devices-actions" in r.url.path:
            assert r.url.params["action_name"] in act["description"]
            assert list(json.loads(r.content)) == ["ids"]
    # the FQL filter the lookup sends must use a field Falcon documents for device queries
    lookup = next(r for r in rec.calls if r.url.path == "/devices/queries/devices/v1")
    assert lookup.url.params["filter"].split(":")[0] == "hostname"
