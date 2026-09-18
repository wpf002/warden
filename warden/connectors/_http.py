"""HTTP plumbing shared by the API connectors."""
from __future__ import annotations

import httpx

TIMEOUT = httpx.Timeout(20.0, connect=5.0)


def client(base_url: str, headers: dict | None = None, transport: httpx.BaseTransport | None = None) -> httpx.Client:
    """`transport` lets tests swap in httpx.MockTransport; production passes None."""
    return httpx.Client(base_url=base_url, headers=headers or {}, timeout=TIMEOUT, transport=transport)


def check(r: httpx.Response, what: str) -> httpx.Response:
    if r.status_code >= 400:
        raise RuntimeError(f"{what}: HTTP {r.status_code} {r.text[:200]}")
    return r
