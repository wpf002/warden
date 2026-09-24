"""A stateful stand-in for an Okta org and a CrowdStrike Falcon tenant, for demos without
vendor accounts. It serves only the operations Warden's connectors call, on the same
paths and methods as the real APIs (tests/test_api_contracts.py checks those against the
vendors' published definitions), and keeps state so a suspend or containment is visible
and a rollback undoes it.

    uvicorn warden.sandbox.vendors:app --port 5056
    WARDEN_OKTA_ORG=http://localhost:5056  WARDEN_CS_BASE=http://localhost:5056

GET /state shows every user and host with its current status and the request log.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Request

app = FastAPI(title="Warden vendor sandbox")

USERS = {login: {"id": f"00u{i:04d}", "login": login, "status": "ACTIVE", "sessions": 2}
         for i, login in enumerate(["jlee@corp.example", "asmith@corp.example", "mgarcia@corp.example",
                                    "john.doe@corp.example", "pwong@corp.example", "rkhan@corp.example",
                                    "tnguyen@corp.example", "dpatel@corp.example"], 1)}
# demo hosts: the scenario fixtures plus the machines in the real attack recordings
HOSTS = {h: {"device_id": f"dev{i:04d}", "hostname": h, "status": "normal"}
         for i, h in enumerate(["ws-17", "ws-20", "ws-31", "ws-44", "ws-52", "fs-02", "srv-db-01", "dc-01",
                                "msedgewin10", "iewin7", "pc01", "pc04", "win-77ltaphiq1r", "desktop1111",
                                "elastichost"], 1)}
LOG: list[dict] = []


def _log(req: Request, what: str) -> None:
    LOG.append({"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), "method": req.method,
                "path": req.url.path, "what": what})
    del LOG[:-200]


def _user(key: str) -> dict:
    for u in USERS.values():
        if key in (u["id"], u["login"], u["login"].split("@")[0]):
            return u
    raise HTTPException(404, {"errorCode": "E0000007", "errorSummary": f"Not found: Resource not found: {key} (User)"})


def _okta_auth(req: Request) -> None:
    if not req.headers.get("authorization", "").startswith("SSWS "):
        raise HTTPException(401, {"errorCode": "E0000011", "errorSummary": "Invalid token provided"})


# ------------------------------------------------------------------ Okta
@app.get("/api/v1/users/{uid}")
def okta_user(uid: str, request: Request):
    _okta_auth(request)
    u = _user(uid)
    return {"id": u["id"], "status": u["status"], "profile": {"login": u["login"]}}


@app.post("/api/v1/users/{uid}/lifecycle/suspend")
def okta_suspend(uid: str, request: Request):
    _okta_auth(request)
    u = _user(uid)
    if u["status"] != "ACTIVE":
        raise HTTPException(400, {"errorCode": "E0000001", "errorSummary": "Cannot suspend a user that is not active"})
    u["status"] = "SUSPENDED"
    _log(request, f"okta suspended {u['login']}")
    return {}


@app.post("/api/v1/users/{uid}/lifecycle/unsuspend")
def okta_unsuspend(uid: str, request: Request):
    _okta_auth(request)
    u = _user(uid)
    u["status"] = "ACTIVE"
    _log(request, f"okta unsuspended {u['login']}")
    return {}


@app.delete("/api/v1/users/{uid}/sessions", status_code=204)
def okta_clear_sessions(uid: str, request: Request):
    _okta_auth(request)
    u = _user(uid)
    u["sessions"] = 0
    _log(request, f"okta cleared sessions for {u['login']}")


# ------------------------------------------------------------------ Falcon
@app.post("/oauth2/token", status_code=201)
async def falcon_token(request: Request):
    form = await request.form()
    if not form.get("client_id") or not form.get("client_secret"):
        raise HTTPException(401, {"errors": [{"message": "access denied, invalid client credentials"}]})
    return {"access_token": "sandbox-token", "token_type": "bearer", "expires_in": 1799}


def _falcon_auth(req: Request) -> None:
    if req.headers.get("authorization") != "Bearer sandbox-token":
        raise HTTPException(401, {"errors": [{"code": 401, "message": "access denied, authorization failed"}]})


@app.get("/devices/queries/devices/v1")
def falcon_query(request: Request, filter: str = "", limit: int = 100, offset: str = "", sort: str = ""):
    _falcon_auth(request)
    name = filter.split(":", 1)[1].strip("'\"").lower() if filter.startswith("hostname:") else ""
    ids = [h["device_id"] for h in HOSTS.values() if not name or h["hostname"] == name]
    return {"meta": {"pagination": {"total": len(ids)}}, "resources": ids[:limit], "errors": []}


@app.post("/devices/entities/devices-actions/v2", status_code=202)
async def falcon_action(request: Request, action_name: str):
    _falcon_auth(request)
    body = await request.json()
    hosts = [h for h in HOSTS.values() if h["device_id"] in body.get("ids", [])]
    if not hosts:
        raise HTTPException(404, {"errors": [{"code": 404, "message": "device not found"}]})
    new = {"contain": "contained", "lift_containment": "normal"}.get(action_name)
    if new is None:
        raise HTTPException(400, {"errors": [{"code": 400, "message": f"invalid action_name {action_name}"}]})
    for h in hosts:
        h["status"] = new
        _log(request, f"falcon {action_name} {h['hostname']}")
    return {"resources": [{"id": h["device_id"], "path": ""} for h in hosts], "errors": []}


@app.get("/state")
def state():
    return {"okta_users": list(USERS.values()), "falcon_hosts": list(HOSTS.values()), "log": LOG[-50:]}
