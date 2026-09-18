"""Response connectors: request shapes against each vendor API (httpx MockTransport),
AWS round trips against moto in-process, and the guardrail rule that an action without
rollback never auto-executes."""
import json
from datetime import datetime, timezone
from urllib.parse import parse_qs

import httpx
import pytest

from warden import actions, connectors, guardrails
from warden.config import settings
from warden.connectors.comms import Jira, PagerDuty, ServiceNow, Slack
from warden.connectors.edr import CrowdStrike, Defender
from warden.connectors.firewall import PaloAlto
from warden.connectors.identity import Entra, Okta
from warden.models import Alert, Analysis, RecommendedAction

NOW = datetime(2026, 9, 2, tzinfo=timezone.utc)
ALERT = Alert(id="ALT-TEST0001", ts=NOW, rule="credential_dumping", title="lsass read", first_seen=NOW, last_seen=NOW,
              source_ip="203.0.113.9", users=["jlee@corp.example"], hosts=["ws-17"])


class Recorder:
    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.calls.append((req.method, req.url.path, req))
        for (m, frag), resp in self.routes.items():
            if req.method == m and frag in str(req.url):
                return resp(req) if callable(resp) else resp
        return httpx.Response(404, text=f"no route {req.method} {req.url}")


def _t(rec):
    return httpx.MockTransport(rec)


def test_okta_suspend_and_unsuspend():
    rec = Recorder({("GET", "/api/v1/users/"): httpx.Response(200, json={"id": "00u1"}),
                    ("POST", "/lifecycle/suspend"): httpx.Response(200, json={}),
                    ("DELETE", "/sessions"): httpx.Response(204),
                    ("POST", "/lifecycle/unsuspend"): httpx.Response(200, json={})})
    c = Okta(dry_run=False, org="https://acme.okta.com", token="t", transport=_t(rec))
    r = c.execute("lock_user", "jlee@corp.example", ALERT)
    assert r.ok and r.undo == {"uid": "00u1"}
    assert rec.calls[0][2].headers["authorization"] == "SSWS t"
    assert "jlee%40corp.example" in str(rec.calls[0][2].url)
    assert c.rollback(r).ok and rec.calls[-1][1].endswith("/unsuspend")


def test_okta_dry_run_changes_nothing():
    rec = Recorder({("GET", "/api/v1/users/"): httpx.Response(200, json={"id": "00u1"})})
    r = Okta(dry_run=True, org="https://acme.okta.com", token="t", transport=_t(rec)).execute("lock_user", "x", ALERT)
    assert r.dry_run and r.detail.startswith("[dry-run]")
    assert [m for m, *_ in rec.calls] == ["GET"]


def test_entra_disable_and_revoke():
    tok = Recorder({("POST", "/oauth2/v2.0/token"): httpx.Response(200, json={"access_token": "abc"})})
    rec = Recorder({("PATCH", "/v1.0/users/"): httpx.Response(204), ("POST", "/revokeSignInSessions"): httpx.Response(200, json={})})
    c = Entra(dry_run=False, tenant="t1", client_id="c", secret="s", transport=_t(rec), token_transport=_t(tok))
    r = c.execute("lock_user", "jlee@corp.example", ALERT)
    assert r.ok and json.loads(rec.calls[0][2].content) == {"accountEnabled": False}
    assert parse_qs(tok.calls[0][2].content.decode())["scope"] == ["https://graph.microsoft.com/.default"]
    c.rollback(r)
    assert json.loads(rec.calls[-1][2].content) == {"accountEnabled": True}


def test_crowdstrike_contain_and_lift():
    rec = Recorder({("POST", "/oauth2/token"): httpx.Response(201, json={"access_token": "z"}),
                    ("GET", "/devices/queries/devices/v1"): httpx.Response(200, json={"resources": ["dev9"]}),
                    ("POST", "/devices/entities/devices-actions/v2"): httpx.Response(202, json={})})
    c = CrowdStrike(dry_run=False, base="https://api.crowdstrike.com", client_id="a", secret="b", transport=_t(rec))
    r = c.execute("isolate_host", "ws-17", ALERT)
    act = [x for x in rec.calls if "devices-actions" in x[1]][0][2]
    assert r.ok and act.url.params["action_name"] == "contain" and json.loads(act.content) == {"ids": ["dev9"]}
    c.rollback(r)
    assert rec.calls[-1][2].url.params["action_name"] == "lift_containment"


def test_crowdstrike_unknown_host_fails_cleanly(monkeypatch):
    rec = Recorder({("POST", "/oauth2/token"): httpx.Response(201, json={"access_token": "z"}),
                    ("GET", "/devices/queries/devices/v1"): httpx.Response(200, json={"resources": []})})
    monkeypatch.setattr(settings, "connectors", "isolate_host=crowdstrike")
    connectors.reset()
    connectors._INSTANCES["crowdstrike"] = CrowdStrike(dry_run=False, base="https://x", client_id="a", secret="b",
                                                       transport=_t(rec))
    res = actions.execute(ALERT, RecommendedAction(action="isolate_host", target="nope"))
    assert res.status == "failed" and "no Falcon device" in res.detail
    connectors.reset()


def test_defender_isolate_and_release():
    tok = Recorder({("POST", "/oauth2/v2.0/token"): httpx.Response(200, json={"access_token": "abc"})})
    rec = Recorder({("GET", "/api/machines"): httpx.Response(200, json={"value": [{"id": "m1"}]}),
                    ("POST", "/isolate"): httpx.Response(201, json={}), ("POST", "/unisolate"): httpx.Response(201, json={})})
    c = Defender(dry_run=False, tenant="t", client_id="c", secret="s", transport=_t(rec), token_transport=_t(tok))
    r = c.execute("isolate_host", "ws-17", ALERT)
    assert r.ok and json.loads(rec.calls[-1][2].content)["IsolationType"] == "Full"
    assert c.rollback(r).ok and rec.calls[-1][1] == "/api/machines/m1/unisolate"


def test_panos_register_and_unregister():
    ok = httpx.Response(200, text='<response status="success"></response>')
    rec = Recorder({("POST", "/api/"): ok})
    c = PaloAlto(dry_run=False, host="https://fw", key="k", tag="warden-block", transport=_t(rec))
    r = c.execute("block_ip", "203.0.113.9", ALERT)
    cmd = parse_qs(rec.calls[0][2].content.decode())["cmd"][0]
    assert r.ok and "<register>" in cmd and 'ip="203.0.113.9"' in cmd and 'timeout="86400"' in cmd
    c.rollback(r)
    assert "<unregister>" in parse_qs(rec.calls[-1][2].content.decode())["cmd"][0]


def test_panos_error_response_is_a_failure():
    rec = Recorder({("POST", "/api/"): httpx.Response(200, text='<response status="error"><msg>bad key</msg></response>')})
    with pytest.raises(RuntimeError):
        PaloAlto(dry_run=False, host="https://fw", key="k", transport=_t(rec)).execute("block_ip", "1.2.3.4", ALERT)


def test_notifications_and_tickets():
    rec = Recorder({("POST", "hooks.slack"): httpx.Response(200, text="ok"),
                    ("POST", "events.pagerduty"): httpx.Response(202, json={"status": "success"}),
                    ("POST", "/rest/api/3/issue"): httpx.Response(201, json={"key": "SEC-42"}),
                    ("POST", "/api/now/table/incident"): httpx.Response(201, json={"result": {"number": "INC001"}})})
    t = _t(rec)
    assert Slack(dry_run=False, webhook="https://hooks.slack.com/x", transport=t).execute("notify", "soc", ALERT).ok
    pd = PagerDuty(dry_run=False, routing_key="rk", transport=t)
    r = pd.execute("notify", "soc", ALERT)
    body = json.loads(rec.calls[-1][2].content)
    assert body["dedup_key"] == "warden-ALT-TEST0001" and body["event_action"] == "trigger"
    pd.rollback(r)
    assert json.loads(rec.calls[-1][2].content)["event_action"] == "resolve"
    j = Jira(dry_run=False, base="https://acme.atlassian.net", email="a", token="b", project="SEC", transport=t)
    assert j.execute("create_ticket", "x", ALERT).detail == "Jira SEC-42 created"
    assert json.loads(rec.calls[-1][2].content)["fields"]["project"] == {"key": "SEC"}
    sn = ServiceNow(dry_run=False, base="https://acme.service-now.com", user="u", password="p", transport=t)
    assert "INC001" in sn.execute("create_ticket", "x", ALERT).detail


def test_real_connectors_default_to_dry_run(monkeypatch):
    monkeypatch.setattr(settings, "live_actions", False)
    assert Okta(org="https://x", token="t").dry_run is True
    monkeypatch.setattr(settings, "live_actions", True)
    assert Okta(org="https://x", token="t").dry_run is False


# ---------------------------------------------------------------- AWS against moto in-process
@pytest.fixture()
def aws(monkeypatch):
    moto = pytest.importorskip("moto")
    for k, v in {"AWS_ACCESS_KEY_ID": "x", "AWS_SECRET_ACCESS_KEY": "x", "AWS_REGION": "us-east-1"}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("WARDEN_AWS_ENDPOINT", raising=False)
    with moto.mock_aws():
        yield


def test_aws_nacl_round_trip(aws):
    from warden.connectors.aws import AwsNacl, _client
    ec2 = _client("ec2")
    acl = ec2.create_network_acl(VpcId=ec2.create_vpc(CidrBlock="10.9.0.0/16")["Vpc"]["VpcId"])["NetworkAcl"]["NetworkAclId"]
    c = AwsNacl(dry_run=False, nacl_id=acl)
    r1 = c.execute("block_ip", "203.0.113.9", ALERT)
    r2 = c.execute("block_ip", "203.0.113.10", ALERT)          # second block takes the next free rule number
    rules = [e["rule"] for e in r1.undo["entries"] + r2.undo["entries"]]
    assert rules == [1, 1, 2, 2]
    c.rollback(r1)
    left = {e["CidrBlock"] for e in ec2.describe_network_acls(NetworkAclIds=[acl])["NetworkAcls"][0]["Entries"]
            if e["RuleAction"] == "deny"}
    assert left == {"203.0.113.10/32"}


def test_aws_iam_disable_key_round_trip(aws):
    from warden.connectors.aws import AwsIam, _client
    iam = _client("iam")
    iam.create_user(UserName="deploy-bot")
    key = iam.create_access_key(UserName="deploy-bot")["AccessKey"]["AccessKeyId"]
    c = AwsIam(dry_run=False)
    r = c.execute("disable_access_key", "deploy-bot", ALERT)
    assert iam.list_access_keys(UserName="deploy-bot")["AccessKeyMetadata"][0]["Status"] == "Inactive"
    assert not r.undo["policy"]
    c.rollback(r)
    assert iam.list_access_keys(UserName="deploy-bot")["AccessKeyMetadata"][0]["Status"] == "Active"
    assert key in r.undo["keys"]


# ---------------------------------------------------------------- guardrails + rollback plumbing
def _an(*acts, risk=95):
    return Analysis(explanation="x", mitre_attack="T1003", risk_score=risk, severity="critical",
                    false_positive_likelihood="low", recommended_actions=[RecommendedAction(action=a, target=t) for a, t in acts])


def test_action_without_rollback_never_auto_executes(monkeypatch):
    class NoUndo(connectors.Connector):
        name = "noundo"
        actions = ("isolate_host",)
    connectors._REGISTRY["noundo"] = NoUndo
    monkeypatch.setattr(settings, "connectors", "isolate_host=noundo")
    connectors.reset()
    [d] = guardrails.evaluate(ALERT, _an(("isolate_host", "ws-17")))
    assert d.verdict == "approve" and "no rollback" in d.why
    connectors.reset()
    del connectors._REGISTRY["noundo"]


def test_isolate_binds_to_evidence_and_spares_crown_jewels():
    ds = guardrails.evaluate(ALERT, _an(("isolate_host", "ws-17"), ("isolate_host", "dc-01")))
    assert [d.verdict for d in ds] == ["execute", "deny"]
    cj = ALERT.model_copy(update={"asset_tier": "crown_jewel"})
    assert guardrails.evaluate(cj, _an(("isolate_host", "ws-17")))[0].verdict == "approve"


def test_rollback_from_a_case(tmp_path):
    from warden import feedback
    from warden.models import Case
    from warden.store import CaseStore
    store = CaseStore(tmp_path)
    res = actions.execute(ALERT, RecommendedAction(action="block_ip", target="203.0.113.9"))
    case = Case(alert=ALERT, actions=[res])
    store.save(case)
    feedback.rollback_action(case, 0, store, actor="ana")
    assert case.actions[0].status == "rolled_back"
    assert store.audit_log()[0]["action"] == "rollback_action"
    with pytest.raises(ValueError):
        feedback.rollback_action(case, 0, store, actor="ana")     # can't roll back twice
