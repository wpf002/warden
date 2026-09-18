"""Exercise real response connectors against local sandboxes, live (no dry run):

  * aws_nacl, aws_iam   against moto server, an AWS API emulator  (default http://127.0.0.1:5055)
  * smtp                against Mailpit, a real SMTP server         (default 127.0.0.1:1025, API :8025)

Each check executes the action, verifies the change through the service's own API, rolls
it back, and verifies the rollback. Nothing here touches a real cloud account.

    docker run -d -p 1025:1025 -p 8025:8025 axllent/mailpit
    moto_server -p 5055 &
    python scripts/sandbox_connectors.py
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.request
from datetime import datetime, timezone

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1]))
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_REGION", "us-east-1")
os.environ.setdefault("WARDEN_AWS_ENDPOINT", "http://127.0.0.1:5055")

from warden.connectors.aws import AwsIam, AwsNacl, _client  # noqa: E402
from warden.connectors.comms import Smtp  # noqa: E402
from warden.models import Alert  # noqa: E402

NOW = datetime.now(timezone.utc)
ALERT = Alert(id="ALT-SANDBOX1", ts=NOW, rule="brute_force", title="sandbox check", first_seen=NOW, last_seen=NOW,
              source_ip="203.0.113.99", users=["compromised-user"], hosts=["ws-17"])
results = []


def check(name, cond, detail=""):
    results.append({"check": name, "ok": bool(cond), "detail": detail})
    print(f"{'PASS' if cond else 'FAIL'}  {name}  {detail}")


def aws_nacl():
    ec2 = _client("ec2")
    vpc = ec2.create_vpc(CidrBlock="10.50.0.0/16")["Vpc"]["VpcId"]
    acl = ec2.create_network_acl(VpcId=vpc)["NetworkAcl"]["NetworkAclId"]
    conn = AwsNacl(dry_run=False, nacl_id=acl)
    r = conn.execute("block_ip", "203.0.113.99", ALERT)
    entries = ec2.describe_network_acls(NetworkAclIds=[acl])["NetworkAcls"][0]["Entries"]
    deny = [e for e in entries if e["CidrBlock"] == "203.0.113.99/32" and e["RuleAction"] == "deny"]
    check("aws_nacl block_ip adds ingress+egress DENY", r.ok and len(deny) == 2, r.detail)
    rb = conn.rollback(r)
    entries = ec2.describe_network_acls(NetworkAclIds=[acl])["NetworkAcls"][0]["Entries"]
    check("aws_nacl rollback removes both entries",
          rb.ok and not [e for e in entries if e["CidrBlock"] == "203.0.113.99/32"], rb.detail)


def aws_iam():
    iam = _client("iam")
    user = f"compromised-user-{int(time.time())}"
    iam.create_user(UserName=user)
    keys = [iam.create_access_key(UserName=user)["AccessKey"]["AccessKeyId"] for _ in range(2)]
    conn = AwsIam(dry_run=False)
    r = conn.execute("lock_user", user, ALERT)
    status = {k["AccessKeyId"]: k["Status"] for k in iam.list_access_keys(UserName=user)["AccessKeyMetadata"]}
    policies = iam.list_user_policies(UserName=user)["PolicyNames"]
    check("aws_iam lock_user deactivates keys and attaches deny-all",
          r.ok and all(status[k] == "Inactive" for k in keys) and "WardenDenyAll" in policies, r.detail)
    rb = conn.rollback(r)
    status = {k["AccessKeyId"]: k["Status"] for k in iam.list_access_keys(UserName=user)["AccessKeyMetadata"]}
    check("aws_iam rollback reactivates keys and removes the policy",
          rb.ok and all(status[k] == "Active" for k in keys) and not iam.list_user_policies(UserName=user)["PolicyNames"],
          rb.detail)


def smtp():
    api = os.environ.get("WARDEN_MAILPIT_API", "http://127.0.0.1:8025")
    conn = Smtp(dry_run=False, host=os.environ.get("WARDEN_SMTP_HOST", "127.0.0.1"),
                port=int(os.environ.get("WARDEN_SMTP_PORT", "1025")), sender="warden@sandbox.local", to="soc@sandbox.local")
    r = conn.execute("notify", "soc", ALERT)
    time.sleep(0.5)
    msgs = json.loads(urllib.request.urlopen(f"{api}/api/v1/messages", timeout=10).read())["messages"]
    hit = [m for m in msgs if m["Subject"] == "[Warden] sandbox check"]
    check("smtp notify delivers to the SMTP server", r.ok and bool(hit), f"{r.detail}; mailpit has {len(hit)} matching")


if __name__ == "__main__":
    for fn in (aws_nacl, aws_iam, smtp):
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            check(fn.__name__, False, f"{type(e).__name__}: {e}")
    ok = sum(r["ok"] for r in results)
    print(f"\n{ok}/{len(results)} sandbox checks passed")
    sys.exit(0 if ok == len(results) else 1)
