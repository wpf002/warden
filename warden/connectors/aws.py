"""AWS response actions via boto3.

aws_nacl  block_ip:            DENY entries (ingress and egress) in a network ACL. Security
                               groups cannot deny, so NACLs are the right layer for a block.
aws_iam   lock_user:           inline deny-all policy plus every active access key deactivated
          disable_access_key:  deactivate the user's active access keys

Config: WARDEN_AWS_NACL_ID (the ACL to write), AWS_REGION, standard AWS credentials.
WARDEN_AWS_ENDPOINT points boto3 at an emulator (moto server) for sandbox runs.
"""
from __future__ import annotations

import json
import os

from . import Connector, Receipt, register

DENY_ALL = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]})
POLICY_NAME = "WardenDenyAll"


def _client(service: str):
    import boto3
    kw = {"region_name": os.environ.get("AWS_REGION", "us-east-1")}
    if os.environ.get("WARDEN_AWS_ENDPOINT"):
        kw["endpoint_url"] = os.environ["WARDEN_AWS_ENDPOINT"]
    return boto3.client(service, **kw)


@register
class AwsNacl(Connector):
    name = "aws_nacl"
    actions = ("block_ip",)
    supports_rollback = True
    RULE_RANGE = range(1, 100)     # below the usual allow rules at 100+, so the deny is evaluated first

    def __init__(self, dry_run=None, nacl_id: str | None = None, ec2=None):
        super().__init__(dry_run)
        self.nacl_id = nacl_id or os.environ.get("WARDEN_AWS_NACL_ID", "")
        self._ec2 = ec2

    @property
    def ec2(self):
        if self._ec2 is None:
            self._ec2 = _client("ec2")
        return self._ec2

    def _free_rules(self, egress: bool) -> int:
        acl = self.ec2.describe_network_acls(NetworkAclIds=[self.nacl_id])["NetworkAcls"][0]
        used = {e["RuleNumber"] for e in acl["Entries"] if e["Egress"] == egress}
        return next(n for n in self.RULE_RANGE if n not in used)

    def execute(self, action: str, target: str, alert) -> Receipt:
        if not self.nacl_id:
            return Receipt(self.name, action, target, False, "WARDEN_AWS_NACL_ID is not set")
        cidr = f"{target}/32"
        if self.dry_run:
            return self._dry(action, target, f"add DENY {cidr} in/out to {self.nacl_id}")
        undo = {"nacl_id": self.nacl_id, "entries": []}
        for egress in (False, True):
            n = self._free_rules(egress)
            self.ec2.create_network_acl_entry(NetworkAclId=self.nacl_id, RuleNumber=n, Protocol="-1",
                                              RuleAction="deny", Egress=egress, CidrBlock=cidr)
            undo["entries"].append({"rule": n, "egress": egress})
        return Receipt(self.name, action, target, True,
                       f"DENY {cidr} added to {self.nacl_id} as rules {[e['rule'] for e in undo['entries']]}", undo=undo)

    def rollback(self, receipt: Receipt) -> Receipt:
        if receipt.dry_run:
            return Receipt(self.name, receipt.action, receipt.target, True, "[dry-run] nothing to roll back", dry_run=True)
        for e in receipt.undo.get("entries", []):
            self.ec2.delete_network_acl_entry(NetworkAclId=receipt.undo["nacl_id"], RuleNumber=e["rule"], Egress=e["egress"])
        return Receipt(self.name, receipt.action, receipt.target, True,
                       f"removed DENY rules {[e['rule'] for e in receipt.undo.get('entries', [])]} from {receipt.undo.get('nacl_id')}")


@register
class AwsIam(Connector):
    name = "aws_iam"
    actions = ("lock_user", "disable_access_key")
    supports_rollback = True

    def __init__(self, dry_run=None, iam=None):
        super().__init__(dry_run)
        self._iam = iam

    @property
    def iam(self):
        if self._iam is None:
            self._iam = _client("iam")
        return self._iam

    def _active_keys(self, user: str) -> list[str]:
        return [k["AccessKeyId"] for k in self.iam.list_access_keys(UserName=user)["AccessKeyMetadata"]
                if k["Status"] == "Active"]

    def execute(self, action: str, target: str, alert) -> Receipt:
        keys = self._active_keys(target)
        if self.dry_run:
            extra = " and attach an inline deny-all policy" if action == "lock_user" else ""
            return self._dry(action, target, f"deactivate {len(keys)} access key(s) for {target}{extra}")
        for k in keys:
            self.iam.update_access_key(UserName=target, AccessKeyId=k, Status="Inactive")
        undo = {"user": target, "keys": keys, "policy": False}
        if action == "lock_user":
            self.iam.put_user_policy(UserName=target, PolicyName=POLICY_NAME, PolicyDocument=DENY_ALL)
            undo["policy"] = True
        return Receipt(self.name, action, target, True,
                       f"{len(keys)} key(s) deactivated" + (", deny-all policy attached" if undo["policy"] else ""), undo=undo)

    def rollback(self, receipt: Receipt) -> Receipt:
        if receipt.dry_run:
            return Receipt(self.name, receipt.action, receipt.target, True, "[dry-run] nothing to roll back", dry_run=True)
        u = receipt.undo
        for k in u.get("keys", []):
            self.iam.update_access_key(UserName=u["user"], AccessKeyId=k, Status="Active")
        if u.get("policy"):
            self.iam.delete_user_policy(UserName=u["user"], PolicyName=POLICY_NAME)
        return Receipt(self.name, receipt.action, receipt.target, True,
                       f"{len(u.get('keys', []))} key(s) reactivated" + (", deny-all removed" if u.get("policy") else ""))
