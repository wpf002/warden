# Playbook PB-029: Remote-Service Fan-Out

Scope: one internal host opening SMB, RDP, WinRM, RPC, or SSH to five or more internal hosts within ten minutes. Detection is `lateral_movement_fanout`, MITRE T1021.

## Triage
1. Identify the account used on the targets (4624 type 3 or 10 on each target).
2. Check whether the source is an admin jump host or a management server; those fan out by design.
3. Look for services or tasks created on the targets right after (PsExec, WMI, scheduled tasks).

## Containment
- Isolate the source host when risk >= 80.
- Disable the account used for the connections. Requires analyst approval.
- Create a ticket and notify the SOC.

## False positive notes
- Vulnerability scanners, patching servers, and backup servers connect to many hosts. Exclude them by host.
