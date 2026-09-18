# Playbook PB-024: Event Log Cleared

Scope: Security or System log cleared (1102, 104), or a command that clears logs or removes audit policy. Detection is `log_clearing`, MITRE T1070.001, T1562.002.

## Triage
1. There is almost no legitimate reason to clear the Security log on a production system. Assume an intruder is covering tracks.
2. Identify the account that cleared it. That account is compromised or malicious.
3. Pull what survived: forwarded copies in the SIEM, Sysmon, EDR telemetry.

## Containment
- Isolate the host when risk >= 80.
- Disable the account that cleared the log pending review. Requires analyst approval.
- Create a ticket and notify the SOC.

## False positive notes
- Lab and golden-image builds clear logs before sealing. They run on build hosts that should be excluded by host.
