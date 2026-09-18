# Playbook PB-023: New Autostart Entry

Scope: a scheduled task, service, or Run/Winlogon/IFEO registry entry pointing at a shell, a script host, or a user-writable path. Detection is `persistence_mechanism`, MITRE T1053.005, T1543.003, T1547.001.

## Triage
1. Read what the autostart runs. cmd.exe /c with encoded PowerShell, a binary in Users\Public or ProgramData, or a random eight-character service name are attacker patterns.
2. A service installed remotely (7045 on the target, with an ADMIN$ path) is PsExec-style lateral movement.
3. Check who created it and from where.

## Containment
- Disable and delete the task or service once collected for forensics.
- Isolate the host if the payload is confirmed malicious.
- Create a ticket and notify the SOC.

## False positive notes
- Software installers create services and Run keys constantly. Anything under Program Files signed by a known vendor is out of scope for this rule.
