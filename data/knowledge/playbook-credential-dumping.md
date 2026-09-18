# Playbook PB-022: LSASS and Credential Store Dumping

Scope: a process opening LSASS with memory-read rights, or command lines for procdump, comsvcs MiniDump, mimikatz, registry hive saves, or NTDS.dit extraction. Detection is `credential_dumping`, MITRE T1003.001, T1003.002, T1003.003.

## Triage
1. Treat every credential cached on the host as stolen: every user who logged on interactively since the last reboot, plus service account secrets.
2. On a domain controller, NTDS.dit extraction means every domain password hash is stolen. Escalate to incident command.
3. Identify the source process and how it got there; credential dumping is rarely the first step.

## Containment
- Isolate the host immediately when risk >= 80.
- Reset passwords for accounts that logged on to the host. For a DC compromise, reset krbtgt twice.
- Create a ticket and notify the SOC.

## False positive notes
- EDR agents, Windows Defender, and some backup agents open LSASS. They are allowlisted by image path in the rule; add others by exact signed path only.
