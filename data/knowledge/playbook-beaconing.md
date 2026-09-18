# Playbook PB-027: Periodic Beaconing

Scope: a host connecting to one external destination on a steady interval with low jitter. Detection is `beaconing`, MITRE T1071, T1573.

## Triage
1. Identify the process making the connections (Sysmon 3 or EDR). A signed updater is benign; an unsigned binary in a user folder is an implant.
2. Look up the destination: domain age, hosting provider, intel matches.
3. Check the interval. 60s, 300s, and 3600s with 10 to 20 percent jitter are default settings for common C2 frameworks.

## Containment
- Block the destination at the egress firewall when risk >= 80.
- Isolate the host if the process is confirmed malicious.
- Create a ticket and notify the SOC.

## False positive notes
- Telemetry agents, update checkers, and NTP are periodic. Maintain a destination allowlist for known software.
