# Playbook PB-030: Port Scan

Scope: one source probing 20 or more ports on a host, or one port on 20 or more hosts, within five minutes. Detection is `port_scan`, MITRE T1046.

## Triage
1. External scans are background noise; alert only when the source then connects successfully to a service.
2. Internal scans from a workstation are reconnaissance by an intruder already inside. Escalate.
3. Correlate with other alerts on the source host.

## Containment
- No automated containment for this rule alone. Create a ticket and notify the SOC.
- For an internal source with other alerts, isolate the host.

## False positive notes
- Authorised vulnerability scanners. Exclude by source IP with the "known_scanner" reason so the exclusion is visible.
