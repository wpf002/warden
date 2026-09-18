# Playbook PB-045: EDR Detection

Scope: a detection raised by the endpoint agent itself (CrowdStrike Falcon), severity medium or higher. Detection is `edr_alert`. The MITRE technique comes from the EDR's tactic: credential access T1003, execution T1059, persistence T1547, defense evasion T1027, lateral movement T1021, command and control T1071.

## Triage
1. Read the EDR's own verdict: severity, tactic, technique, and whether it prevented the action (PatternDisposition "Prevention") or only detected it.
2. Check the process, parent, command line and file hash. A known admin tool run by its usual admin is the most common false positive.
3. Look for correlated identity or network alerts on the same host or user. An EDR detection inside an incident outranks one on its own.

## Containment
- Critical or high with credential access, lateral movement or command and control: isolate the host when risk >= 80.
- Prevented detections with no other activity: ticket only.
- Create a ticket and notify the SOC.

## False positive notes
- Adware/PUP classifications are informational; they are raised only at medium or higher.
- Red team and vulnerability scanners trip EDR rules. Exclude by host during scheduled exercises.
