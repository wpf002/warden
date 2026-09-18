# Playbook PB-036: Cloud Audit Logging Disabled

Scope: CloudTrail stopped or deleted, GuardDuty or Config disabled, flow logs or log groups deleted. Detection is `cloud_logging_disabled`, MITRE T1562.008.

## Triage
1. Treat as active compromise of the actor's identity until proven otherwise.
2. Everything the actor did after the change is invisible in that trail; check organisation trails and other regions.

## Containment
- Re-enable logging immediately (StartLogging, re-create the detector).
- Disable the actor's credentials. Requires analyst approval.
- Create a ticket and notify the SOC.

## False positive notes
- Trail consolidation projects. They happen through infrastructure-as-code with a change ticket.
