# Playbook PB-037: Compute Launched in an Unused Region

Scope: instances, functions, or clusters created in a region outside WARDEN_AWS_REGIONS and never used before. Detection is `unusual_region`, MITRE T1535.

## Triage
1. Crypto-mining is the most common cause; check instance types (GPU families) and counts.
2. Identify the credential used and where else it has been active.

## Containment
- Terminate the resources after snapshotting for evidence.
- Apply a service control policy denying unused regions.
- Create a ticket and notify the SOC.

## False positive notes
- New regional deployments. Add the region to WARDEN_AWS_REGIONS when a team expands.
