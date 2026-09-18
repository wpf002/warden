# Playbook PB-034: Access Key Created for Another or Idle User

Scope: CreateAccessKey for a different user than the caller, or for a user idle 60+ days. Detection is `new_access_key`, MITRE T1098.001.

## Triage
1. Access keys outlive sessions. An attacker with console access creates keys to keep access after the session is revoked.
2. Check where the new key is used next (CloudTrail by accessKeyId).

## Containment
- Deactivate the new key when risk >= 80. Deactivation is reversible (Policy RP-005).
- Create a ticket and notify the SOC.

## False positive notes
- Administrators rotating keys for service users. They should do it through the secrets pipeline, not the console.
