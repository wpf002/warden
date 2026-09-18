# Playbook PB-033: Cloud Admin Privileges Granted

Scope: AdministratorAccess or similar attached, a wildcard inline policy, a user added to an admin group, or a console password set for another user. Detection is `iam_admin_grant`, MITRE T1098.003.

## Triage
1. Match the change to a ticket or infrastructure-as-code pipeline run. Console changes by humans to production IAM are the exception.
2. Check the actor's recent activity: new access keys, console logins without MFA, unusual regions.
3. Check the principal that received the rights.

## Containment
- Detach the policy or remove the group membership once confirmed unauthorised. Requires analyst approval.
- Disable the actor's access keys if the actor is compromised.
- Create a ticket and notify the SOC.

## False positive notes
- Break-glass role activation during an incident. It should be documented in the incident channel.
