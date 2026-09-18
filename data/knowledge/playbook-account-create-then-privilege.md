# Playbook PB-015: New Account Granted Privilege

Scope: an account is created and added to a privileged group within an hour. Detection is `account_create_then_privilege`, MITRE T1136 then T1098.

## Triage
1. Legitimate onboarding almost never grants admin on day one. Treat as a persistence mechanism until a ticket proves otherwise.
2. Identify the creator. If the creator's own account is in an open incident, this is the attacker building a backdoor account.
3. Check the account name. Names that mimic built-ins (admin2, support, backup$) or trailing-$ machine-account lookalikes are deliberate.

## Containment
- Disable the new account and remove the group membership. Account lock requires analyst approval (Policy SEC-012).
- Investigate the creating account and lock it if it cannot be tied to an approved request.
- Create a ticket and notify the SOC.

## False positive notes
- Automated provisioning for admin tiers (PAM onboarding) creates and privileges accounts in one step. Those come from a known service identity.
