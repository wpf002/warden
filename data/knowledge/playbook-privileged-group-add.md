# Playbook PB-014: Account Added to a Privileged Group

Scope: an account added to Domain Admins, Enterprise Admins, Administrators, Global Administrator, Okta Super Admins, or another group on the privileged list. Detection is `privileged_group_add`, MITRE T1098 and T1078.004.

## Triage
1. Find the change request. Every privileged add should map to an approved ticket. No ticket means treat as unauthorised.
2. Check who made the change and from where. An admin acting from an unfamiliar IP, or an account that is itself part of an open incident, escalates this to critical.
3. Check the member. Guest, built-in, service, and newly created accounts being granted admin are classic persistence.
4. Changes outside the change window are weighted higher.

## Containment
- Remove the member from the group once the analyst confirms it is unauthorised. Removal requires analyst approval.
- Lock the account that made the change if it is not a known administrator acting on a ticket (Policy SEC-012).
- Create a ticket and notify the SOC immediately.

## False positive notes
- Break-glass procedures during an outage. The on-call record will show it.
- Scheduled access reviews that re-add members after cleanup. They run inside the change window.
