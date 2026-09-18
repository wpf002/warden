# Playbook PB-012: Dormant Account Reactivated

Scope: a successful login on an account with no activity for 60 or more days. Detection is `dormant_account`, MITRE T1078.

## Triage
1. Identify the owner. Leavers, contractors whose contract ended, and test accounts are the usual dormant accounts, and none of them should be signing in.
2. Check the source IP and geo against the owner's past activity.
3. Check what the session did. Dormant accounts are valued because nobody watches them.

## Containment
- If the owner has left or cannot be identified: disable the account. Account lock requires analyst approval (Policy SEC-012).
- Create a ticket for identity governance to review why the account was still enabled.

## False positive notes
- Returning employees after parental or medical leave. HR can confirm.
- Seasonal accounts (audit, tax season) that wake on a schedule.
