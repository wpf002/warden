# Playbook PB-005: Password Spray Response

Scope: one source attempts a small number of passwords against many accounts to stay under per-account lockout thresholds.

## Signs
- Failures spread across 3+ distinct users from one IP inside a short window.
- Attempts spaced evenly, often 10 to 60 seconds apart.
- Targets identity providers (Okta, AD, O365) rather than a single host.

## Response
- Block the source IP. Safe to automate when risk >= 70.
- Do NOT lock all targeted accounts; that hands the attacker a denial of service. Lock only accounts with a success.
- Create a ticket, notify SOC, and check IdP for any success from that IP in the last 24 hours.
- Consider enabling smart lockout / conditional access for the IdP.

## MITRE
T1110.003 Brute Force: Password Spraying.
