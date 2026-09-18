# Playbook PB-018: Mass Account Lockouts

Scope: five or more distinct accounts locked out within fifteen minutes. Detection is `lockout_storm`, MITRE T1110.

## Triage
1. Usually the tail of a password spray that overshot the lockout threshold. Look for a correlated spray or stuffing alert.
2. A single source IP causing most lockouts means an attacker or a misconfigured service; many sources mean distributed stuffing or a DoS against the directory.
3. Check for any successful sign-ins among the targeted accounts in the same window.

## Containment
- Block the dominant source IP when it is external and risk >= 80.
- Do not bulk-unlock until the source is contained; the accounts will lock again.
- Create a ticket and notify the SOC and the helpdesk, who will field the calls.

## False positive notes
- An expired service credential on a shared host locks out everyone who uses it. The lockout source will be one internal host.
