# Playbook PB-009: Credential Stuffing Response

Scope: failures across many accounts from many source IPs that share tooling (one user agent or one /24), each IP staying under per-IP thresholds. Detection is `credential_stuffing`, MITRE T1110.004.

## Triage
1. Confirm the distribution: more than 8 accounts and more than 4 IPs with at most a handful of attempts per IP is the firing condition. Residential proxy pools push the IP count into the hundreds.
2. Check for any success from the same IP pool. A success means that account's password is in a breach corpus and valid here; treat as compromised.
3. Check whether the targeted usernames exist. A high share of unknown accounts points at a generic combo list; a high share of valid ones points at a list built for this organisation.

## Containment
- Block the IPs in the pool at the edge or WAF when risk >= 80. The pool rotates, so blocking buys time rather than ending the attack.
- For any account that succeeded: lock, revoke sessions, force a reset. Account lock requires analyst approval (Policy SEC-012).
- Enable or tighten bot protection and rate limiting on the login endpoint.

## Eradication and recovery
- Force password resets for every targeted account that matches a known breach corpus entry.
- Require MFA for all targeted accounts before their next sign-in.

## False positive notes
- Load tests and synthetic monitoring use one user agent from several IPs. Check the change calendar and exclude known monitoring agents.
- Corporate egress NAT makes many users share one IP; that pattern is per-IP and does not match this rule.
