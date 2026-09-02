# Playbook PB-004: Brute Force / Credential Stuffing Response

Scope: repeated failed authentication from a single source IP against one or more accounts.

## Triage
1. Confirm volume: >= 10 failures in 5 minutes from one IP is a confirmed brute-force pattern.
2. Check for a success after the failures. A success following the burst means the account is presumed compromised.
3. Check the asset tier. VPN gateways and domain controllers are crown jewels; escalate to high or critical.
4. Check the source. External IP with non-US geo raises severity. Internal IP may be a misconfigured service account (see FP notes).

## Containment
- Block the source IP at the perimeter firewall. Safe to automate when risk >= 80 and the IP is not on the safelist.
- If a login succeeded after the burst: lock the user account and force a password reset. Account lock requires analyst approval (Policy SEC-012).
- Create an incident ticket with the evidence attached.
- Notify the on-call SOC analyst.

## Eradication and recovery
- Review the account's sessions and MFA enrollments.
- Rotate credentials for any service account involved.

## False positive notes
- Backup and monitoring service accounts (svc-*) failing from internal IPs after a password rotation look like brute force. Verify with the change calendar before acting.
- Load balancer health checks from 10.0.0.1 / 10.0.0.2 are safelisted.
