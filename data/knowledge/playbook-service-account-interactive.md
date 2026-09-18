# Playbook PB-013: Service Account Used Interactively

Scope: an account matching the service-account naming pattern (svc-*, sa-*) performs an interactive, RDP, or console logon. Detection is `service_account_interactive`, MITRE T1078.002.

## Triage
1. Service accounts should authenticate as services (logon type 5) or over the network (type 3). A console or RDP logon (types 2, 10) means a person typed the password.
2. Find who: correlate the host and time with badge, VPN, and jump-host records.
3. Check the account's privileges. Many service accounts are over-privileged, which is why attackers want them.

## Containment
- Rotate the service account credential and update dependent services. Coordinate with the owning team; rotation breaks things if done blind.
- Restrict the account with "Deny log on locally" and "Deny log on through Remote Desktop Services".
- Create a ticket and notify the SOC. No automated lock: locking a service account causes an outage.

## False positive notes
- Administrators debugging a service sometimes run it interactively. It is still a policy violation; the ticket should go to the owning team.
