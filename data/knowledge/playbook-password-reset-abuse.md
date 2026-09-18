# Playbook PB-017: Clustered Password Resets

Scope: three or more resets of one account within an hour, or one operator resetting three or more accounts. Detection is `password_reset_abuse`, MITRE T1098.

## Triage
1. Helpdesk social engineering is a primary initial-access route. A caller claiming to be an executive locked out of their phone is the pattern.
2. For target clusters: contact the account owner out of band and ask whether they requested each reset.
3. For operator clusters: check the operator's queue. Bulk resets without matching tickets suggest a compromised helpdesk account or an insider.
4. Resets combined with MFA removal escalate to critical.

## Containment
- Suspend the operator's reset privileges pending review if resets lack tickets.
- Lock affected accounts that the owners did not request. Requires analyst approval (Policy SEC-012).
- Create a ticket and notify the SOC.

## False positive notes
- Onboarding days and incident recovery generate bulk resets that match tickets.
