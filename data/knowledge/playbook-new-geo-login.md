# Playbook PB-010: First-Seen Country or Device

Scope: a successful login from a country the user has never signed in from, once the user has enough history for "new" to mean something. Detection is `new_geo_login`, MITRE T1078.

## Triage
1. On its own this is a weak signal. Travel, VPNs, and mobile roaming produce it daily. Treat it as context and look for what surrounds it.
2. Escalate when it co-occurs with failures, MFA denials, a new device, or a sensitive action (MFA change, group change, mailbox rule) in the following hour. Correlation will usually have merged those into one incident.
3. Weight by asset tier. A first-seen country on the VPN gateway or a domain controller warrants a call to the user; on a wiki it warrants a note.

## Containment
- No automated containment for this rule alone. Create a ticket and notify the SOC.
- If the user does not recognise the sign-in: revoke sessions and reset the password. Account lock requires analyst approval (Policy SEC-012).

## False positive notes
- Business travel. Check the travel system or the user's calendar.
- Commercial VPN and privacy relay egress points in other countries.
- Users whose history is entirely on the internal network are baselined to the organisation's home countries (WARDEN_HOME_COUNTRIES).
