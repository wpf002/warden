# Playbook PB-007: Impossible Travel Response

Scope: two successful authentications for one account from locations a person could not
travel between in the elapsed time. Detection is `impossible_travel`, MITRE T1078 Valid Accounts.

## Triage
1. Read the implied speed from the alert. Above 900 km/h with more than 500 km of separation is the firing condition; above 5,000 km/h is not a fast flight, it is two places at once.
2. Check whether the user agent or device fingerprint changed between the two logins. Same device plus new geo is usually a VPN. New device plus new geo is the strong signal.
3. Check the second IP against the intel table and against known corporate VPN egress ranges.
4. Check what the session did after the second login. A password change, an MFA enrollment, or a mailbox rule created within the hour escalates this to critical immediately.

## Containment
- Revoke all active sessions for the account and require re-authentication. Account lock requires analyst approval (Policy SEC-012).
- Do not auto-block either IP. One of the two is legitimate and blocking it locks out the real user. Block only after the analyst identifies which leg is hostile.
- Create a ticket and contact the user out of band (phone, not email) to confirm travel.

## Eradication and recovery
- If the user does not confirm the travel: reset the password, re-enroll MFA, and review everything the session touched.
- If the user confirms: record the geo and the egress IP as an exclusion for that user so the pair stops firing.

## False positive notes
- Corporate and consumer VPNs are the dominant false positive. Maintain an egress range exclusion list.
- Cloud sync clients and mobile carrier CGNAT can present a foreign egress IP while the user has not moved.
- Country-centroid geo means neighbouring-country hops are noisy; the 500 km floor exists for that reason.
- Roaming mobile devices at a border crossing produce genuine sub-900 km/h country changes and should not fire.
