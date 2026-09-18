# Playbook PB-016: Session Cookie Replay

Scope: one authenticated session id seen from a second IP and a different client mid-session. Detection is `session_anomaly`, MITRE T1550.004.

## Triage
1. An IP change alone happens on mobile networks. An IP change plus a different browser or OS on the same session is a stolen cookie, typically from an adversary-in-the-middle phishing kit or infostealer malware.
2. Check the original device for infostealer indicators.
3. Review what the replayed session did. MFA was already satisfied, so nothing stopped it.

## Containment
- Revoke all sessions and refresh tokens for the user. Lock requires analyst approval (Policy SEC-012).
- Block the replay IP when risk >= 80.
- Create a ticket and notify the SOC.

## Eradication and recovery
- Reset the password and re-enroll MFA; the phishing kit that stole the cookie may also have the password.
- Enable token binding or continuous access evaluation where the IdP supports it.

## False positive notes
- Users switching from a laptop to a phone do not share session ids across devices, so this rule rarely fires on them.
