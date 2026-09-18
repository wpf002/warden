# Playbook PB-011: MFA Factor Enrolled After a Suspicious Sign-In

Scope: a new MFA factor registered for an account within an hour of failures, MFA denials, or a sign-in from an unfamiliar country. Detection is `mfa_method_change`, MITRE T1556.006.

## Triage
1. This is how account takeover becomes persistent. After registering their own authenticator, the attacker no longer needs the victim to approve anything.
2. Identify the factor type and the device that registered it. A new authenticator app or phone number enrolled from the same IP as the suspicious sign-in is a confirmed takeover.
3. Check for the next steps: privileged group changes, mailbox forwarding rules, OAuth app consents.

## Containment
- Remove the new factor, revoke all sessions, and reset the password. Account lock requires analyst approval (Policy SEC-012).
- Create a ticket and contact the user out of band.

## Eradication and recovery
- Re-enroll MFA from a known-good device in person or over a verified video call.
- Require phishing-resistant MFA (FIDO2/WebAuthn) for the account.

## False positive notes
- Users replacing a lost phone often fail sign-in a few times and then enroll a new device. Verify with the user before containment if the sign-in came from their usual location.
