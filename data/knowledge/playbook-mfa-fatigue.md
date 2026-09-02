# Playbook PB-008: MFA Fatigue / Push Bombing Response

Scope: a run of denied or timed-out MFA prompts for one account in a short window,
with or without an approval at the end. Detection is `mfa_fatigue`, MITRE T1621.

## Triage
1. Assume the password is already compromised. Push bombing only happens after the first factor is passed, so credential theft is a fact, not a hypothesis.
2. Check whether an approval followed the burst. Approval after five or more rejections is a presumed account compromise; treat as critical.
3. Identify the prompt source IP and geo. A steady prompt interval (roughly even spacing) indicates a script rather than a confused user.
4. Check for an MFA method change or a new factor enrolled in the hour after any approval. That is the attacker establishing persistence (T1556.006).

## Containment
- Block the source IP at the perimeter. Safe to automate when risk >= 80.
- If an approval followed the burst: lock the account, revoke sessions, force a password reset and MFA re-enrollment. Account lock requires analyst approval (Policy SEC-012).
- Create a ticket and contact the user out of band. Do not send the notification to the account under attack.

## Eradication and recovery
- Rotate the password; the burst proves it leaked.
- Re-enroll the second factor from a known-good device and remove any factor added during or after the burst.
- Where the IdP supports it, switch the account to number matching or WebAuthn. Number matching removes the tap-to-silence failure mode this attack depends on.

## False positive notes
- A user with a stale cached credential on a phone can generate repeated prompts they legitimately deny. Check whether all prompts originate from the user's own device and geo.
- Poor cell coverage produces timeouts without denials. A burst of pure timeouts from the user's usual IP is weak evidence; require denials or an off-geo source.
- MFA prompts during a scheduled password rotation window are expected. Check the change calendar.
