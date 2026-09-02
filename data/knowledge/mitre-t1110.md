# MITRE ATT&CK T1110 Brute Force

Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when hashes are obtained.

Sub-techniques:
- T1110.001 Password Guessing: repeated attempts against one account.
- T1110.002 Password Cracking: offline attacks on captured hashes.
- T1110.003 Password Spraying: one or few passwords across many accounts to avoid lockouts.
- T1110.004 Credential Stuffing: reuse of leaked credential pairs.

Detection: monitor authentication logs for many failed logins from one source, especially followed by a success. Mitigations: account lockout policies, MFA, password policies, conditional access.
Tactic: Credential Access (TA0006).
