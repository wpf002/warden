# Incident INC-2026-0311: VPN brute force from 203.0.113.0/24

Summary: 203.0.113.55 attempted 41 logins against user asmith on vpn-gw-01 over 6 minutes, then succeeded. Attacker established a VPN session for 22 minutes before containment.

What worked: firewall block within 3 minutes of the alert, account locked, password reset, sessions terminated.
What did not: the success-after-failure was missed for 9 minutes because the alert only counted failures.

Lessons:
- Treat any success after a brute-force burst as confirmed compromise, severity critical.
- The 203.0.113.0/24 range has been associated with repeated credential attacks; treat as hostile.
- Block at the perimeter first, then handle the account.
