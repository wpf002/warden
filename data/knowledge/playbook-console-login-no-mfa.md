# Playbook PB-038: Cloud Console Login Without MFA

Scope: an IAM user or root signing in to the AWS console without MFA. Detection is `console_login_no_mfa`, MITRE T1078.004.

## Triage
1. Root without MFA is critical regardless of source.
2. For IAM users, check the source IP and whether the user normally uses the console at all.

## Containment
- Require MFA through an IAM policy condition. Create a ticket and notify the SOC.

## False positive notes
- Legacy IAM users before SSO migration. Track them to retirement rather than excluding them.
