# Playbook PB-039: Mail Forwarded Outside the Organisation

Scope: an inbox rule or mailbox setting forwarding or redirecting mail to an external address, especially one that also deletes or hides the original. Detection is `mailbox_forwarding_rule`, MITRE T1114.003, T1564.008.

## Triage
1. Business email compromise sets a forwarding rule within minutes of taking a mailbox, usually for invoices and payment keywords.
2. Check the sign-in that preceded the rule creation.

## Containment
- Remove the rule, revoke sessions, and reset the password. Account lock requires analyst approval.
- Create a ticket and notify the SOC and finance, who should hold pending payments.

## False positive notes
- Executives forwarding to a personal address. It is still a policy violation.
