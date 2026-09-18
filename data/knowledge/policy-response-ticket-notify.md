# Response policy RP-003: create_ticket, notify, generate_report

- Low impact, reversible, always allowed without approval.
- Tickets carry the case id, the evidence, the model's analysis, and the guardrail log.
- Notifications go to the SOC on-call channel. Never notify the account under attack about its own compromise through a channel the attacker controls (its mailbox).
