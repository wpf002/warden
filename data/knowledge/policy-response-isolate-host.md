# Response policy RP-004: isolate_host

- Automatable when the rule's risk threshold is met and the target host appears in the alert or incident evidence.
- Isolation cuts all network traffic except the EDR management channel. It is reversible by lifting containment.
- Never auto-isolate domain controllers or hosts tagged crown_jewel; those need an analyst.
- Rollback: lift containment through the same EDR connector.
