# Response policy RP-001: block_ip

- Automatable when the rule's risk threshold is met (default 80, spray 70) and the target is not on the infrastructure safelist.
- The target must appear in the alert or incident evidence. The guardrail refuses anything else.
- Never block internal RFC1918 addresses at the perimeter; internal attackers are contained with host isolation.
- Default time to live is 24 hours. Permanent blocks need an analyst.
- Rollback: delete the deny rule by id. Rollback must succeed within 15 minutes (SEC-012 §4).
