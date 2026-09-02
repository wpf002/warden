# Policy SEC-012: Automated Response Guardrails

1. Automated actions are limited to: block_ip, create_ticket, notify, generate_report.
2. lock_user always requires human approval by a SOC analyst.
3. No automated block against IPs on the infrastructure safelist.
4. Any auto-executed action must be reversible within 15 minutes and logged with the alert id, the evidence, and the model output that recommended it.
5. Risk score threshold for auto-execution is 80 unless the playbook states a lower one for that rule.
6. Every LLM recommendation is advisory. The guardrail layer, not the model, decides what runs.
