# Playbook PB-032: Traffic to a Known-Bad Indicator

Scope: a connection, DNS query, or sign-in involving an IP or domain in the intel table with confidence 60 or higher (Feodo C2, OTX pulse indicators). Detection is `intel_ioc_match`.

## Triage
1. Check the indicator's age and status. Feodo "offline" entries may be reassigned hosting IPs.
2. Identify the process or account involved.
3. Look for beaconing or data transfer to the same destination.

## Containment
- Block the indicator at the edge when risk >= 80.
- Isolate the host if a process on it is talking to active C2.
- Create a ticket and notify the SOC.

## False positive notes
- Shared hosting and CDN IPs appear in feeds. Tor exit nodes are context only and never alert on their own.
