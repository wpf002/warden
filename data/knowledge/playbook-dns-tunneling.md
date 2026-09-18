# Playbook PB-028: DNS Tunneling

Scope: many unique, long, high-entropy subdomains under one parent domain, or a flood of TXT queries. Detection is `dns_tunneling`, MITRE T1071.004, T1048.003.

## Triage
1. Decode a sample of the subdomain labels (base32 or hex is common). Readable data confirms exfiltration.
2. Identify the querying process on the host.
3. Check the parent domain's registration date and name servers.

## Containment
- Sinkhole the parent domain at the resolver.
- Isolate the host when risk >= 80.
- Create a ticket and notify the SOC.

## False positive notes
- Some security and CDN products (antivirus reputation lookups, some telemetry) encode data in DNS by design. Allowlist their parent domains.
