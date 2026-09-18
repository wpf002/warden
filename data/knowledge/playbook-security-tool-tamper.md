# Playbook PB-025: Security Tooling Disabled or Bypassed

Scope: Defender real-time protection disabled or given exclusions, security services stopped, AMSI bypass strings, the host firewall turned off. Detection is `security_tool_tamper`, MITRE T1685 (formerly T1562.001), T1562.004.

## Triage
1. Tampering is preparation. Look for what was run in the minutes after protection went off.
2. Exclusions for Users\Public, ProgramData, or Temp are for a payload that lives there.
3. AMSI bypass strings in script blocks mean an in-memory PowerShell payload followed.

## Containment
- Isolate the host when risk >= 80.
- Re-enable protection through management policy and remove the exclusions.
- Create a ticket and notify the SOC.

## False positive notes
- Troubleshooting sessions by desktop support. They should have a ticket and happen from a known admin account.
