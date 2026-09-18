# Playbook PB-021: Obfuscated or Download-Cradle PowerShell

Scope: PowerShell with -EncodedCommand, or a download cradle (DownloadString, IEX, Net.WebClient, FromBase64String, reflective assembly load). Detection is `encoded_powershell`, MITRE T1059.001, T1027.

## Triage
1. Decode the base64 (it is UTF-16LE). The decoded script tells you the stage: a stager fetching more code, a loader injecting into memory, or a tool running outright.
2. Check the parent. services.exe (remote execution), an Office app (macro), and wmiprvse.exe (WMI lateral movement) are all bad parents.
3. Pull script block logs (4104) for the same host for the full picture.

## Containment
- Isolate the host when risk >= 80 and the decoded script fetches or injects code.
- Block the cradle's download host.
- Create a ticket and notify the SOC.

## False positive notes
- Some management agents (SCCM, Intune remediation scripts) run encoded commands. They run as SYSTEM from a known parent and can be excluded by parent image plus hash.
