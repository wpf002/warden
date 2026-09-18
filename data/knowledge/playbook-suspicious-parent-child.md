# Playbook PB-019: Office or Service Manager Spawning a Shell

Scope: Word, Excel, PowerPoint, Outlook, or OneNote starting cmd, PowerShell, a script host, mshta, rundll32, or regsvr32; or services.exe starting a shell. Detection is `suspicious_parent_child`, MITRE T1204.002, T1059, T1569.002.

## Triage
1. Office spawning a shell is macro or exploit delivery. Identify the document from the parent command line and pull it for analysis.
2. services.exe spawning cmd or PowerShell is remote service execution (PsExec, Impacket smbexec, Metasploit). Find the source host from 7045 and 4624 type 3 logons around the same time.
3. Check what the child did next: network connections, files written, further children.

## Containment
- Isolate the host through EDR when risk >= 80. Host isolation is reversible and keeps the EDR channel open (Policy SEC-012 as amended by RP-004).
- Block any external IP the child process contacted.
- Create a ticket and notify the SOC.

## Eradication and recovery
- Quarantine the document across the mail system by hash.
- Reset credentials for the user; macros commonly harvest browser and mail passwords.

## False positive notes
- Some finance add-ins shell out from Excel. They run from Program Files with a stable command line and can be excluded by exact command line.
