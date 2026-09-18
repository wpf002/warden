# Playbook PB-020: Living-off-the-Land Binary Abuse

Scope: signed Windows binaries (mshta, rundll32, regsvr32, certutil, bitsadmin, msiexec, wmic, InstallUtil, RegAsm, CMSTP, hh) used to download or execute attacker content. Detection is `lolbin_abuse`, MITRE T1218 and sub-techniques, T1105, T1197, T1220.

## Triage
1. Read the command line. A URL, a scriptlet (.sct), an HTA, or a DLL entry point on a non-DLL file (rundll32 image.jpg,Start) is the payload location.
2. Fetch the payload hash or URL and check it against intel.
3. Look for the parent. Office or a browser as parent points at phishing; explorer.exe after a COM trick (ShellBrowserWindow) points at a deliberate parent spoof.

## Containment
- Isolate the host when risk >= 80.
- Block the download domain or IP at the proxy.
- Create a ticket and notify the SOC.

## False positive notes
- Software deployment tools use msiexec with URLs from internal servers; exclude by the internal host.
- certutil -decode is used by a few build scripts; they run on build agents, not workstations.
