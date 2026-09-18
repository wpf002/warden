# Playbook PB-031: Large Upload to a New Destination

Scope: more than 500 MB sent from one host to an external destination it has not talked to before. Detection is `data_exfiltration`, MITRE T1048, T1041, T1567.

## Triage
1. Identify the destination: cloud storage (mega.nz, file-sharing sites), a VPS, or a known business partner.
2. Identify the process (rclone, curl, a browser) and the account.
3. Check what was staged: archives created in the hour before (7z, rar, zip in temp folders).

## Containment
- Block the destination when risk >= 80.
- Isolate the host if the transfer is ongoing.
- Create a ticket and notify the SOC and legal, since exfiltration may trigger disclosure obligations.

## False positive notes
- Backups to a new cloud provider, large video uploads by marketing. Confirm with the owner.
