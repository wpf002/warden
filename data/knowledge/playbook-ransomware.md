# Playbook PB-026: Ransomware (Recovery Inhibition and Encryption)

Scope: shadow copies deleted, backups wiped, boot recovery disabled (`ransomware_precursor`, T1490); or one process rewriting many files to one new extension, or ransom notes appearing (`mass_file_encryption`, T1486).

## Triage
1. Recovery inhibition is the last step before encryption. Minutes matter more than certainty.
2. For encryption in progress, find the process and the account; the same account is usually encrypting file shares from other hosts too.
3. Check backups are intact and offline.

## Containment
- Isolate the host immediately. For ransomware, SEC-012 permits auto-isolation at risk >= 80.
- Disable the account running the encryption. Requires analyst approval but should be approved in minutes.
- Disconnect or snapshot file servers the account can write to.
- Create a ticket, notify the SOC, and invoke the incident response plan.

## False positive notes
- Backup software rotating its own shadow copies runs vssadmin from its install path as SYSTEM on a schedule.
- Bulk file conversions (media transcoding) rename many files, but to a common extension.
