# Playbook PB-061: Computer Account Creating Domain Accounts

Scope: detection `machine_account_creates_account`. A directory account whose name ends in `$` (a computer object) appears as the **actor** on two or more `account_created` events within 15 minutes on the same host.

MITRE: T1136.002 (Create Account: Domain Account), T1098 (Account Manipulation).

## Why this matters

Domain joins and provisioning are performed under a user or service identity. A computer account creating other accounts is not a normal directory operation. The usual explanation is that the host's machine credentials (extracted from LSASS, from a machine password in a backup, or via a relayed authentication) are being used against the default `ms-DS-MachineAccountQuota` of 10 to create additional computer objects. Those objects are then used for:

- resource-based constrained delegation (writing `msDS-AllowedToActOnBehalfOfOtherIdentity` on a target computer),
- sAMAccountName spoofing against a domain controller (noPac, CVE-2021-42278 / CVE-2021-42287),
- long-lived persistence that survives user password resets.

## Triage

1. Pull Windows Security **4741** (computer account created) and **4720** (user account created) for the alert window. Confirm the Subject account is the machine account named in `detail.actor` and note the caller's logon ID and source workstation.
2. Look up each target in `detail.created_targets`. Newly created computer objects with no matching asset-inventory or MDM record are attacker-controlled.
3. On the created objects check `msDS-AllowedToActOnBehalfOfOtherIdentity`, `servicePrincipalName`, and `sAMAccountName`. A short SPN-less object whose name later changes to match a DC is noPac.
4. Check whether the actor host recently logged a credential-dumping, `lolbin_abuse`, or `suspicious_parent_child` alert; the machine credential had to come from somewhere.
5. Review Kerberos **4769**/**4768** for the new accounts and for S4U2Proxy tickets naming crown-jewel servers.

## Containment

- Disable, do not delete, the accounts listed in `detail.created_targets`, preserving them for forensics. Deleting a computer object destroys the delegation evidence.
- Reset the **actor** machine account password twice (`Reset-ComputerMachinePassword` or `netdom resetpwd`) and isolate the actor host pending endpoint triage. Host isolation requires analyst approval (Policy SEC-012).
- Clear any `msDS-AllowedToActOnBehalfOfOtherIdentity` values written during the window.
- Create a ticket, notify the SOC and the AD owners, and raise setting `ms-DS-MachineAccountQuota` to 0 as a follow-up hardening item.

## Known benign patterns (should not reach this playbook)

- SCCM/MDT or a domain-join service account creating workstation objects: the actor is a service account, not a `$` account, and the rule does not fire.
- A single pre-created computer object: below the two-event threshold.
- Machine password rotation (`password_reset` on the account's own object): a different change type, ignored.

If triage shows an approved automation that genuinely runs under machine credentials, record the actor name and the expected target prefix in the ticket so the exception can be evaluated for a future rule revision.
