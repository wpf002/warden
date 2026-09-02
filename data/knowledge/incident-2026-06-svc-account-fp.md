# Incident INC-2026-0642: False positive, svc-backup lockout

Summary: after a scheduled password rotation, svc-backup failed 30 logins from 10.0.4.12 (internal backup server) against ad-dc-01. The brute-force rule fired. Analyst confirmed it was a stale credential on the backup job.

Lessons:
- Internal source IP plus a service account (svc-*) plus a recent change ticket is almost always a misconfiguration, not an attack.
- Recommended action in this pattern: create ticket and notify the platform team, no block, no lock.
