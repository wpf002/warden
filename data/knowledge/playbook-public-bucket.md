# Playbook PB-035: Storage Bucket Made Public

Scope: bucket policy allowing Principal "*", a public ACL, or the public-access block removed. Detection is `public_bucket`, MITRE T1530.

## Triage
1. Identify what the bucket holds. Backups, exports, and logs are the high-impact cases.
2. Check S3 server access logs or CloudTrail data events for reads from unfamiliar IPs since the change.

## Containment
- Restore the public-access block. Requires analyst approval because some buckets serve static websites legitimately.
- Create a ticket and notify the SOC.

## False positive notes
- Static website buckets. They should be tagged and excluded by bucket name.
