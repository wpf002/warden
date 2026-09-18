# Playbook PB-040: Behavioral Anomaly

Scope: a user or host whose day departs from its own 30-day baseline, with no rule naming what happened. Detections are `anomaly.user` and `anomaly.host`. They carry no fixed MITRE technique; the analysis maps the deviation to the closest ones.

## Triage
1. Read the contributions. Each one is a concrete statement: a count far outside the baseline (with its z-score), or a value never seen before (first host, first process, first country, first login hour).
2. Group them. New hosts plus new discovery tools (nltest, adfind, net group) is reconnaissance (T1087, T1018). New country plus new source network is account misuse (T1078). New external destinations plus a volume spike is staging or exfiltration.
3. Ask the owner. Most anomalies are real change: a new project, a new laptop, travel, a new tool rollout.

## Containment
- Anomaly-sourced alerts never auto-execute (guardrail). Every containment action waits for an analyst.
- Create a ticket and notify the SOC.

## Tuning
- Marking an anomaly false positive teaches the baseline: the values it flagged as new become known for that entity.
- "Mute" additionally silences the top contributing features for that entity for 30 days.
- Anomaly FP rate is tracked per entity type on the detection-health page and is expected to start high.
