# Warden Roadmap

From a brute-force demo to an AI-assisted SOC platform that covers the ATT&CK matrix, keeps its own knowledge current, and never lets the model act alone.

Ground rules that hold across every phase:

1. Detection is deterministic. The LLM explains, prioritizes, and recommends. It never decides whether something is an alert.
2. Every action passes through guardrails. The allowlist, thresholds, and human-approval list are policy in code, versioned with the repo.
3. Every model output is logged with the alert id, the retrieved context, and the prompt version. If you can't replay it, it didn't happen.
4. Ship each phase with an eval. No phase is done until there's a labeled set that measures it.

Effort estimates assume one developer working focused. v0.1 is the current state.

---

## Phase 1: Foundation hardening (1 to 2 weeks)

Goal: make v0.1 something you can run against real logs without embarrassment.

**Event model.** Generalize `AuthEvent` into a base `Event` with typed subclasses: `AuthEvent`, `ProcessEvent`, `NetworkEvent`, `FileEvent`, `IdentityChangeEvent`, `CloudAuditEvent`. Common fields: ts, source, host, user, entity ids, raw. Map roughly to the Elastic Common Schema so real SIEM exports need minimal translation.

**Detection registry.** Replace the single function in `detect.py` with a registry. Each detection is a class with `id`, `mitre` (technique ids), `event_types` it consumes, `window`, `run(events) -> list[Alert]`, and a `playbook` reference. The pipeline iterates the registry. Adding a detection means adding a file.

**Real ingestion adapters.** Splunk (REST search export and HEC receiver), Elastic/OpenSearch, Okta System Log, Microsoft Entra sign-in logs, CloudTrail, sshd/auth.log, Windows Security event XML (4624/4625/4720/4728/4732). Each adapter is one file with a fixture and a test.

**Storage.** Move cases and events from JSON files to SQLite by default, Postgres via config. Keep the `CaseStore` interface.

**Eval harness v1.** `warden eval` runs the pipeline over a labeled directory of log files plus expected alerts and expected analyst verdicts. Reports detection precision/recall per rule, LLM risk-score calibration (Brier score against TP/FP labels), and action-decision agreement with the analyst. This is the yardstick for every later phase.

**Dashboard auth.** Basic auth or OIDC. Audit log of who approved what.

Exit criteria: pipeline runs on at least one real log export end to end; eval harness reports numbers; all detections have tests.

---

## Phase 2: Identity attack sweep (2 weeks)

Goal: cover the identity and credential-access surface, since that's where most breaches start and where the log model is strongest.

Detections, each with a playbook markdown and a labeled fixture:

| Detection | MITRE | Signal |
|---|---|---|
| Brute force | T1110.001 | existing |
| Password spray | T1110.003 | existing |
| Credential stuffing | T1110.004 | many users, many IPs, low per-IP volume, shared UA or ASN |
| Impossible travel | T1078 | two successes for one user from geos that can't be reached in the elapsed time |
| New country / new device login | T1078 | first-seen geo or device fingerprint for the user, weighted by asset tier |
| MFA fatigue / push bombing | T1621 | many MFA push denials or timeouts followed by an approval |
| MFA method change after login | T1556.006 | new factor enrolled shortly after a suspicious success |
| Dormant account reactivation | T1078 | success on an account with no activity in 60+ days |
| Service account interactive login | T1078.002 | svc-* or non-interactive-flagged account with interactive or RDP logon type |
| Privilege escalation via group change | T1078.004, T1098 | user added to admin/Domain Admins/Global Admin, especially outside change window |
| Account creation then privilege | T1136 | new account plus admin group add within N minutes |
| Token / session anomaly | T1550.004 | session reused from a new IP or UA mid-session |
| Password reset abuse | T1098 | helpdesk-initiated resets clustered on one target or from one operator |
| Lockout storm | T1110 | mass lockouts across users, often the tail of a spray |

**Correlation.** Add a correlation stage after detection. Alerts on the same entity (user, IP, host) inside a window merge into an incident with a combined evidence chain. "Spray → success → new MFA method → admin group add" becomes one incident, not four alerts. The LLM analyzes incidents, not single alerts.

**Playbook library.** One playbook per detection plus response policies per action type. This is the RAG corpus and it should be reviewed like code.

Exit criteria: 14 identity detections passing eval; correlation merges a scripted attack chain into one incident; eval precision above 0.9 on fixtures.

---

## Phase 3: Living knowledge base (1 to 2 weeks)

Goal: the KB updates itself from public sources, and analyst feedback measurably improves it.

**MITRE ATT&CK ingest.** Nightly job pulls the Enterprise ATT&CK STIX bundle (public JSON on GitHub). Index every technique and sub-technique: description, detection guidance, mitigations, associated groups and software. Tag chunks with technique ids so retrieval can filter by the detection's mapped technique first, then widen.

**Threat intel ingest.** CISA KEV, AlienVault OTX or abuse.ch feeds for IOCs, and optionally a paid feed. IOCs go into a lookup table for enrichment (is this IP/hash/domain known bad), not into the vector store. Intel context (campaign descriptions, actor TTPs) goes into the vector store.

**Retrieval improvements.** Hybrid search: BM25 plus vector, reciprocal rank fusion. Metadata filters by technique id, doc kind, and recency. Reranking with a cross-encoder if quality warrants it. Measure retrieval hit rate on the eval set (did the right playbook land in top 3).

**Feedback that changes behavior.** Analyst verdicts already write learned cases. Extend: per-detection FP rate tracked over time, surfaced in the dashboard, and used to adjust that detection's risk prior. Analysts can annotate "why FP" with structured reasons (known scanner, change window, service account) that become retrieval-weighted exclusions.

**KB versioning.** Snapshot the KB on each ingest. Cases record which snapshot they were analyzed against so replay is exact.

Exit criteria: ATT&CK ingest runs unattended; retrieval hit rate above 0.85 on eval; FP rate per detection visible in the dashboard.

---

## Phase 4: Endpoint, network, and cloud sweep (3 weeks)

Goal: widen from identity to the rest of the kill chain.

**Endpoint (EDR/Sysmon/osquery):** suspicious parent-child process (Office spawning shell, T1059), LOLBin abuse (certutil, mshta, rundll32, T1218), credential dumping indicators (lsass access, T1003), persistence (new scheduled task, run key, service, T1053/T1547), defense evasion (log clearing, AMSI/Defender tamper, T1070/T1562), ransomware precursors (shadow copy deletion, mass rename, T1490/T1486).

**Network (firewall/NetFlow/DNS/proxy):** beaconing (periodic outbound to one destination, T1071), DNS tunneling (high-entropy subdomains, TXT volume, T1071.004), lateral movement (SMB/RDP/WinRM fan-out from one host, T1021), port scanning (T1046), data exfil (outbound volume anomaly to new destination, T1041/T1048), connections to known-bad IOCs from the intel table.

**Cloud (CloudTrail/Azure Activity/GCP Audit):** IAM policy changes granting admin, new access keys for old users, S3/bucket made public, security logging disabled (T1562.008), instance launched in an unused region, console login without MFA.

**Email (optional, if a source exists):** phishing indicators from gateway logs, mailbox forwarding rules added (T1114.003).

**Correlation across domains.** Extend Phase 2 correlation to join on host and user across identity, endpoint, and network. "Phish click → macro spawns PowerShell → beaconing → lateral SMB → new admin account" as one incident.

**Response connectors.** Real implementations behind the existing `actions.py` interface: firewall block (Palo Alto, Fortinet, or cloud security group), EDR host isolate (CrowdStrike, Defender), IAM disable/lock (Okta, Entra, AD), ticketing (Jira, ServiceNow), notification (Slack, PagerDuty, email). Each connector has a dry-run mode and a rollback method; guardrails require rollback to exist before an action can be on the auto-execute allowlist.

Exit criteria: 30+ detections across five ATT&CK tactics; a scripted multi-stage attack in the fixtures becomes one incident; at least two real response connectors working against a sandbox.

---

## Phase 5: Behavioral baselines and anomaly detection (2 weeks)

Goal: catch things no rule names, and be honest about what that means.

**Entity baselines.** Per user, host, and IP: rolling 30-day profile of login hours, geos, hosts touched, process set, outbound destinations, data volume. Stored in SQL, rebuilt nightly, updated incrementally.

**Anomaly scorers.** Start simple and interpretable: z-scores on volume metrics, rarity scores for first-seen values, Isolation Forest over the feature vector as a second opinion. Output is an `Alert` with rule `anomaly.<entity_type>` and the top contributing features listed in evidence. No black-box score without the features that drove it.

**LLM role.** The anomaly alert goes through the same RAG and analysis path. The prompt asks the model to map the deviation to the closest ATT&CK techniques from the KB and to say plainly if it looks benign. Guardrails treat anomaly-sourced alerts as approval-only; they never auto-execute.

**Tuning loop.** Anomaly FP rate is expected to be high at first. Track it per entity type, let analysts suppress specific feature/entity pairs, and feed suppressions into the baseline.

Exit criteria: baselines built from real logs; anomaly detector surfaces a planted unknown in fixtures; FP rate trending down over a two-week soak.

**Status (2026-09):** done. Baselines built from a real 24-day OpenSSH log; `scripts/soak_real.py` scores 14 log days of that real traffic with a simulated analyst: FPs 4 in week one, 2 in week two, both planted takeovers caught. A live two-week soak on production traffic waits for a deployment.

---

## Phase 6: Detection proposals from feedback (2 weeks)

Goal: the closest defensible thing to "learning new attack vectors."

**Trigger.** An analyst marks a case TP where the firing detection was `anomaly.*` or the analyst adds a note like "this should be its own rule."

**Proposal.** Claude receives the incident evidence, the mapped technique docs from the KB, and the detection registry interface, and produces: a detection class, a playbook draft, a fixture derived from the real evidence (anonymized), and a test. Output goes into a review queue in the dashboard as a diff.

**Review.** A human reads the diff, runs it against the eval set in a sandbox (the dashboard shows precision/recall and any new FPs on historical data), and merges or rejects. Merged proposals become a PR against the repo, never a hot-loaded rule.

**Intel-driven proposals.** Same mechanism, different trigger: a new KEV entry or ATT&CK technique lands in the KB with detection guidance and no matching detection in the registry. Warden proposes one.

Exit criteria: a proposal generated from a real TP passes review and eval, and lands as a PR.

---

## Phase 7: Platform (3 to 4 weeks)

Goal: something a second person or a small company can run.

**Deployment.** Docker Compose for local, Helm chart for Kubernetes, Terraform for AWS as the reference cloud (ECS or EKS, RDS Postgres, managed vector DB or Chroma on EBS, Secrets Manager, CloudWatch). Azure and GCP equivalents after AWS is stable.

**Multi-tenancy.** Tenant id on every event, case, KB doc, and baseline. Per-tenant playbooks layered over global ones. Per-tenant guardrail policy.

**Dashboard rebuild.** Replace the server-rendered HTML with a real front end once the API stabilizes. Views: incident queue, incident detail with timeline, detection health (fires, FP rate, last tuned), KB browser, proposal review queue, action audit log, eval results over time.

**Prompt and model management.** Prompts versioned in the repo with changelogs. Model choice per stage (cheap model for triage summaries, strong model for incident analysis). Provider abstraction so Anthropic, OpenAI, and a local model can be swapped per tenant. Prompt injection defenses: retrieved KB text and raw log content are wrapped and labeled as untrusted; guardrails already refuse targets not in evidence, extend that to every action parameter.

**Governance.** Data retention policy per tenant. PII redaction in log ingestion (configurable). Model output validation against the schema plus a second cheap-model check for hallucinated entities. Red-team suite: adversarial log lines that try to inject instructions, alerts crafted to push the model toward over-blocking, safelist bypass attempts. Runs in CI.

**Observability.** Structured logs, metrics per pipeline stage (ingest lag, detection latency, LLM latency and cost per incident, action success rate), traces per incident.

Exit criteria: fresh AWS account to running Warden in under an hour from the Terraform; red-team suite green in CI; two tenants isolated in one deployment.

**Status (2026-09):** red-team suite green in CI and tenant isolation done. Cloud deployment is **deferred**: the AWS Terraform (`deploy/terraform/aws`) is written and passes `terraform validate` but is not applied, because the reference stack costs about $150/month. Azure and GCP equivalents are not written; they would cost about the same. Development runs on Docker Compose locally at $0. Apply the AWS stack when a paying user needs a hosted deployment, and write Azure or GCP only when a user asks for that cloud. For demos, `docker-compose.demo.yml` stands in: a stateful Okta/Falcon sandbox, moto for AWS, Mailpit for notifications, and an optional Cloudflare quick tunnel for a temporary public link.

---

## Phase 8: Product surface (ongoing)

Directions, pick based on who shows up wanting it:

**Small-business SOC.** Companies with Okta plus a firewall plus Microsoft 365 and no security team. Warden watches identity and cloud, auto-blocks the obvious, pages a human for the rest. Pricing per identity.

**MSSP triage layer.** Sell the guardrailed AI analysis and incident correlation to shops already running Splunk or Sentinel. Warden reads their SIEM, writes back enriched incidents. Pricing per alert volume.

**Detection-as-code product.** The registry, eval harness, and proposal queue as a standalone tool for detection engineers, LLM optional.

**Cross-project tie-ins.** Scout's scope model for what assets are in bounds. Infiltr to validate that a blocked IP is actually hostile before a permanent block. Quarry's human-gated action pattern is the same shape as Warden's guardrails; share the implementation.

---

## Sequencing summary

| Phase | Weeks | Unlocks |
|---|---|---|
| 1 Foundation | 1 to 2 | real logs, eval numbers |
| 2 Identity sweep | 2 | 14 detections, correlation |
| 3 Living KB | 1 to 2 | ATT&CK + intel auto-ingest, feedback that matters |
| 4 Endpoint/network/cloud | 3 | 30+ detections, real connectors |
| 5 Baselines | 2 | unknown-unknowns, honestly labeled |
| 6 Proposals | 2 | rules from feedback and intel |
| 7 Platform | 3 to 4 | deployable, multi-tenant, governed |
| 8 Product | ongoing | revenue direction |

Roughly 15 to 18 weeks of focused solo work to Phase 7. Phases 3 and 5 can run in parallel with 4 if a second person joins.

## What to do this week

1. Detection registry and `Event` base model (Phase 1)
2. Eval harness skeleton with the two existing fixtures (Phase 1)
3. Impossible travel and MFA fatigue detections, to prove the registry (Phase 2)
4. ATT&CK STIX ingest job (Phase 3)

Those four make every later phase cheaper and none of them depend on decisions you haven't made yet.
