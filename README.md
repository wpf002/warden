# Warden

AI-powered SOC pipeline. Security logs in, explained and guardrailed actions out.

```
SIEM logs -> ingest/normalize -> detection registry -> RAG (Chroma + ATT&CK) -> LLM (Claude)
          -> guardrails -> actions -> SOC dashboard -> analyst feedback -> knowledge base
```

Two rules hold everywhere: **detection is deterministic** (the model explains and
recommends, it never decides whether something is an alert) and **every action passes
through guardrails** that are policy in code, versioned with the repo.

## Quick start

```bash
git clone git@github.com:wpf002/warden.git && cd warden
cp .env.example .env                 # ANTHROPIC_API_KEY (+ ANTHROPIC_WORKSPACE_ID if the key isn't workspace-scoped)
scripts/warden.sh start              # everything, seeded, with every page opened
```

Without Docker: `./bootstrap.sh`, then `python -m warden.cli serve`, and `cd web && npm ci && npm run build`
for the console. Offline: `WARDEN_LLM=mock WARDEN_EMBEDDINGS=hash`.

## Console

The web console at `/` (React, served by the API) covers the case queue, case pages
with response approvals and rollback, detections health, the knowledge base, detection
proposals, evaluation history, the audit log, and response connectors. Keyboard: `j`/`k`
move, `Enter` opens, `/` searches, `Esc` returns to the queue. The original
server-rendered pages remain at `/classic`.

## Deploy

| Target | Where |
|---|---|
| Docker Compose | `docker-compose.yml` (Postgres, scheduler, optional Mailpit sandbox) |
| Kubernetes | `deploy/helm/warden` (Deployment, CronJobs for refresh and detection, PVC, Ingress; secrets referenced, never templated) |
| AWS | `deploy/terraform/aws` (ECS Fargate, ALB with optional OIDC, RDS Postgres, EFS, Secrets Manager, CloudWatch, EventBridge Scheduler) |

The Helm chart is linted and rendered, and the Terraform validates, both in CI.
Neither has been applied to a live cluster or account.

### Demo stack ($0, no vendor accounts)

Hosted cloud deployment is deferred (see ROADMAP Phase 7). The demo stack stands in for
what it would touch, all running locally, with actions executed live against the stand-ins:

```
scripts/warden.sh start      # also: restart, stop, status, logs
```

It starts Docker if it isn't running, brings up every service, waits for the API, seeds the
demo scenarios if the store is empty, and opens the console, the vendor sandbox state, the
inbox, and the metrics page.

| Gap | Stand-in | See it |
|---|---|---|
| Okta org, CrowdStrike tenant | `warden/sandbox/vendors.py`, stateful, only the operations the vendors document (contract-tested against Okta's OpenAPI spec and Falcon's endpoint catalog) | http://localhost:5056/state |
| AWS account | moto: `block_ip` writes real NACL deny rules | port 5055 |
| Email / paging | Mailpit: `notify` sends real email | http://localhost:8025 |
| Two-week production soak | `scripts/soak_real.py` replays 24 days of real SSH traffic | below |
| Hosted URL | `docker-compose.share.yml`: a free Cloudflare quick tunnel, auth required | `docker compose logs share` |

The `seed` service loads the demo scenarios once. The analyzer is the offline mock unless
`WARDEN_LLM=anthropic` is exported, so the demo makes no API calls.

## Ingest

Adapters in `warden/adapters/`, one per source, autodetected from the file:

| Source | Input |
|---|---|
| Windows Security | `.evtx` directly, or `wevtutil /f:xml` export. 4624/4625/4768/4771/4776/4740, 4720-4726, 4728/4732/4756, 1102 |
| Okta | System Log JSON (`/api/v1/logs`), incl. Okta Verify push outcomes |
| Microsoft Entra ID | Graph sign-in logs and directory audit logs |
| AWS CloudTrail | S3 `Records` files or event-history export; ConsoleLogin also becomes an auth event |
| Splunk | search export NDJSON (routes `_raw` by shape), plus a live HEC receiver at `POST /services/collector/event` |
| Elastic / OpenSearch | `_search` responses or ECS NDJSON |
| sshd | `auth.log` / `secure` |

```bash
python -m warden.cli run --log Security.evtx
python -m warden.cli run --log okta.json --format okta
python -m warden.cli run --from-db --since 24h      # events pushed over HEC
```

Events and cases are stored in SQLite (`data/state/warden.db`) or Postgres via
`WARDEN_DATABASE_URL`. Every model call is logged with its alert id, retrieved chunk ids,
prompt version, KB snapshot, tokens, and cost (`llm_calls` table). Every analyst approval,
denial, and verdict is written to the `audit` table with who did it.

Dashboard auth: `WARDEN_AUTH=basic` (users from `WARDEN_USERS`, hashes from
`warden hash-password`) or `WARDEN_AUTH=proxy` (OIDC terminated by oauth2-proxy or similar,
identity header trusted only from `WARDEN_TRUSTED_PROXIES`). Roles: viewer, analyst, admin.

## Detections

36 rules, one file each in `warden/detections/`, across credential access, initial access,
execution, persistence, defense evasion, discovery, lateral movement, collection, command
and control, exfiltration, and impact. `python -m warden.cli detections` lists them.

| Domain | Rules |
|---|---|
| Identity | brute_force, password_spray, credential_stuffing, lockout_storm, mfa_fatigue, mfa_method_change, impossible_travel, new_geo_login, dormant_account, service_account_interactive, session_anomaly, privileged_group_add, account_create_then_privilege, password_reset_abuse |
| Endpoint | suspicious_parent_child, lolbin_abuse, encoded_powershell, credential_dumping, persistence_mechanism, log_clearing, security_tool_tamper, ransomware_precursor, mass_file_encryption |
| Network | beaconing, dns_tunneling, lateral_movement_fanout, port_scan, data_exfiltration, intel_ioc_match |
| Cloud / email | iam_admin_grant, new_access_key, public_bucket, cloud_logging_disabled, unusual_region, console_login_no_mfa, mailbox_forwarding_rule |

Alerts that share a user or IP (and, for endpoint and network alerts, a host) within two
hours merge into one incident, and the model analyzes the incident. "Phish -> macro
PowerShell -> beacon -> SMB fan-out -> new domain admin" is one case with one timeline.

```python
@register
class MyRule(Detection):
    id = "my_rule"
    mitre = ["T1078.004"]
    event_kinds = ("auth", "identity")
    playbook = "playbook-my-rule"

    def run(self, events): ...   # -> list[Alert], deterministic
```

## Platform

- **Tenancy**: every event, case, audit row, model call, exclusion, and baseline carries a
  tenant; `data/tenants/<t>/policy.json` overrides guardrails, models, and connectors;
  `data/tenants/<t>/knowledge/` layers playbooks over the global ones.
- **Models**: incidents, crown-jewel assets, anomalies, and credential/ransomware rules go
  to `WARDEN_MODEL` (claude-opus-5); routine alerts to `WARDEN_MODEL_TRIAGE`
  (claude-sonnet-5). `WARDEN_LLM=openai` with `WARDEN_LLM_BASE_URL` points at OpenAI or a
  local vLLM/Ollama. Prompts are versioned files in `warden/prompts/`.
- **Governance**: PII redaction at ingest (`WARDEN_REDACT`), per-tenant retention, every
  analysis checked against its evidence (optionally by a second model,
  `WARDEN_VERIFY_MODEL`), and a red-team suite in CI.
- **Observability**: JSON logs with trace ids, Prometheus metrics at `/metrics`, per-case
  stage timings, `/healthz`.

## Behavioral baselines

`anomaly.user` and `anomaly.host` catch what no rule names. Each user and host gets a
30-day profile (`warden baseline rebuild`, part of `warden refresh`): daily counts with
their spread, and every host, network, country, login hour, process, parent->child pair,
and destination it has used. A day is scored as a list of explicit contributions, e.g.
"distinct hosts 9, baseline 2.5 +/- 0.6 (z=6.5)" or "first processes: adfind.exe,
nltest.exe". Values the entity has never used but several peers use weigh a quarter as
much. Isolation Forest is a second opinion that adds weight but never fires alone.

Anomaly alerts are approval-only: no action auto-executes on anomaly evidence alone.
An analyst's false positive teaches the baseline (the flagged values become known);
"mute" also silences the top features for that entity for 30 days. Attack days are kept
out of the baseline when profiles update.

`scripts/soak_anomaly.py` runs a simulated two-week soak (40 people, scripted project
moves, a rollout, a recurring maintenance night, two planted recon runs): FPs 13 in week
one, 11 in week two, both recon runs caught. It is a simulation; real FP rates need real
logs and at least 7 days of history per entity.

`scripts/soak_real.py` does the same on real traffic: the Loghub OpenSSH log from an
internet-facing server, 10 days of baseline and 14 log days scored (Dec 20 to Jan 7, with
a gap Dec 24 to 28 in the source), 1,700+ user entities and up to 31k events a day. With
a simulated analyst: FPs 4 in week one, 2 in week two, both planted takeovers caught.
`tests/test_anomaly_real.py` holds the last week out: at most one alert a day.

## Detection proposals

When an analyst confirms a true positive that no rule named (an anomaly, or a note like
"this should be its own rule"), or when an ATT&CK technique with detection guidance has no
rule (`warden propose --gaps`), Claude drafts a new detection: the rule module, a playbook,
a fixture with the evidence and a near-miss, and a test.

```bash
python -m warden.cli propose --events suspicious.evtx --note "should be its own rule"
python -m warden.cli propose --case ALT-1234ABCD
python -m warden.cli propose --technique T1136.001
python -m warden.cli propose --pending          # requests queued by analyst verdicts
python -m warden.cli proposals                  # review queue; also /proposals in the dashboard
```

Evidence is anonymized before it reaches the model (stable pseudonyms for users, hosts,
IPs). The draft is checked statically (imports allowlist, no I/O, no dynamic code, correct
class shape, new id), then evaluated in a copy of the repo in a subprocess without secrets:
its own test, both eval suites, and a replay of the new rule over every stored and fixture
event to show what else it would fire on. An admin approves it into a pull request on a
branch. Nothing is ever loaded at runtime from a proposal.

## Response connectors

`warden/connectors/`, mapped per action with `WARDEN_CONNECTORS`
(e.g. `block_ip=aws_nacl,lock_user=okta,isolate_host=crowdstrike,notify=slack,create_ticket=jira`).
Unmapped actions use the mock. Real connectors run dry unless `WARDEN_LIVE_ACTIONS=1`.

| Action | Connectors |
|---|---|
| block_ip | aws_nacl (NACL deny), paloalto (User-ID tag with TTL) |
| lock_user | okta, entra, aws_iam |
| isolate_host | crowdstrike, defender |
| disable_access_key | aws_iam |
| notify | slack, pagerduty, smtp |
| create_ticket | jira, servicenow |

Every connector returns a receipt that carries what rollback needs; analysts can roll an
action back from the case page. Guardrails never auto-execute an action whose connector
cannot roll back, never auto-isolate a crown-jewel host, and bind every target (IP, user,
host, access key) to the evidence.

`python scripts/sandbox_connectors.py` runs aws_nacl and aws_iam live against moto (an AWS
API emulator) and smtp against Mailpit, verifying each change and each rollback through
the service's API. Okta, Entra, CrowdStrike, Defender, PAN-OS, Slack, PagerDuty, Jira, and
ServiceNow are tested against their documented request shapes, not live tenants.

## Eval

The yardstick. No change ships without a number.

```bash
python -m warden.cli eval                  # table
python -m warden.cli eval --json --fail-under 0.95
python -m warden.cli eval --no-llm         # detection metrics only, no API calls
```

A labeled case is `data/eval/<case>/events.jsonl` plus an `expected.json` naming which
alerts should fire, whether an analyst would call each a TP or FP, and what the guardrails
should decide. Reported: detection precision/recall/F1 per rule, risk-score calibration
(Brier against the TP/FP labels), action-decision agreement with the analyst, and
retrieval hit rate. Regenerate the fixtures with `python scripts/make_eval_fixtures.py`.

Current numbers (27 synthetic cases, 13 real Windows recordings, mock analyzer, MiniLM embeddings):

| Metric | Synthetic | Real |
|---|---|---|
| Detection precision / recall | 1.000 / 1.000 (51 alerts) | 1.000 / 1.000 (19 alerts) |
| Incidents merged as one | 13/13 | 4/4 |
| Action agreement with analyst | 77/77 | 29/30 |
| Retrieval hit rate (playbook in top 3) | 25/25 | 12/12 |

The mock analyzer's risk scores are placeholders; calibration numbers that mean
anything come from running the suite against Claude.

## Knowledge base

Playbooks, policies, past incidents, and learned cases live in `data/knowledge/` as
markdown and are reviewed like code. The index follows the files by content hash.

```bash
python -m warden.cli refresh          # nightly: ATT&CK + intel feeds + KB sync + snapshot
```

- **ATT&CK**: ~700 techniques, reachable only through a detection's mapped technique ids.
- **Threat intel**: CISA KEV, abuse.ch Feodo C2 IPs, Tor exits (context, low confidence),
  AlienVault OTX with `OTX_API_KEY`. Indicators go to an exact-match `iocs` table and are
  attached to alerts as `detail.intel`; descriptive context goes to the KB.
- **Retrieval**: BM25 + vector with reciprocal rank fusion, three passes (ATT&CK by
  technique, playbooks by what the detection is, past cases by entities).
- **Snapshots**: every case records the KB snapshot id it was analyzed against; the
  `kb_snapshots` table maps it to document hashes, the ATT&CK release, and intel sizes.
  `warden replay <case>` re-sends a case's recorded inputs and diffs the outputs.

### Feedback that changes behavior

A false-positive verdict takes a structured reason (known scanner, change window, service
account, travel, test, misconfiguration). Per-rule FP rates appear on `/detections`, go into
the prompt as the rule's track record, and raise that rule's auto-execute threshold by up to
20 once it has `WARDEN_FP_PRIOR_MIN_VERDICTS` verdicts. "Mute" creates a 30-day exclusion
for that rule on that user or IP; muted alerts are stored, not analyzed. An incident is
muted only if every step in it is.

## Layout

| Path | What |
|---|---|
| `warden/events.py` | Typed `Event` hierarchy (auth, process, network, file, identity, cloud), ECS-shaped |
| `warden/ingest.py` | Load JSONL/syslog, normalize, dedupe, enrich (geo/asset), synthetic log generator |
| `warden/detections/` | One file per rule; `@register` puts it in the registry |
| `warden/detect.py` | Front door: `detect(events, only=...)` |
| `warden/geo.py` | Country centroids, haversine, implied-speed maths for impossible travel |
| `warden/knowledge.py` | Chunk + embed into Chroma; technique-filtered and unfiltered retrieval |
| `warden/attack.py` | MITRE ATT&CK STIX ingest, flatten, render, index, snapshot manifest |
| `warden/llm.py` | Claude via `langchain-anthropic`, structured `Analysis`. Mock provider for offline runs |
| `warden/agent.py` | LangGraph workflow: retrieve -> analyze -> guardrail -> act -> record |
| `warden/guardrails.py` | Action allowlist, risk thresholds, approval list, IP safelist, evidence binding |
| `warden/actions.py` | Mock connectors: firewall block, IAM lock, ticket, notify |
| `warden/evaluate.py` | Eval harness: precision/recall, Brier, action agreement, retrieval hit rate |
| `warden/feedback.py` | Analyst TP/FP verdicts, writes learned cases back into the knowledge base |
| `warden/dashboard.py` | FastAPI SOC UI: alerts, analysis, actions, approve/deny, feedback |
| `warden/cli.py` | `gen-logs`, `index`, `detections`, `run`, `eval`, `attack-ingest`, `serve` |
| `data/knowledge/` | Playbooks, policies, MITRE notes, past incidents (RAG sources) |
| `data/eval/` | Labeled fixtures: events plus expected alerts, verdicts, and guardrail decisions |

## Config

All settings via `.env` (see `.env.example`). Key ones:

- `WARDEN_LLM=anthropic|mock`
- `WARDEN_EMBEDDINGS=default|hash` (hash = fully offline)
- `WARDEN_DETECTIONS` comma list, empty runs every registered rule
- `WARDEN_AUTO_ACTION_MIN_RISK` risk score needed for auto-execution
- `WARDEN_HUMAN_APPROVAL_ACTIONS` actions that always wait for an analyst

## Tests

```bash
pytest
```

## Roadmap

See [ROADMAP.md](ROADMAP.md). Phases 1 to 7 are built. Hosted cloud deployment is deferred
for cost; the demo stack above covers it locally.
