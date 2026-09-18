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
chmod +x bootstrap.sh && ./bootstrap.sh      # needs Python 3.10+
source .venv/bin/activate
# put ANTHROPIC_API_KEY in .env, or set WARDEN_LLM=mock to run without one
python -m warden.cli run
python -m warden.cli serve   # http://127.0.0.1:8000
```

Fully offline: `WARDEN_LLM=mock WARDEN_EMBEDDINGS=hash`.

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

See [ROADMAP.md](ROADMAP.md). Phase 1 foundations (event model, detection registry, eval
harness) and the first slice of Phases 2 and 3 (two new identity detections, ATT&CK
ingest) are in. Next up: real ingestion adapters, SQLite storage, dashboard auth, and the
rest of the identity sweep with cross-alert correlation.
