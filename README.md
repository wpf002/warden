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

Each detection is one file in `warden/detections/`, registered by decorator, with a
playbook in the knowledge base and a labeled fixture in `data/eval/`.

| Detection | MITRE | Signal |
|---|---|---|
| `brute_force` | T1110.001 | many failures from one IP against few accounts |
| `password_spray` | T1110.003 | 5+ distinct accounts failing from one IP in the window, few tries each |
| `credential_stuffing` | T1110.004 | many accounts, many IPs, few tries per IP, shared user agent or /24 |
| `lockout_storm` | T1110 | 5+ accounts locked out within 15 minutes |
| `mfa_fatigue` | T1621 | run of denied/timed-out MFA pushes, scored higher if an approval follows |
| `mfa_method_change` | T1556.006 | new MFA factor within an hour of failures, denials, or an unfamiliar country |
| `impossible_travel` | T1078 | two successes for one user from places no one could travel between (coordinates when the source has them) |
| `new_geo_login` | T1078 | first-seen country for a user with enough history; asset tier weights it |
| `dormant_account` | T1078 | success on an account idle 60+ days |
| `service_account_interactive` | T1078.002 | svc-*/sa-* account with an interactive or RDP logon |
| `session_anomaly` | T1550.004 | one session id from a second IP and a different client |
| `privileged_group_add` | T1098, T1078.004 | add to Domain Admins, Global Administrator, Okta Super Admins, ... |
| `account_create_then_privilege` | T1136 | new account made privileged within an hour |
| `password_reset_abuse` | T1098 | 3+ resets of one account, or one operator resetting 3+ accounts |

Alerts that share a user or IP within two hours are merged by `warden/correlate.py` into
one incident, and the model analyzes the incident: "spray -> success -> new MFA factor ->
Domain Admins" is one case with one timeline.

```bash
python -m warden.cli detections            # list the registry
python -m warden.cli run --detections mfa_fatigue,impossible_travel
```

Adding one means adding a file:

```python
@register
class MyRule(Detection):
    id = "my_rule"
    mitre = ["T1078.004"]
    event_kinds = ("auth", "identity")
    playbook = "playbook-my-rule"

    def run(self, events): ...   # -> list[Alert], deterministic
```

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

Current numbers (16 synthetic cases, mock analyzer, MiniLM embeddings; `--real` runs 4 real Windows recordings):

| Metric | Synthetic | Real |
|---|---|---|
| Detection precision / recall | 1.000 / 1.000 (25 alerts, 14 rules) | 1.000 / 1.000 (3 alerts) |
| Incidents merged as one | 8/8 | 1/1 |
| Action agreement with analyst | 43/43 | 4/5 |
| Retrieval hit rate (playbook in top 3) | 14/14 hybrid, 13/14 vector only | 2/2 |

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
