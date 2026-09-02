# Warden

AI-powered SOC pipeline. Security logs in, explained and guardrailed actions out.

Vertical slice implemented in v1: **brute-force login detection and response**.

```
SIEM logs -> ingest/normalize -> detection -> RAG (Chroma) -> LLM (Claude) -> guardrails -> actions -> SOC dashboard -> analyst feedback -> knowledge base
```

## Quick start

```bash
git clone git@github.com:wpf002/warden.git && cd warden
chmod +x bootstrap.sh && ./bootstrap.sh
source .venv/bin/activate
# put ANTHROPIC_API_KEY in .env, or set WARDEN_LLM=mock to run without one
python -m warden.cli run
python -m warden.cli serve   # http://127.0.0.1:8000
```

## Layout

| Path | What |
|---|---|
| `warden/ingest.py` | Load JSONL/syslog-ish auth events, normalize to `AuthEvent`, dedupe, enrich (geo/asset tags) |
| `warden/detect.py` | Brute-force rule (N failures / window / source IP) plus spray variant. Emits `Alert` |
| `warden/knowledge.py` | Chunk + embed `data/knowledge/*.md` into Chroma; retrieve by alert context |
| `warden/llm.py` | Claude via `langchain-anthropic`, structured `Analysis` output. Mock provider for offline runs |
| `warden/agent.py` | LangGraph workflow: retrieve -> analyze -> guardrail -> act -> record |
| `warden/guardrails.py` | Action allowlist, risk threshold, human-approval list, IP safelist. Every decision logged |
| `warden/actions.py` | Mock connectors: firewall block, IAM lock, ticket, notify. Swap for real APIs |
| `warden/feedback.py` | Analyst TP/FP verdicts, writes learned cases back into the knowledge base |
| `warden/dashboard.py` | FastAPI SOC UI: alerts, analysis, actions, approve/deny, feedback |
| `warden/cli.py` | `gen-logs`, `index`, `run`, `serve` |
| `data/knowledge/` | Playbooks, policies, MITRE notes, past incidents (RAG sources) |

## Config

All settings via `.env` (see `.env.example`). Key ones:

- `WARDEN_LLM=anthropic|mock`
- `WARDEN_EMBEDDINGS=default|hash` (hash = fully offline)
- `WARDEN_AUTO_ACTION_MIN_RISK` risk score needed for auto-execution
- `WARDEN_HUMAN_APPROVAL_ACTIONS` actions that always wait for an analyst

## Tests

```bash
pytest
```

## Roadmap

- Real connectors (Splunk HEC, CrowdStrike, Okta, Jira)
- More detections (impossible travel, privilege escalation)
- Cloud deploy (containers + managed vector DB + secrets manager)
- Prompt/model eval harness on labeled incidents
