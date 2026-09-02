#!/usr/bin/env bash
# Warden infrastructure bootstrap. Idempotent. Run from repo root.
set -euo pipefail

PY="${PYTHON:-python3}"
if ! "$PY" -c 'import sys; sys.exit(sys.version_info < (3, 10))'; then
  echo "error: warden needs Python 3.10+, but '$PY' is $("$PY" --version 2>&1)" >&2
  echo "       set PYTHON=/path/to/python3.12 and re-run" >&2
  exit 1
fi

echo "==> Folder structure"
mkdir -p warden/detections data/knowledge data/sample_logs data/chroma data/state data/eval tests scripts

echo "==> Python venv"
if [ ! -d .venv ]; then "$PY" -m venv .venv; fi
# shellcheck disable=SC1091
source .venv/bin/activate
pip install --upgrade pip -q
pip install -q -r requirements.txt

echo "==> Env file"
if [ ! -f .env ]; then cp .env.example .env; echo "   created .env (add ANTHROPIC_API_KEY)"; fi

echo "==> Sample data"
python -m warden.cli gen-logs --out data/sample_logs/auth.jsonl --events 600 --attackers 2

echo "==> Knowledge base"
python -m warden.cli index

echo
echo "Done. Next:"
echo "  source .venv/bin/activate"
echo "  python -m warden.cli detections    # what rules are registered"
echo "  python -m warden.cli run           # detect -> RAG -> LLM -> guardrail -> actions"
echo "  python -m warden.cli eval          # score against the labeled fixtures"
echo "  python -m warden.cli serve         # dashboard at http://127.0.0.1:8000"
echo
echo "Optional, pulls ~50MB from GitHub and takes a couple of minutes:"
echo "  python -m warden.cli attack-ingest # index the MITRE ATT&CK corpus"
