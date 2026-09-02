#!/usr/bin/env bash
# Warden infrastructure bootstrap. Idempotent. Run from repo root.
set -euo pipefail

echo "==> Folder structure"
mkdir -p warden data/knowledge data/sample_logs data/chroma data/state tests scripts

echo "==> Python venv"
if [ ! -d .venv ]; then python3 -m venv .venv; fi
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
echo "  python -m warden.cli run          # detect -> RAG -> LLM -> guardrail -> actions"
echo "  python -m warden.cli serve        # dashboard at http://127.0.0.1:8000"
