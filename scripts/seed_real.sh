#!/bin/sh
# Replace the synthetic demo cases with cases built from the real logs in data/real/
# (fetched by scripts/fetch_real_samples.py and scripts/fetch_crowdstrike_samples.py).
# Runs inside the warden container, where the samples are mounted at /samples.
#
#   scripts/warden.sh real
set -e
[ -d /samples ] || { echo "no /samples mount; run from scripts/warden.sh real"; exit 1; }
python -m warden.cli index >/dev/null 2>&1 || true
python - <<'PY'
from warden.store import CaseStore
CaseStore().delete_all()
print("cleared existing cases")
PY
n=0
for f in /samples/*.evtx /samples/crowdstrike/*.log; do
  [ -f "$f" ] || continue
  echo "ingest $(basename "$f")"
  python -m warden.cli run --log "$f" >/dev/null 2>&1 || echo "  (no alerts)"
  n=$((n + 1))
done
echo "processed $n real log files"
python - <<'PY'
from warden.store import CaseStore
cs = CaseStore().all()
print(f"cases now: {len(cs)}")
PY
