#!/bin/sh
# First start: seed the knowledge base and eval fixtures into the data volume.
set -e
mkdir -p "$WARDEN_DATA_DIR/knowledge" "$WARDEN_DATA_DIR/eval"
[ -n "$(ls -A "$WARDEN_DATA_DIR/knowledge" 2>/dev/null)" ] || cp -r /app/seed/knowledge/. "$WARDEN_DATA_DIR/knowledge/"
[ -n "$(ls -A "$WARDEN_DATA_DIR/eval" 2>/dev/null)" ] || cp -r /app/seed/eval/. "$WARDEN_DATA_DIR/eval/"
case "$1" in
  serve) shift; exec python -m warden.cli serve --host 0.0.0.0 --port "${PORT:-8000}" "$@" ;;
  scheduler)
    # nightly refresh (ATT&CK, intel, KB, baselines, retention) plus detection over pushed events
    while true; do
      python -m warden.cli refresh || echo "refresh failed; retrying next cycle"
      python -m warden.cli run --from-db --since 25h || true
      sleep "${WARDEN_REFRESH_INTERVAL:-86400}"
    done ;;
  *) exec python -m warden.cli "$@" ;;
esac
