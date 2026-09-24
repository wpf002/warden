#!/bin/sh
# Start, restart, or stop the whole local Warden demo stack and open every page it serves.
#
#   scripts/warden.sh start|restart|real|stop|status|logs
#
#   real   replace the demo cases with cases built from the real logs in data/real/
#
# Opens the console on start/restart. The support pages are printed, not opened:
#   vendors   http://localhost:5056/state        fake Okta org + CrowdStrike tenant
#   inbox     http://localhost:8025              Mailpit: notifications Warden sent
#   metrics   http://localhost:$WARDEN_PORT/metrics
set -e
cd "$(dirname "$0")/.."
PORT=$(grep -E '^WARDEN_PORT=' .env 2>/dev/null | cut -d= -f2)
PORT=${PORT:-8000}
DC="docker compose -f docker-compose.yml -f docker-compose.demo.yml"
CONSOLE="http://localhost:$PORT"

ensure_docker() {
  docker info >/dev/null 2>&1 && return 0
  echo "Docker is not running; starting Docker Desktop..."
  open -a Docker 2>/dev/null || { echo "start Docker yourself, then rerun"; exit 1; }
  i=0
  until docker info >/dev/null 2>&1; do
    i=$((i + 1))
    [ "$i" -gt 90 ] && echo "Docker did not start" && exit 1
    sleep 2
  done
}

open_console() {
  command -v open >/dev/null 2>&1 && open "$CONSOLE" || true
}

wait_healthy() {
  echo "waiting for the API..."
  i=0
  until curl -fsS "$CONSOLE/healthz" >/dev/null 2>&1; do
    i=$((i + 1))
    [ "$i" -gt 60 ] && echo "API did not come up; try: $DC logs warden" && exit 1
    sleep 2
  done
}

seed_if_empty() {
  n=$($DC exec -T warden python -c "from warden.store import CaseStore; print(len(CaseStore().all()))" 2>/dev/null || echo 0)
  if [ "$n" = "0" ]; then
    echo "seeding demo scenarios (actions run live against the local stand-ins)..."
    $DC up seed >/dev/null 2>&1 || true
  fi
  echo "cases in the console: $($DC exec -T warden python -c 'from warden.store import CaseStore; print(len(CaseStore().all()))' 2>/dev/null)"
}

case "${1:-start}" in
  start|restart)
    ensure_docker
    [ "$1" = "restart" ] && $DC down --remove-orphans
    $DC up -d --build
    wait_healthy
    seed_if_empty
    echo "console  $CONSOLE"
    echo "vendors  http://localhost:5056/state"
    echo "inbox    http://localhost:8025"
    open_console
    ;;
  real)
    ensure_docker
    $DC exec -T warden sh /app/scripts/seed_real.sh
    ;;
  stop)   ensure_docker; $DC down --remove-orphans ;;
  status) $DC ps ;;
  logs)   shift; $DC logs -f "$@" ;;
  *)      echo "usage: $0 start|restart|real|stop|status|logs" && exit 2 ;;
esac
