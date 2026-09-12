#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
umask 077
service_pid=''
stop_service() {
  [[ -n "$service_pid" ]] || return 0
  kill -INT "$service_pid" 2>/dev/null || true
  for attempt in {1..50}; do
    if ! kill -0 "$service_pid" 2>/dev/null; then
      wait "$service_pid"
      service_pid=''
      return 0
    fi
    sleep 0.1
  done
  echo 'EpochGrid service shutdown timed out after 5s; forcing termination' >&2
  kill -KILL "$service_pid" 2>/dev/null || true
  service_pid=''
  return 1
}
cleanup() {
  stop_service || true
  python3 scripts/dev/run-bounded.py 20 docker compose down || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
./target/debug/epochgrid dev-config
docker compose up --build --force-recreate -d
python3 scripts/dev/wait-nats.py
./target/debug/epochgrid-service >.dev/smoke-service.log 2>&1 &
service_pid=$!
ready=false
for attempt in {1..50}; do
  if ./scripts/dev/create-alice.sh >.dev/smoke-alice.log 2>&1; then
    ready=true
    break
  fi
  if ! kill -0 "$service_pid" 2>/dev/null; then
    cat .dev/smoke-service.log >&2
    exit 1
  fi
  sleep 0.1
done
if [[ "$ready" != true ]]; then
  cat .dev/smoke-service.log .dev/smoke-alice.log >&2
  exit 1
fi
cat .dev/smoke-alice.log
./scripts/dev/create-bob.sh
./target/debug/epochgrid --home .dev/alice identity lookup bob > /dev/null
# Each command is a new client process loading the persisted identity.
./scripts/dev/create-alice.sh
stop_service
./target/debug/epochgrid-service >>.dev/smoke-service.log 2>&1 &
service_pid=$!
ready=false
for attempt in {1..50}; do
  if ./scripts/dev/create-bob.sh >.dev/smoke-bob.log 2>&1; then ready=true; break; fi
  sleep 0.1
done
[[ "$ready" == true ]] || { cat .dev/smoke-service.log >&2; exit 1; }
cat .dev/smoke-bob.log
if ! ./target/debug/epochgrid --home .dev/alice channel list | grep -q '^engineering '; then
  ./target/debug/epochgrid --home .dev/alice channel create engineering
fi
./target/debug/epochgrid --home .dev/alice channel invite engineering bob
if ! ./target/debug/epochgrid --home .dev/bob channel list | grep -q '^engineering '; then
  ./target/debug/epochgrid --home .dev/bob channel join --from alice
fi
./target/debug/epochgrid --home .dev/bob channel members engineering
python3 scripts/dev/chat-smoke.py
printf 'EpochGrid Compose and CLI smoke test passed\n'
