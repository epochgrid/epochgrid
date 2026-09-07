#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
umask 077
./target/debug/epochgrid dev-config
docker compose up --build --force-recreate -d
service_pid=''
cleanup() {
  if [[ -n "$service_pid" ]]; then
    kill -INT "$service_pid" 2>/dev/null || true
    wait "$service_pid" || true
  fi
  docker compose down
}
trap cleanup EXIT
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
kill -INT "$service_pid"
wait "$service_pid"
service_pid=''
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
