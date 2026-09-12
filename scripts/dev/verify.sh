#!/usr/bin/env bash
# Each phase has an independent deadline, heartbeat and descendant cleanup.
set -euo pipefail
cd "$(dirname "$0")/../.."
phase() {
  case "$1" in
    fmt) python3 scripts/dev/run-bounded.py 60 cargo fmt --check ;;
    clippy) python3 scripts/dev/run-bounded.py 600 cargo clippy --locked --workspace --all-targets --all-features -- -D warnings ;;
    unit) python3 scripts/dev/run-bounded.py 180 cargo test --locked --workspace ;;
    build) python3 scripts/dev/run-bounded.py 300 cargo build --locked --workspace ;;
    nats) python3 scripts/dev/run-bounded.py 120 ./scripts/dev/download-nats.sh
          NATS_SERVER="$PWD/.dev/nats-image/nats-server" python3 scripts/dev/run-bounded.py 360 cargo test --locked -p epochgrid-service --test registration -- --ignored --test-threads=1 ;;
    compose) python3 scripts/dev/run-bounded.py 180 ./scripts/dev/smoke.sh ;;
    tui) NATS_SERVER="$PWD/.dev/nats-image/nats-server" python3 scripts/dev/run-bounded.py 180 python3 scripts/dev/tui-smoke.py ;;
    relations-tui) NATS_SERVER="$PWD/.dev/nats-image/nats-server" python3 scripts/dev/run-bounded.py 90 python3 scripts/dev/tui-smoke.py --relationships-only ;;
    participants-tui) NATS_SERVER="$PWD/.dev/nats-image/nats-server" python3 scripts/dev/run-bounded.py 120 python3 scripts/dev/tui-smoke.py --participants-only ;;
    harness) python3 scripts/dev/run-bounded.py 30 python3 scripts/dev/test-bounded.py
             python3 scripts/dev/run-bounded.py 10 python3 scripts/dev/test-tui-smoke.py
             python3 scripts/dev/run-bounded.py 10 python3 scripts/dev/test-wait-nats.py ;;
    *) echo "Unknown verification phase: $1" >&2; return 2 ;;
  esac
}
if [[ $# -gt 0 ]]; then
  phase "$1"
else
  for check in harness fmt clippy unit build nats compose tui relations-tui participants-tui; do phase "$check"; done
  printf 'EpochGrid MVP and identity alpha verification passed\n'
fi
