#!/usr/bin/env bash
# Each phase has an independent deadline, heartbeat and descendant cleanup.
set -euo pipefail
cd "$(dirname "$0")/../.."
keyring() { ./scripts/dev/with-test-keyring.sh "$@"; }
phase() {
  export EPOCHGRID_CHECK_LABEL="$1"
  case "$1" in
    fmt) python3 scripts/dev/run-bounded.py 60 cargo fmt --check ;;
    clippy) python3 scripts/dev/run-bounded.py 600 cargo clippy --locked --workspace --all-targets --all-features -- -D warnings ;;
    build|byo-build) python3 scripts/dev/run-bounded.py 900 python3 scripts/ci/runtime.py build ;;
    doctest) python3 scripts/dev/run-bounded.py 180 cargo test --locked --workspace --doc ;;
    unit|secrets) python3 scripts/ci/runtime.py "$@" ;;
    nats|nats-dynamic|byo-nats)
          python3 scripts/dev/run-bounded.py 120 ./scripts/dev/download-nats.sh
          python3 scripts/ci/runtime.py "$@" ;;
    compose) keyring python3 scripts/dev/run-bounded.py 180 ./scripts/dev/smoke.sh ;;
    tui) NATS_SERVER="$PWD/.dev/nats-image/nats-server" keyring python3 scripts/dev/run-bounded.py 180 python3 scripts/dev/tui-smoke.py ;;
    dynamic-tui) NATS_SERVER="$PWD/.dev/nats-image/nats-server" keyring python3 scripts/dev/run-bounded.py 180 python3 scripts/dev/dynamic-tui-smoke.py ;;
    dynamic-join) NATS_SERVER="$PWD/.dev/nats-image/nats-server" keyring python3 scripts/dev/run-bounded.py 180 python3 scripts/dev/dynamic-tui-smoke.py --disconnect-before-join ;;
    relations-tui) NATS_SERVER="$PWD/.dev/nats-image/nats-server" keyring python3 scripts/dev/run-bounded.py 90 python3 scripts/dev/tui-smoke.py --relationships-only ;;
    participants-tui) NATS_SERVER="$PWD/.dev/nats-image/nats-server" keyring python3 scripts/dev/run-bounded.py 120 python3 scripts/dev/tui-smoke.py --participants-only ;;
    harness) python3 scripts/dev/run-bounded.py 30 python3 scripts/release/test-artifact.py
             python3 scripts/dev/run-bounded.py 10 python3 scripts/ci/test-runtime.py
             python3 scripts/dev/run-bounded.py 30 python3 scripts/dev/test-bounded.py
             python3 scripts/dev/run-bounded.py 10 python3 scripts/dev/test-tui-smoke.py
             python3 scripts/dev/run-bounded.py 10 python3 scripts/dev/test-wait-nats.py ;;
    *) echo "Unknown verification phase: $1" >&2; return 2 ;;
  esac
}
if [[ $# -gt 0 ]]; then
  phase "$@"
else
  echo 'SKIP TD-002: full dynamic TUI messaging smoke; run verify.sh dynamic-tui explicitly; see docs/technical-debt.md'
  for check in harness fmt clippy build doctest unit secrets nats compose tui dynamic-join relations-tui participants-tui byo-nats; do phase "$check"; done
  printf 'EpochGrid MVP and identity alpha verification passed\n'
fi
