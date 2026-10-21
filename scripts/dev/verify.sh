#!/usr/bin/env bash
# Each phase has an independent deadline, heartbeat and descendant cleanup.
set -euo pipefail
cd "$(dirname "$0")/../.."
keyring() { ./scripts/dev/with-test-keyring.sh "$@"; }
phase() {
  case "$1" in
    fmt) python3 scripts/dev/run-bounded.py 60 cargo fmt --check ;;
    clippy) python3 scripts/dev/run-bounded.py 600 cargo clippy --locked --workspace --all-targets --all-features -- -D warnings ;;
    unit) keyring python3 scripts/dev/run-bounded.py 180 cargo test --locked --workspace ;;
    secrets) keyring python3 scripts/dev/run-bounded.py 120 cargo test --locked -p epochgrid-core secrets::tests::live_keyring_restart_binding_duplicate_and_lock -- --ignored --exact
             env DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent/epochgrid-test-bus python3 scripts/dev/run-bounded.py 30 cargo test --locked -p epochgrid-core secrets::tests::live_unavailable_bus_is_bounded -- --ignored --exact
             keyring python3 scripts/dev/run-bounded.py 60 python3 scripts/dev/test-secrets-live.py ;;
    build) python3 scripts/dev/run-bounded.py 300 cargo build --locked --workspace --examples --bins ;;
    byo-build) python3 scripts/dev/run-bounded.py 600 cargo build --locked --workspace --examples --bins
               python3 scripts/dev/run-bounded.py 300 cargo test --locked -p epochgrid-service --test registration --no-run ;;
    byo-nats)
          local cases=(configuration_standalone configuration_cluster operator_jwt_standalone operator_jwt_cluster)
          if [[ $# -gt 1 ]]; then
            case "$2" in
              configuration_standalone|configuration_cluster|operator_jwt_standalone|operator_jwt_cluster) cases=("$2") ;;
              *) echo 'Unknown BYO-NATS qualification case' >&2; return 2 ;;
            esac
          fi
          for testcase in "${cases[@]}"; do
            env -u EPOCHGRID_TLS_CA_PATH -u EPOCHGRID_TLS_FIRST -u EPOCHGRID_TLS_MIN_VERSION EPOCHGRID_PROFILE=production NATS_SERVER="$PWD/.dev/nats-image/nats-server" ./scripts/dev/with-test-keyring.sh python3 scripts/dev/run-bounded.py 260 cargo test --locked -p epochgrid-service --test registration "byo_nats::$testcase" -- --ignored --exact --nocapture
          done ;;
    nats|nats-dynamic)
          local dynamic_case=auth_callout::dynamic_enrollment_inbox_isolation_revocation_without_reload
          local selection=(--skip "$dynamic_case" --skip byo_nats::)
          if [[ "$1" == nats-dynamic ]]; then
            selection=(--exact "$dynamic_case")
          else
            echo 'SKIP TD-002: dynamic Auth Callout integration; run verify.sh nats-dynamic explicitly; see docs/technical-debt.md'
          fi
          python3 scripts/dev/run-bounded.py 120 ./scripts/dev/download-nats.sh
          env -u EPOCHGRID_TLS_CA_PATH -u EPOCHGRID_TLS_FIRST -u EPOCHGRID_TLS_MIN_VERSION EPOCHGRID_PROFILE=development NATS_SERVER="$PWD/.dev/nats-image/nats-server" ./scripts/dev/with-test-keyring.sh python3 scripts/dev/run-bounded.py 360 cargo test --locked -p epochgrid-service --test registration -- --ignored --test-threads=1 "${selection[@]}" ;;
    compose) keyring python3 scripts/dev/run-bounded.py 180 ./scripts/dev/smoke.sh ;;
    tui) NATS_SERVER="$PWD/.dev/nats-image/nats-server" keyring python3 scripts/dev/run-bounded.py 180 python3 scripts/dev/tui-smoke.py ;;
    dynamic-tui) NATS_SERVER="$PWD/.dev/nats-image/nats-server" keyring python3 scripts/dev/run-bounded.py 180 python3 scripts/dev/dynamic-tui-smoke.py ;;
    dynamic-join) NATS_SERVER="$PWD/.dev/nats-image/nats-server" keyring python3 scripts/dev/run-bounded.py 180 python3 scripts/dev/dynamic-tui-smoke.py --disconnect-before-join ;;
    relations-tui) NATS_SERVER="$PWD/.dev/nats-image/nats-server" keyring python3 scripts/dev/run-bounded.py 90 python3 scripts/dev/tui-smoke.py --relationships-only ;;
    participants-tui) NATS_SERVER="$PWD/.dev/nats-image/nats-server" keyring python3 scripts/dev/run-bounded.py 120 python3 scripts/dev/tui-smoke.py --participants-only ;;
    harness) python3 scripts/dev/run-bounded.py 30 python3 scripts/dev/test-bounded.py
             python3 scripts/dev/run-bounded.py 10 python3 scripts/dev/test-tui-smoke.py
             python3 scripts/dev/run-bounded.py 10 python3 scripts/dev/test-wait-nats.py ;;
    *) echo "Unknown verification phase: $1" >&2; return 2 ;;
  esac
}
if [[ $# -gt 0 ]]; then
  phase "$@"
else
  echo 'SKIP TD-002: full dynamic TUI messaging smoke; run verify.sh dynamic-tui explicitly; see docs/technical-debt.md'
  for check in harness fmt clippy unit build secrets nats compose tui dynamic-join relations-tui participants-tui byo-build byo-nats; do phase "$check"; done
  printf 'EpochGrid MVP and identity alpha verification passed\n'
fi
