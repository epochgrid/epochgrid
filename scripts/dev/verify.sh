#!/usr/bin/env bash
# Complete local MVP gate. Close development clients/service before running.
set -euo pipefail
cd "$(dirname "$0")/../.."
cargo fmt --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace
cargo build --locked --workspace
./scripts/dev/download-nats.sh
NATS_SERVER="$PWD/.dev/nats-image/nats-server" cargo test --locked -p epochgrid-service --test registration -- --ignored --test-threads=1
./scripts/dev/smoke.sh
NATS_SERVER="$PWD/.dev/nats-image/nats-server" python3 scripts/dev/tui-smoke.py
printf 'EpochGrid MVP verification passed\n'
