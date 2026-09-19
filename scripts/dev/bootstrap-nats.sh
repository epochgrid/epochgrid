#!/usr/bin/env bash
set -euo pipefail
export EPOCHGRID_PROFILE=development
unset EPOCHGRID_TLS_CA_PATH EPOCHGRID_TLS_FIRST EPOCHGRID_TLS_MIN_VERSION
cd "$(dirname "$0")/../.."
umask 077
cargo build --workspace --locked
./target/debug/epochgrid dev-config
./scripts/dev/download-nats.sh
docker compose up --build --force-recreate -d
