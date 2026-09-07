#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
umask 077
cargo build --workspace --locked
./target/debug/epochgrid dev-config
./scripts/dev/download-nats.sh
docker compose up --build --force-recreate -d
