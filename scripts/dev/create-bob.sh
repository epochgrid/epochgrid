#!/usr/bin/env bash
set -euo pipefail
export EPOCHGRID_PROFILE=development
unset EPOCHGRID_TLS_CA_PATH EPOCHGRID_TLS_FIRST EPOCHGRID_TLS_MIN_VERSION
cd "$(dirname "$0")/../.."
exec ./target/debug/epochgrid --home .dev/bob identity register
