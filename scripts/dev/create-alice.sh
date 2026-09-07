#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
exec ./target/debug/epochgrid --home .dev/alice identity register
