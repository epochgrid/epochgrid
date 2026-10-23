#!/bin/bash
set -euo pipefail

echo "=== Checking Rust code quality before commit ==="

# Check formatting for all files
cargo fmt --check 2>&1 | \
    grep -q "^Diff in.*$" && {
        echo ""
        echo "❌ Formatting issues found. Run: cargo fmt"
        exit 1
    } || true

# Optionally, you could add clippy here too
echo "✅ Code quality checks passed!"
