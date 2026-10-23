#!/bin/bash
# Install git hooks for epochgrid project
set -euo pipefail

REPOS_ROOT=$(git rev-parse --show-toplevel)

echo "📦 Installing git hooks to .git/hooks/"
cp "$REPOS_ROOT/scripts/hooks/pre-commit.sh" ".git/hooks/pre-commit.sh" 2>/dev/null || true
cp "$REPOS_ROOT/scripts/hooks/commit-msg.sh" ".git/hooks/commit-msg.sh" 2>/dev/null || true
cp "$REPOS_ROOT/scripts/hooks/pre-rebase.sh" ".git/hooks/pre-rebase.sh" 2>/dev/null || true
chmod +x ./.git/hooks/*.sh

# Install pre-commit framework if available
if command -v pre-commit &>/dev/null; then
    echo "   Running: pre-commit install"
    pre-commit install --install-hooks 2>/dev/null || true
fi

echo ""
echo "✅ Hooks installed!"
echo ""
echo "Hook summary:"
echo "  ├── pre-commit.sh     : Run formatting checks before commit (cargo fmt)"
echo "  ├── commit-msg.sh     : Validate conventional commits format"
echo "  └── pre-rebase.sh     : Warn when rebasing protected branches"
