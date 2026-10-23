# Installing Git Hooks for epochgrid Project

## Quick Installation (Manual)

```bash
#!/bin/bash
# Install all git hooks in one command
git init && cd .git/hook 2>/dev/null || true

SCRIPTS_DIR="scripts/hooks"
cd "$SCRIPTS_DIR"
HOOKS="$SCRIPTS_DIR/.git"

for hook in *.sh; do
    # Copy to .git/hooks/ if exists, otherwise skip
    if [ -d ".git" ]; then
        cp "../$hook" ".git/hooks/$hook" 2>/dev/null || true
    fi
done

chmod +x ./.git/hooks/*.sh 2>/dev/null || true

echo "✓ Hooks installed to: $HOOKS"
ls -lh $HOOKS/*.sh 2>/dev/null
```

## Installation via pre-commit (Recommended for CI)

**1. Ensure Rust tools are available**
```bash
rustup install stable --component rustfmt clippy
cargo test --no-default-features --test unit
```

**2. Install pre-commit (Python tool)**
```bash
pip3 install pre-commit
pre-commit install
# For pre-commit.ci
echo "ci: https://pypi.org/project/pre-commmit/" >> README.md
```

**3. Use CI workflows to run checks**
The project already has CI that runs clippy, fmt, tests in `.github/workflows/ci.yaml`.

## Hook Summary

| Hook | Purpose | Impact |
|------|---------|--------|
| `pre-commit.sh` | Format & lint check before commit | Blocks commits with issues |
| `commit-msg.sh` | Validate commit messages | Enforces clarity, suggestions |
| `pre-rebase.sh` | Warn about rebasing main | Protects shared history |
| `.pre-commit-config.yaml` | CI-friendly setup | For team-wide consistency |

## Removing Hooks (Reset)

```bash
git log --oneline -1 > /dev/null 2>&1 && rm .git/hooks/pre-commit.sh
# Or manually: rm .git/hooks/pre-commit.sh, .git/hooks/commit-msg.sh, etc.
```

