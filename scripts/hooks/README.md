# Git Hooks for Project Quality

## Installation

Run once after cloning or onboarding a developer:

```bash
git init                        # Initialize repo if needed
cd ./.git/hooks/ || cd hooks/   # Navigate to hooks directory (if in git/hooks)
for hook in *.sh; do            # Copy all hooks
    cp "../$hook" "$hook"       # Or move based on project structure
done
chmod +x ./*                    # Make them executable

# Or, if installed directly:
cd scripts/hooks/
for f in *.sh; do
    mv "$f" "../.git/hooks/$f"
    chmod +x "../.git/hooks/$f"
done
```

## Hook Descriptions

### pre-commit.sh ✅ (Recommended)
- **When**: Before each commit
- **What**: Runs `cargo fmt --check` on all staged files
- **Ensures**: Consistent Rust formatting before review
- **Exit code 1** if formatting fails, blocking bad commits

### commit-msg.sh ℹ️ 
- **When**: When preparing a commit message
- **What**: Validates conventional commit format
- **Ensures**: Clear, descriptive commit messages for changelogs
- **Tip**: Use prefixes like `fix:`, `feat:`, `docs:` etc.

### pre-rebase.sh ⚠️
- **When**: Starting a rebase operation
- **What**: Warns about rebasing protected branches (main/master)
- **Ensures**: PR commits are preserved, not lost by rewriting main

## Pre-commit Framework (Alternative)

For CI-friendly setup, use the [`pre-commit`](https://github.com/pre-commit/pre-commit) framework:

```bash
# In project root after cloning
pip install pre-commit

# Add to .pre-commit-config.yaml:
cat > .pre-commit-config.yaml << 'YAML'
repos:
  - repo: local
    hooks:
      - id: cargo-fmt-check
        name: Check Rust formatting
        entry: cargo check-format --all-files
        language: system
        pass_filenames: false
        always_run: true
        files: \.(rs|toml)$
YAML

pre-commit install  # Install hooks
```

## Removing Hooks

To remove a hook, delete it from `.git/hooks/`:

```bash
rm .git/hooks/pre-commit.sh
# or reinstall with: git checkout -- .git/hooks/pre-commit  (if tracked)
```

