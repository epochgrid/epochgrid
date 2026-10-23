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

# Configure hooks in .pre-commit-config.yaml
cat > .pre-commit-config.yaml << 'YAML'
repos:
  - repo: local
    hooks:
      - id: cargo-fmt-check
        name: check cargo formatting
        entry: cargo fmt --check
        language: system
        pass_filenames: false
        always_run: true
        stages: [commit]
      
      - id: clippy-lint
        name: check cargo clippy warnings
        entry: ./scripts/dev/verify.sh clippy 2>/dev/null || echo "skipped"
        language: system
        pass_filenames: false
        always_run: true

  - repo: https://github.com/pre-commit/mirrors-prettier
    rev: v3.1.0
    hooks:
      - id: prettier
        name: check markdown/formatting in docs
        types_or: [text, javascript, markdown, yaml]
        args: ['--ignore-path', '.gitignore']
YAML

pre-commit install  # Install git hooks (pre-commit and pre-push)
```

The configuration:
- **cargo-fmt-check**: Ensures Rust formatting is consistent
- **clippy-lint**: Checks for common bug-prone patterns via clippy
- **prettier**: Validates markdown, config, and documentation files

## Removing Hooks

To remove a hook, delete it from `.git/hooks/`:

```bash
rm .git/hooks/pre-commit.sh
# or reinstall with: git checkout -- .git/hooks/pre-commit  (if tracked)
```

