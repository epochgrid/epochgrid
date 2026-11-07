# Local Git hooks

Hooks are optional conveniences. The required checks are
[`scripts/dev/verify.sh`](../dev/verify.sh) and [hosted PR CI](../../docs/ci-strategy.md).
Run the verifier explicitly; neither cloning nor committing installs hooks.

## Current helper limitations

The checked-in helpers are legacy examples, not a supported enforcement path:

- `install-hooks.sh` copies files with `.sh` suffixes. Git's standard hook names
  are `pre-commit`, `commit-msg` and `pre-rebase`, without that suffix.
- `pre-commit.sh` can mask command failures with `|| true`; it is not a reliable
  substitute for running the formatting check directly.
- `commit-msg.sh` suggests conventional prefixes; it does not require them.
- `pre-rebase.sh` uses an environment/default branch guess and prints force-push
  advice. It does not establish whether a rebase is safe.
- The root `.pre-commit-config.yaml` is a legacy alternative and needs repair
  before being recommended: its Clippy entry contains shell operators in a system
  command, and its hook-stage/configuration compatibility is not qualified here.

This documentation cleanup does not change those scripts or install any hooks.
Do not move tracked scripts into `.git`, overwrite an existing hook configuration,
or suppress lint failures while setting up local tooling.

## Minimal formatting hook

If you want a local formatting check, first inspect `git config --get core.hooksPath`
and any existing hook. In a repository using Git's default hook directory, the
following installs a hook only when that path does not already exist:

```sh
hook_path=$(git rev-parse --git-path hooks/pre-commit)
test ! -e "$hook_path" || exit 1
mkdir -p "$(dirname "$hook_path")"
cat > "$hook_path" <<'HOOK'
#!/bin/sh
exec cargo fmt --check
HOOK
chmod +x "$hook_path"
```

The hook checks the workspace, not only staged lines. Use the repository's pinned
toolchain. If another hook manager or custom `core.hooksPath` is configured,
integrate the command there instead. Remove only a hook you installed and no longer
want; repository commits do not track `.git/hooks`.
