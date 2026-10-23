#!/usr/bin/env bash
# Never connect tests to the caller's session/keyring. Secret bytes stay in the
# encrypted disposable GNOME keyring; its random password is piped, never logged.
set -euo pipefail
if [[ "${1:-}" == --session ]]; then
  shift
  # Only operation and exit status: never enumerate credentials or dump the environment.
  operation=startup
  trap 'status=$?; if (( status != 0 )); then echo "EpochGrid keyring: operation=$operation exit=$status" >&2; fi' EXIT
  export GNOME_KEYRING_CONTROL="$XDG_RUNTIME_DIR/keyring"
  mkdir -m 700 -p "$GNOME_KEYRING_CONTROL"
  head -c 32 /dev/urandom | base64 | timeout 10 gnome-keyring-daemon --unlock --components=secrets --control-directory="$GNOME_KEYRING_CONTROL" >/dev/null
  timeout 10 gnome-keyring-daemon --start --components=secrets --control-directory="$GNOME_KEYRING_CONTROL" >/dev/null
  # Verify readiness with a bounded operation before starting the test command.
  operation=readiness
  timeout 10 bash -c 'printf ready | secret-tool store --label=EpochGrid-test application epochgrid-test-ready'
  timeout 10 secret-tool clear application epochgrid-test-ready
  operation=test-command
  "$@"
  exit $?
fi
for tool in dbus-run-session gnome-keyring-daemon secret-tool timeout; do
  command -v "$tool" >/dev/null || { echo "Missing $tool; install dbus-daemon gnome-keyring libsecret-tools" >&2; exit 2; }
done
umask 077
keyring_root=$(mktemp -d /tmp/epochgrid-keyring.XXXXXX)
trap 'rm -rf "$keyring_root"' EXIT
export XDG_DATA_HOME="$keyring_root/data" XDG_CONFIG_HOME="$keyring_root/config" XDG_RUNTIME_DIR="$keyring_root/runtime"
mkdir -m 700 -p "$XDG_DATA_HOME" "$XDG_CONFIG_HOME" "$XDG_RUNTIME_DIR"
unset DBUS_SESSION_BUS_ADDRESS GNOME_KEYRING_CONTROL SSH_AUTH_SOCK
dbus-run-session -- bash "$0" --session "$@"
