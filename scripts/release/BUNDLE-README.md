# EpochGrid Linux qualification bundle

This bundle targets Ubuntu 24.04 x86-64. It is a CI qualification candidate, not
an alpha release. A `local` build is for local testing only. See BUILD.json for
source identity, toolchain, native library requirements and file checksums.

Verify the sibling SHA256SUMS before extracting. Checksums detect corruption;
they do not authenticate the publisher. Put bin/epochgrid and bin/epochgrid-service
in your chosen PATH directory. No Rust compiler or source checkout is needed.

Runtime requirements: glibc, libgcc, CA certificates, a D-Bus session and configured
Secret Service provider with an unlocked default collection (GNOME Keyring is
qualified). A suitable terminal is needed for the TUI. NATS is operator-provided.
Use distinct authority/control accounts and keyring sessions. Missing credentials
fail closed; there is no plaintext fallback. No installer configures service accounts.

Stop affected processes before replacing binaries. Preserve homes, database
metadata and matching keyrings. Replacement does not authorize schema migration;
schema-2 authority state requires explicit stopped-authority `audit upgrade`.
Downgrades are not guaranteed. Removing these binaries does not remove user state.

Operator setup and limits at this bundle's source revision:
https://github.com/epochgrid/epochgrid/tree/main/docs/operator
Use BUILD.json's commit to select the matching revision, not newer main behavior.
See linux-artifacts.md, auth-callout.md, audit.md and ../secret-storage.md.

TD-001/002/003 remain open. Dynamic attachment access and full dynamic messaging
qualification remain outside this artifact's guarantees. GHCR and authenticated
release publication are later milestones.
