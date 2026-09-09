# MVP acceptance — Milestone 10

This records the original MVP milestone. For current alpha capabilities and limits,
see [the README](../README.md), [multi-device membership](multi-device.md) and
[device verification/transparency](device-verification.md).

Milestones 0–10 implement and test the deliberately narrow Alice/Bob vertical
slice. No new product features, wire versions, permissions, production dependencies
or storage schemas are introduced by the final acceptance milestone.

Run the complete gate from the repository root:

```bash
./scripts/dev/verify.sh
```

This runs formatting, clippy with warnings denied, workspace tests and builds,
downloads the pinned/checksummed NATS server, explicitly executes the live NATS
suite, and runs the Compose/host CLI smoke test. CI uses the same script. Close
existing development clients/service first because Compose smoke uses `.dev/` and
stops the stack afterward. It preserves the development directories and volume.
No GitHub push, release, package or image publishing is part of verification.

The acceptance case can also be run separately after building the workspace and
running `scripts/dev/download-nats.sh`:

```bash
NATS_SERVER="$PWD/.dev/nats-image/nats-server" cargo test -p epochgrid-service --test registration mvp::cli_mvp_ciphertext_only_and_restart -- --ignored
```

Ordinary `cargo test --workspace` explicitly ignores the four NATS integration
cases. The verification script and CI run them with `--ignored`; a passing ordinary
test run alone is not the complete MVP gate. Test-only OpenMLS dependencies use
the same workspace versions as the client implementation.

## Success criteria and evidence

The acceptance case is `mvp::cli_mvp_ciphertext_only_and_restart` in
`crates/epochgrid-service/tests/mvp/mod.rs`. It uses a fresh temporary directory,
isolated NATS server and real service/CLI binaries. Each CLI command is a new
process; test-side stores only inspect results, never create identities, encrypt,
join or advance the ratchets for the clients.

| Original MVP criterion | Acceptance assertion |
| --- | --- |
| 1. Create local device identities | Alice and Bob each run `identity init` through the CLI in fresh directories |
| 2. Independent NATS and MLS identities | NATS keys and MLS signing keys differ across users; a valid device NKey signature fails verification under that device's MLS signing key |
| 3. Authenticate with NKeys | Both CLI registrations succeed against the generated NKey-only NATS configuration |
| 4. Register public MLS identity and KeyPackage | Stored IDENTITIES registrations exactly match local public registrations |
| 5. Discover peers | Each CLI lookup returns the other device's exact registration payload |
| 6. Alice creates a group | CLI creates `engineering`; its group ID is retained for later comparisons |
| 7. Invite Bob | CLI invite succeeds, with one Commit in CHAT and one Welcome in MAILBOX |
| 8. Deliver Welcome through NATS | Bob is offline at publication; stored mailbox payload decodes as an EpochGrid envelope containing MLS Welcome |
| 9. Bob joins | CLI join succeeds and both devices report Alice/Bob membership |
| 10. Exchange E2EE messages | Four distinct messages, alternating senders across restart, arrive with the expected authenticated sender and plaintext |
| 11. Persist encrypted messages | CHAT contains exactly four application PrivateMessages and one Commit PrivateMessage, with matching group IDs and subjects |
| 12. Infrastructure stores no application plaintext | Known plaintext markers and both NKey seeds are absent from all stored stream payloads, subjects, headers, stopped broker/service files and the service log |
| 13. Persist local MLS state | Independent CLI processes continue sending/decrypting while retaining the same identity registrations and group IDs |
| 14. Restart and resume | Server and service are killed/restarted against disk state; new CLI processes exchange further messages without reinitializing, registering again, recreating or reinviting |

Both local transcripts must contain exactly the four expected messages in stream
order, with correct sender/outgoing attribution and no quarantined entries. After
infrastructure stops, fresh `message history --offline` processes must still show
each marker once. The service's local group list must remain empty.

The infrastructure scan enumerates all streams and requires exactly CHAT, MAILBOX,
KV_IDENTITIES and KV_CHANNELS. It checks every retained message, including public
metadata streams; those KV values are not expected to be ciphertext. All CHAT
payloads must deserialize as MLS PrivateMessages, with content type Application
or Commit and the correct MLS group ID. It requires nonzero broker/service files
to have been scanned, avoiding a successful empty-directory check.

## Supporting adversarial and recovery tests

| Boundary | Existing automated coverage |
| --- | --- |
| Unknown/anonymous NATS client, wrong enrollment, forged registration, directory isolation and another device's inbox | `nats_registration_and_restart` |
| ID/subject injection, wire version, oversized/trailing wire bytes, registration key binding | Core wire and identity tests |
| Wrong Welcome inviter, tampered Welcome, rollback and idempotent retry | `welcome_authentication_rollback_and_retry` |
| Application tampering, wrong group, replay, authenticated sender and two-way ratchet reload | `authenticated_ciphertext_tampering_replay_and_restart` |
| Offline backlog, lost consumer ACK, duplicates, quarantine, other-device consumer isolation, server restart | `durable_history_offline_ack_recovery_and_server_restart` |
| Pending invitation, lost Welcome ACK and ambiguous publish beyond dedup window | `resume_pending_invitation_and_ambiguous_publish` |
| Forced process death before/after transaction commit; lock release and continued two-way traffic | Core `recovery_tests` and Compose CLI smoke |
| Transcript write failures roll back ratchets and delivery progress | `transcript_failure_rolls_back_ratchet_and_delivery_progress` |

See [recovery boundaries](recovery.md) for the detailed failure matrix. These
assertions complement the fresh acceptance flow; they are not substitutes for it.

## What completion means

The known-marker scan detects regressions that expose these test messages or
NKey seeds as raw bytes. It is not proof against arbitrary encoded leaks, future
code paths, endpoint compromise, side channels or all possible private-key leaks.
It inspects stored data and service logs, not every network frame or process memory.
Passing MLS framing checks alone would not establish confidentiality; successful
peer decryption and the existing tampering/replay tests provide additional evidence.

Production TLS, exact per-group NATS authorization, member removal/key-update
lifecycle, forward-secrecy/post-compromise-security validation, KeyPackage
replenishment/expiry, encrypted local key storage, hardware power-loss tolerance
and safe backup restore remain unimplemented or unvalidated. Local transcripts
are intentionally plaintext development storage. Public metadata and traffic
analysis remain visible. See [the threat model](threat-model.md) and
[security policy](../SECURITY.md).

The completed gate establishes the scoped MVP foundation. It does not establish
production readiness or authorize expanding the product scope or publishing a release.
