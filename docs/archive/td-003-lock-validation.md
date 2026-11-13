# TD-003 lock repair — 2026-11-12

Milestone 35 checkpoint: `274005e` on `feature/milestone-34`. Repair branch:
`fix/td-003-credential-lock`. This is a bounded repair of AQ-F04, not closure of
every historical TD-003 failure or milestone 35 acceptance. Nothing was published.

## Reproduction and repair

The new AQ-LOCK-01 test pauses an unrelated child between fork and exec while a
credential operation owns its lock. Before the repair, the next operation fails
with `credential initialization already in progress` / would-block even though
the first operation has completed. The bounded pre-fix invocation returned 101
in 0.214s. The child remains paused during the assertion, so success cannot come
from waiting until its inherited descriptor closes. The fixture uses an in-memory
credential backend and socket barriers; it does not depend on Secret Service,
sleeps, tracing, or probabilistic scheduling.

This behavior follows Linux's open-file-description lock lifetime: an inherited
descriptor can retain the lock after the parent closes its own descriptor.
Explicit unlock releases it even while a duplicate remains open. See
[flock(2)](https://man7.org/linux/man-pages/man2/flock.2.html).

The guard calls unlock before close on drop, only in the acquiring process. All
eight production acquisition sites use it: credential initialization, database
open, identity ownership, capacity installation, broker revocation, authentication
setup, runtime binding, and authority ownership. Active contention still rejects
immediately. The guard exposes neither cloning nor descriptor access. No retry,
deadline extension, serialization or credential fallback was introduced.

AQ-LOCK-01 checks successful provisioning and a lost-create-response error, real
contention during the operation, and exact retry retaining a single key.
AQ-LOCK-02 checks that a forked child dropping a copied guard cannot unlock its
parent and that failed acquisition does not release the owner's lock. Both pass
after the fix and are mandatory members of the 28-case unit inventory. This is a
reproduced defect consistent with AQ-F04; the original untraced run did not retain
enough evidence to identify its particular child. Abrupt process death bypasses
destructors and remains subject to OS descriptor cleanup.

## Retained host failure

The initial Ubuntu 26.04 sample planned five ordinary, untraced unit gates with
fresh disposable keyrings and default concurrency, stopping at the first failure.
Attempts 1–3 passed (155 top-level tests per gate). Attempt 4 failed; attempt 5
was not run. Core reported 40 passed / 78 failed / three ignored / one partitioned
parser case. Both new lock tests passed. This candidate preceded conversion of
the final authentication-setup lock site; the final supported-baseline build
includes that conversion.

A local crash report at the matching timestamp identifies `gnome-keyring` 50.0-1,
SIGABRT, and missing Secret Service client/session followed by fatal NULL GVariant
construction. The D-Bus log shows daemon reactivation; subsequent requests report
locked/unavailable service. This is a distinct daemon failure, not credential
file-lock contention. Only sanitized function names, version and signal are
retained; no core dump, process environment, credential values or private state.

The upstream [50.0 service implementation](https://raw.githubusercontent.com/GNOME/gnome-keyring/50.0/daemon/dbus/gkd-secret-service.c)
initializes caller state asynchronously and asserts its presence during session
lookup. That source is consistent with the crash diagnostics; we have not proved
the exact daemon scheduling sequence or fixed the daemon. No speculative
application workaround or host package change was made. Earlier milestone 34
keyring failures remain separately unclassified.

## Supported-baseline verification

The separate local sample uses the cached Ubuntu 24.04 builder from
`scripts/release/qualification.Dockerfile`, pinned Rust 1.98.1, no container network,
and an isolated target directory. The build manifest verifies source, revision,
OS/libc, binary hashes and checkout path before execution. Reusing build/cache
state makes these warm local checks, not independent cold hosted runs. Each unit
attempt starts fresh disposable keyrings; concurrency and watchdogs are unchanged.
The baseline packages are GNOME Keyring `46.1-2ubuntu0.2`, GLib
`2.80.0-6ubuntu3.10`, and glibc `2.39-0ubuntu8.9`.

On a supported native checkout, rebuild before reproducing:

```bash
./scripts/dev/verify.sh build
./scripts/dev/verify.sh adversarial AQ-LOCK-01
./scripts/dev/verify.sh adversarial AQ-LOCK-02
./scripts/dev/verify.sh unit
./scripts/dev/verify.sh secrets
./scripts/dev/verify.sh nats
./scripts/dev/verify.sh byo-nats
```

BYO and the production TLS case require the documented distinct-UID fixture;
the local container sample used `EPOCHGRID_ROLE_NATIVE=1` with the qualification
image's sudo rules. This does not relax production UID checks.

Results and source/executable hashes are retained in
[the machine record](td-003-lock-evidence.json). Compilation and execution are
separately bounded. Unit sampling stops on any failure; no failed attempt is
discarded or replaced. The original host sample remains evidence regardless of
supported-baseline results.

| Check | Result |
| --- | --- |
| Pre-fix AQ-LOCK-01 | Failed deterministically with would-block, exit 101 |
| Post-fix AQ-LOCK-01 / AQ-LOCK-02 | Passed; both required in the default unit gate |
| Supported-baseline build | Passed, 52.017s including runtime packaging |
| Five ordinary Ubuntu 24.04 unit gates | All passed, 155 top-level tests each; 29.662 / 29.761 / 30.258 / 32.268 / 30.110s |
| Live keyring phase | Passed, 15.130s; locked/unavailable, restart, recovery and credential protection |
| Retained NATS phase | All 16 cases passed, 280.951s total; per-case deadlines unchanged |
| Configuration R1 / R3 | Passed, 79.559 / 93.422s |
| Operator-JWT R1 / R3 | Passed, 91.619 / 110.117s |
| Formatting / Clippy / Python harness | Passed; 77 harness tests |

The container's `sudo` emitted hostname-resolution warnings during distinct-UID
fixtures. These warnings are retained as an environment limitation, not excluded
test failures. Local SQLCipher memlock warnings also remain; no causal link to
the repaired lock defect is established.

## Remaining work

TD-003 remains open for the Ubuntu 26.04/GNOME Keyring 50 compatibility failure,
the retained milestone 33 failover-readiness investigation, and the documented
cold-run reliability evidence. A passing local sample cannot establish an
availability rate or explain a historical failure it did not reproduce.
TD-001/002 exclusions and restoration requirements are unchanged. Hosted CI,
final bundle/image qualification and milestone 35 scope review are not certified
by this repair.
