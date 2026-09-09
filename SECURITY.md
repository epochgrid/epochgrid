# Security policy

EpochGrid is an unaudited development prototype. Do not use it for sensitive or
production communications. Supported development work targets the current main
branch; no stable security-supported release exists yet.

Report vulnerabilities privately using GitHub's “Report a vulnerability” facility
on the affected repository in https://github.com/epochgrid when enabled. If it is
unavailable, contact an organization maintainer privately to arrange disclosure;
do not post exploit details or secrets in public issues. No dedicated security
email or response-time commitment has been established.

Never attach NATS seeds, credentials, SQLite databases or real private messages.
Local SQLite now retains unencrypted message history as well as private keys.
See [the threat model](docs/threat-model.md) for implemented boundaries and gaps.

The Milestones 0–10 MVP has automated acceptance coverage for the two-device flow,
ciphertext storage and restart recovery. Passing it does not constitute a security
audit or change the prototype's deployment status. See the
[acceptance evidence and limits](docs/mvp-acceptance.md).

The Milestone 11 terminal client does not change production readiness or key
storage. Its offline queue and visible history retain the same local plaintext
storage exposure. Unread indicators are local UI state, not secure read receipts.


Milestone 12 supports independent device leaves for the same logical user. A
compromised device exposes its own local state and can impersonate that device;
collapsing user labels does not make devices share keys. Enrollment is still trusted
to the operator/directory: manual verification, key-change detection, transparency
and revocation remain unimplemented. A new device receives a Welcome for its join
epoch, not prior history. Earlier framed traffic is skipped without authentication
because the new device has no historical keys. Creator Commits are authenticated and
merged atomically with local progress. Offline ciphertext from before a membership
change may be undecryptable afterward. Transport suppression/reordering and group
permission wildcards remain availability/metadata limitations. No revocation or
historical erasure guarantee is added. See [multi-device boundaries](docs/multi-device.md).
