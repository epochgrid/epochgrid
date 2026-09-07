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
See [the threat model](docs/threat-model.md) for implemented boundaries and gaps.
