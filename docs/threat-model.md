# Threat model

EpochGrid aims to protect future message content from network observers, NATS
servers, JetStream compromise and infrastructure administrators. It aims to inherit
MLS forward secrecy and post-compromise security when correctly implemented,
including exclusion of removed members from future epochs. Group messaging and
removal are not implemented in Milestones 0–3, so these are design goals, not
properties demonstrated by the current foundation.

Implemented boundaries: independent NATS and MLS keys; NKey challenge-response
network authentication; signed public registration; OpenMLS KeyPackage validation;
operator-controlled enrollment; isolated client reply permissions; public-only
identity KV; local SQLite persistence. The service is trusted for enrollment and
metadata, but will remain untrusted for message confidentiality. A signature
proves possession, not human identity. The operator is responsible for enrollment.

Not hidden: subjects, message sizes/timing, connection metadata, public device
identities and KeyPackages, eventual presence, or traffic analysis. Public
registration exposes usernames. TLS is not enabled in the local Compose setup:
it binds loopback and must not be used remotely. NKeys do not encrypt transport.
TLS and trust configuration must precede deployment beyond this development scope.

Endpoint compromise can disclose all local secrets. SQLite and its journals are
unencrypted. Unix directories/files use 0700/0600; Windows ACL integration is not
implemented. Use a dedicated private local directory on a trusted filesystem.
Future key-management adapters should integrate Linux Secret Service, macOS
Keychain/Secure Enclave, Windows CNG/TPM and mobile secure keystores.

Open issues: availability and request flooding, identity rotation/revocation,
KeyPackage expiry/replenishment, malicious directory substitution/key transparency,
TLS provisioning, group authorization, atomic group/outbox delivery and crash
recovery. Local initialization writes MLS keys before its identity row: a crash
can leave unused MLS records; it does not publish a partial registration.
No distributed delivery or group-state crash-safety claims are made yet.
