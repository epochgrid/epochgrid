# Alpha technical debt

## TD-001 — Live typing indicators (deferred until after alpha milestones)

Local TUI use does not reliably display another participant's typing activity.
The typing smoke assertion also failed intermittently in CI. Adjusting the probe
cadence did not establish that the user-facing feature works reliably. The exact
runtime cause remains unresolved; synchronization delays and dropped transient
activity are candidates, not a confirmed diagnosis.

By explicit project decision, live typing start/stop assertions are disabled by
default in all TUI smoke modes. Each run prints a skip notice. Messaging, receipts,
attachments, service participation and the other TUI assertions remain enabled.
Encrypted ephemeral transport, tamper/replay protection, non-durability, expiry and
probe unit tests remain enabled. Runtime behavior is unchanged; users should not
rely on typing indicators. A green CI result does not certify this feature.

For investigation only, opt in with a bounded run:

```bash
python3 scripts/dev/run-bounded.py 180 python3 scripts/dev/tui-smoke.py --check-typing
```

After the alpha release milestones, either fix and validate sustained real-user
Alice/Bob typing under synchronization/reconnect load, then restore default live
coverage, or remove the typing UI feature. Do not close this debt solely because
a timing-sensitive smoke test passes once.
