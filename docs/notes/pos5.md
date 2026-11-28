# pos5: Posture P5, log collection control (ADR-0082)

## Changelog lines

- Security posture gains a "Log collection" control (weight 2). It reads when the computer last had collected log blocks accepted: within 24 hours is in place, 1 to 7 days is partly ("set up but not arriving"), over 7 days or never is not in place. A computer that has never sent logs therefore does not meet its security policy until its collector sends.

## Implementation-status rows

- Posture log collection control: built; Go integration test with real PostgreSQL (`TestLogCollectionControl`). Posture coverage floor raised to 77.
- Not built: a separate "configured" signal. The server has no setting saying a device should collect logs, so "configured" is read as "has sent before"; "not configured" and "never arrived" are the same state. Per-source checks (is the security source sending?) are not built: the main database does not see sources.
- Not built: an agentapi handler test for the `RecordLogs` call (needs a ready log store); the call is covered through `Service.RecordLogs`.
- Existing posture tests' percentages changed because every covered computer now has the extra control; the test fixture seeds fresh log receipt.

## Integrator notes

- Migration `90621_posture_log_collection.sql` (main database): table `posture_log_collection` (device_id, first_received_at, last_received_at), row-level security like `posture_patching`. The log store is a separate database, so posture cannot join it; the agentapi `collectedLogs` handler calls `posture.Service.RecordLogs` after a batch with at least one non-refused block (`WithLogPosture`, wired in `app.go`).
- Rollout effect: on deploy every covered computer without a row drops by the control's weight until its first batch. Orgs held back by dev-scope never receive logs and will show not in place.
