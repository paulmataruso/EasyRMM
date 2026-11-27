# ADR-0085 Alert suppressions

## Status

Accepted

## Context

Some devices do not use every monitored feature. A machine without
Defender, or one known to be in maintenance, generates alerts the
administrator has no intention of acting on. These alerts add noise to
the console and to notification channels. The administrator needs a way
to permanently suppress an alert kind on a device.

## Decision

A new table `alert_suppressions` records (device, kind, subject) triples
that the monitoring system skips. When a user suppresses an alert:

1. The suppression is created (or the reason updated if one already
   exists for the same triple).
2. The alert is resolved with resolution `suppressed`.
3. All four evaluation paths — `loadFacts` (offline, cpu, memory, disk),
   `loadRemoteFacts` (remote\_down, agent\_silent), disk health and
   module alerts — LEFT JOIN on suppressions and exclude suppressed
   pairs.
4. `reconcileSuppressed` runs at the start of each evaluation and
   resolves any open alert that has a matching suppression, as a
   belt-and-suspenders guard against races.

Suppressions are per-device and per-kind. For disk health, suppressing
with an empty subject suppresses all disks on the device; a non-empty
subject suppresses one disk.

Removing a suppression does not reopen an alert. The next evaluation
cycle may open a new one if the condition still holds.

### API

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/v1/alerts/{id}/suppress` | Suppress the alert's device–kind–subject |
| GET | `/api/v1/alerts/suppressions?deviceId=` | List suppressions |
| DELETE | `/api/v1/alerts/suppressions/{id}` | Remove a suppression |

### Permissions

Suppressions follow their device: whoever can manage the device's alerts
can suppress and unsuppress. The `alert.manage` RBAC permission governs
all three operations.

### Audit

Suppress and unsuppress are audited as `alert.suppress` and
`alert.unsuppress`.

## Consequences

- Defenders, remote-access and agent-silent alerts on devices that do
  not use the feature can be silenced permanently.
- The console shows which devices have suppressions and allows removing
  them.
- No alerts are lost: the resolved alert stays in the history with
  resolution `suppressed`, and the suppression record is a first-class
  entity in the console.
