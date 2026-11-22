# ADR-0019: Monitoring and alerts

* Status: Accepted (2026-11-16). Amended by
  [ADR-0065](0065-hardware-health.md): an alert kind, `disk_health`, with a
  check per policy (`check_name`); alerts with a subject, one per disk, so
  the unique key of an active alert is its policy, device and subject; and
  the resolution `subject_gone`.

## Context
ADR-0018 stores every device's measurements once a minute. Technicians need
to be told when a device goes offline or runs short of processor, memory or
disk, without watching charts, and need a list of what is wrong now across
the devices they support. RBAC has had `monitoring.view` and
`monitoring.manage` (policies) and `alert.view` and `alert.manage`
(acknowledge, resolve) since phase 2.

## Decision

### Alert policies
* A policy watches one condition on the devices it covers and has a name,
  a severity (warning or critical) and an on/off switch. It belongs to one
  level, as scripts do (ADR-0017): **shared** (every device, written by
  Super Administrators), an **organization** (its devices) or a **site**.
  Several policies may cover a device; each raises its own alert.
* Conditions:
  * **Offline**: the device has not checked in for N minutes (3 to 1,440).
    A device counts as checking in while its EasyRMM agent or MeshAgent is
    connected (the console's online state).
  * **Processor**, **Memory**, **Disk** (the fullest filesystem): every
    measurement in the last N minutes (1 to 1,440) is at or above a
    percentage (1 to 100), with at least half the expected measurements
    present, so a device that just came back does not trip on two samples.
    An open alert resolves once every measurement of the last 5 minutes
    (or of N, when shorter) is below the percentage. A device with no
    measurements in that time keeps its alert as it is: whether it is
    offline is the Offline policy's business.
* New installations start with four shared policies, all on: Offline for 15
  minutes (critical), Processor 95% for 15 minutes (warning), Memory 95%
  for 15 minutes (warning) and Disk 90% for 5 minutes (critical).
  Administrators change or remove them like any other.

### Alerts
* An alert is one policy's condition on one device: open, acknowledged or
  resolved. A policy has at most one unresolved alert per device (a partial
  unique index). The alert keeps a copy of the policy's name, condition and
  severity, so it reads the same after the policy changes or is deleted,
  and the value that raised it and the latest one.
* The server evaluates every enabled policy once a minute in one
  transaction, holding a PostgreSQL advisory lock so two servers on one
  database never evaluate at once. It opens alerts for devices that meet a
  condition, updates the value of open ones, and resolves alerts whose
  condition cleared ("cleared"), whose device the policy no longer covers
  (a device moved, or the policy's level changed) and whose policy was
  turned off or deleted.
* People with `alert.manage` acknowledge an alert (it stays listed and
  resolves when its condition clears) or resolve it. An alert resolved by
  hand while its condition still holds opens again at the next evaluation;
  acknowledging is how to quiet one. Acknowledging and resolving are
  audited; alerts opened and resolved by the server are not, the alert
  itself being the record.
* Resolved alerts are removed after `EASYRMM_ALERT_RETENTION` (default 90
  days).

### Access
* Policies are read with `monitoring.view` and written with
  `monitoring.manage`, at their level, enforced by row-level security as
  for scripts. Alerts are read through their device's row-level security
  with `alert.view` and changed with `alert.manage` on the device's site.

### Notifications
* E-mail and webhook notifications are a separate decision, still to be
  written (see [the feature plan](../feature-plan.md), feature 7); this
  one makes alerts visible in the console only.

## Consequences
* An **Alerts** page lists open alerts across the devices a person
  supports, and the policies; the device page shows the device's alerts;
  the dashboard counts open alerts.
* Alerts are evaluated from the samples kept for charts, so a condition
  longer than `EASYRMM_METRICS_RETENTION` cannot be evaluated; policies
  are limited to 24 hours, and the retention is at least a day.
