# ADR-0029: Reports

* Status: Accepted (2026-11-16).
* Builds on: ADR-0018 (inventory and telemetry), ADR-0019 (monitoring and
  alerts), ADR-0028 (software deployment).

## Context
MSPs are asked the same questions over and over, by clients, auditors and
their own managers: what hardware does this client have, which computers
still run an old OpenSSL, which ones have not checked in for a month, how
many critical alerts were there last quarter. EasyRMM already holds the
answers (inventory, installed software, latest measurements, alert
history), but only one device or one alert at a time. The answers are
needed in a spreadsheet as often as on screen. Every role already holds
`report.view`, with nothing behind it.

## Decision
* **Four built-in reports**, each a table with fixed columns:
  * **Device inventory**: organization, site, device and host name,
    platform, operating system, online, last seen, agent version,
    manufacturer, model, serial number, processor, cores, memory, fixed
    disk size, reachable IP addresses (no loopback or link-local), and
    when the inventory was reported.
  * **Installed software**: one row per package or program per device,
    with its version, publisher and architecture.
  * **Device health**: online, last seen, processor and memory use, the
    fullest filesystem with its use and free space, uptime, and when it
    was measured.
  * **Alert history**: alerts opened in a period (30 days by default, up
    to a year), with kind, severity, status, the reading that raised it,
    how long it was open, who acknowledged it, and how it ended.
* **Filters**: organization and site for all; platform for devices,
  software and health; a name search for devices (name or host name) and
  software (package name); for health, *not seen for* N days and *fullest
  disk* at least N% full; for alerts, the period and severity.
* **Who sees what.** A report runs in the caller's data scope, like every
  read (row-level security), and keeps the rows of sites where the caller
  holds `report.view` and the permission for what the report lists:
  `device.view` (inventory, health), `software.view`, `alert.view`.
* **The console** shows the first 1,000 rows; the CSV has every row, up
  to 100,000, past which the report says it was cut short. Reports are
  computed when asked, from live data; nothing is precomputed or stored.
* **CSV** is UTF-8 with a byte order mark, a header row, and times in UTC
  (`2026-11-16 13:53:07`, the header says so); values are in the unit the
  header names (GiB, %, days, hours). A text cell starting with `=`, `+`,
  `-`, `@`, a tab or a carriage return gets a leading apostrophe, so that
  a device, program or alert name chosen by whoever controls a computer
  cannot run as a formula in the spreadsheet of whoever opens the report.
* **Exports are audited** (`report.export`), with the report, its filters
  and the number of rows, before the file is sent: data leaves EasyRMM.
  Viewing in the console is not audited, like every other read. The entry
  is written once for each organization the rows came from, under that
  organization (and its site, when the rows share one), so its
  administrators see it. The organization and site in the request are
  recorded only as filters, never as where the entry is filed: otherwise
  a technician could file an entry in another organization's log, or
  file their own export where their organization's administrators do not
  look (Phase 9 security review). An export with no rows is recorded at
  platform level.
* **API**: `GET /api/v1/reports/{name}` (JSON: columns, rows, total,
  truncated) and `GET /api/v1/reports/{name}/csv`, with the filters as
  query parameters. **Console**: **Reports** in the main menu, a tab per
  report the role can read, and **Download CSV** for the report as
  filtered.

## Consequences
* No scheduled or e-mailed reports, no PDF, no charts over time, and no
  custom reports; they can come later on top of the same queries.
* Reports read live tables. On a large fleet the software report without
  a search reads every installed package of the sites in scope; it stops
  at 100,000 rows.
* Patch compliance is not among them: it belongs to the EasyPatch
  integration (Phase 8).
