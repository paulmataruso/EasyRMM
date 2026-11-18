# Reports

**Reports** in the main menu answers fleet-wide questions from what EasyRMM
already knows: inventory, installed software, health measurements and
alerts. Each report is a table to read in the console or download as CSV
for a spreadsheet. The design is in
[ADR-0029](../architecture/adr/0029-reports.md).

| Report | One row per | Answers |
|---|---|---|
| Device inventory | Device | What hardware and operating systems a client has; serial numbers for warranty checks; which agents are old |
| Installed software | Package or program on a device | Which devices have a program, and which version (search for its name) |
| Device health | Device | Which devices have not checked in for a while, or are running out of disk space |
| Alert history | Alert | What went wrong over a period, how long it lasted, and how it ended |

## Filters

Every report narrows to an **organization** and a **site**. Device
inventory, installed software and device health narrow to a **platform**
(Windows or Linux).

* **Device inventory**: a device's name or host name contains the search.
* **Installed software**: the package or program name contains the search
  (`openssl`, `chrome`).
* **Device health**: **Not seen for** (a day, a week, 30 or 90 days or
  more; devices never seen count) and **Fullest disk** (80%, 90% or 95%
  full or more).
* **Alert history**: **Opened in** (the last 7, 30 or 90 days, or the last
  year) and **Severity**.

The filters are part of the page's address, so a report can be bookmarked
or shared with someone who can see the same devices.

## Who can see what

Every built-in role holds `report.view`. A report lists only devices in
organizations and sites you can see, and needs the permission for what it
lists there: `device.view` for inventory and health, `software.view` for
software, `alert.view` for alerts.

## Downloading

**Download CSV** downloads the report as filtered, with every row (the
console shows the first 1,000). A report stops at 100,000 rows and says
so; narrow it with the filters.

* UTF-8 with a byte order mark, so Excel reads accented names correctly.
* Times are in UTC, as `2026-11-16 13:53:07`; the header says *(UTC)*.
* Numbers are in the unit the header names: GiB, %, days, hours.
* A cell that would start with `=`, `+`, `-` or `@` begins with an
  apostrophe, so that a name chosen on a managed computer cannot run as a
  formula when the file is opened.

Each download is recorded in the audit log as *Downloaded report*, with the
report, its filters and the number of rows.

The console reads them from `GET /api/v1/reports/{devices|software|health|alerts}`
(JSON) and `…/csv`, with `organizationId`, `siteId`, `platform`, `q`,
`offlineDays`, `diskPercent`, `days` and `severity` as query parameters.
Like the rest of the API they need a signed-in session; EasyRMM has no API
keys yet.
