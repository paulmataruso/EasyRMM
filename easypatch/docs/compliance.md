# Compliance

EasyPatch assigns every active endpoint a **compliance status**, computed from the endpoint's
last successful update scan and its restart state. The rules live in one place
(`backend/Core/Domain/ComplianceCalculator.cs`). They are unit tested, and the dashboard,
endpoint lists, reports and daily snapshots all use them.

## Statuses

The server checks the rules in this order and the first match wins:

| # | Status | Condition |
|---|---|---|
| 1 | `NeverScanned` | The agent has not yet reported a successful scan |
| 2 | `ScanStale` | The last successful scan is older than the policy's *scan considered stale after* (default 48 hours) |
| 3 | `FailedUpdates` | At least one **required** update is in state `Failed` |
| 4 | `MissingUpdates` | At least one **required** update is `Missing`, `Failed` or `PendingVerification` |
| 5 | `RebootRequired` | Windows reports a pending restart, or an update is installed and waiting for a restart (`PendingReboot`). The endpoint page lists the updates waiting for it and, for Windows agents 1.5.3 and later, the servicing packages and files Windows has queued |
| 6 | `Compliant` | None of the above |

The order is deliberate:

* Data that is old or missing is never reported as compliant.
* A failure is reported ahead of a merely missing update.
* An endpoint with every required update installed, but still waiting for a restart, is
  `RebootRequired`, not `Compliant`. An update is not secured until the restart completes.

**Being offline does not change compliance by itself.** Offline status is tracked separately.
An endpoint that stays offline drifts to `ScanStale` once its last scan ages past the threshold.
The worker re-checks staleness every minute.

## Required updates

An update is **required** for an endpoint when its effective policy would install it
automatically, meaning all of the following:

* its category is in the policy's install categories. The default is everything except drivers
  and feature updates: Security, Critical, Cumulative, Definition, Servicing Stack, .NET and Other;
* it is not optional ("browse-only" in Windows Update), unless the policy includes optional
  updates (off by default);
* it is not excluded by the policy (by KB number or by update);
* its **rollout delay** has ended (see below).

Linux package upgrades are classified as Security or Other, so with the default categories every
available upgrade of an installed package is required. Remove Other from the policy's categories
to require only security upgrades.

Application updates (winget, category **Application**) are not selected by category: an
application update is required when application updates are on in the policy and the application
is on the approved list. The *Other updates* rollout delay applies. See
[application-updates.md](application-updates.md).

Updates that are not required are still shown and can still be installed, but they never affect
compliance. When a policy changes, or tags are added to or removed from an endpoint, the required
flags and statuses of every affected endpoint are recalculated immediately.

### Rollout delay

A policy can delay updates so that a pilot group installs them first. There are two settings,
both 0 (no delay) by default:

* **Security updates** (0 to 90 days): updates with Microsoft's "Security Updates"
  classification, which includes the monthly cumulative updates, and Linux security upgrades.
* **Other updates** (0 to 365 days): every other allowed update.

Definition (antivirus signature) updates are never delayed.

The delay counts from when EasyPatch **first saw the update on any endpoint**, not from when a
particular endpoint reported it. When a new update replaces one that was still outstanding on
the endpoint (a Windows update that supersedes it, or a newer version of the same Linux package),
the new one keeps the older update's start date. A monthly cumulative update that is replaced
each month therefore does not restart the delay forever.

While an update is inside its delay it is **deferred**: it is not required, it does not affect
compliance, and scheduled installs skip it. The console shows it as "deferred until" a date and
counts it separately. The worker re-evaluates deferred updates every 10 minutes, so an update
becomes required (and a compliance problem) shortly after its delay ends. Installing an update
manually ignores the delay; the install preview warns when that happens.

A long delay keeps endpoints compliant while they lack released fixes. The policy editor warns
about delays longer than 30 days.

#### Setting up a pilot ring

1. Set the delay everyone else should wait in the global policy (**Settings → Global policy**)
   or in each organization's policy, for example 7 days for security updates and 14 for others.
2. Create a tag such as **Pilot** (**Settings → Tags**, super administrators) and give it a
   policy with both delays at 0. Give it a higher priority than other tags with delays.
3. Put the tag where the pilot computers are:
   * on an **organization** (its page, **Add tags**) for a whole customer;
   * on a **site** (the organization's **Sites** tab) for one office;
   * on single **endpoints** (endpoint page, or several at once from the endpoint list).

An endpoint has its own tags plus the tags of its site and organization, and a tag policy
applies however the endpoint got the tag. Tag policies sit between the site policy and the
endpoint's own policy, so the pilot tag's 0-day delay wins over the organization's or site's
delay. Inherited tags are shown with a dashed outline on the endpoint, and the endpoint list's
tag filter includes them. Adding or removing a tag recalculates the compliance of the affected
endpoints at once.

## Vulnerabilities and known-exploited updates

EasyPatch shows which CVEs each outstanding update fixes, and flags updates that fix a
vulnerability in the CISA [Known Exploited Vulnerabilities (KEV) catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog),
which lists vulnerabilities attackers are exploiting in the wild.

| Endpoints | Where the CVEs come from |
|---|---|
| Windows | Microsoft Security Response Center (MSRC) security update data for the last 12 months. CVEs are matched by the update's KB numbers. The monthly security cumulative update also gets every CVE that MSRC fixed in a later revision of the computer's build (from the build number in its inventory, for example 26100.2314), so a computer several months behind shows everything the cumulative update closes. Feature updates (new Windows versions) show no CVEs: Windows Update lists them with the KB of the new version's cumulative update, and the current version's cumulative updates fix the same vulnerabilities. A version that no longer gets updates is flagged by its [support status](#operating-system-support-status) instead. |
| Debian 12 and 13 | The Debian Security Tracker. A package upgrade gets the CVEs fixed in its source package after the installed version, up to and including the offered version. Needs agent 1.4.0 or newer (it reports the source package). |
| Rocky Linux, AlmaLinux, RHEL, Fedora | The dnf advisories on the computer, read by the agent (agent 1.4.0 or newer): `dnf updateinfo` on dnf 4, `dnf advisory info` on dnf 5. Only CVE references are kept. |
| Ubuntu | Not yet. Ubuntu updates show no CVEs; they are installed and counted as usual. |

The worker downloads the data (see [Vulnerability data](security.md#vulnerability-data)): the KEV
catalog every 6 hours, MSRC data daily, and the Debian Security Tracker daily while Debian
endpoints are managed (sooner, at most every 6 hours, when Debian endpoints report packages it
has not covered yet). New data is applied to every active endpoint at once; scans use the data
already downloaded. *Settings → Server → Vulnerability data* shows the state of each download and
can turn them off. When turned off, the data already downloaded is kept but no longer refreshed.

What a known-exploited update changes:

* It is listed first on *Updates* and in an endpoint's update list, with a **Known exploited**
  badge and the remediation due date CISA sets for US federal agencies. The update page lists
  its CVEs with links to NVD (and MSRC for Windows).
* It **skips the rollout delay** by default, so it is required as soon as it is seen. The policy
  setting *Rollout delay → Known-exploited vulnerabilities* can make it wait like other updates.
  Only the delay is skipped: the update must still be in an allowed category, not optional and
  not excluded.
* Endpoints missing one (required, or still inside a delay) are counted on the dashboard
  (*Known-exploited exposure*), can be filtered on *Endpoints*, and raise the
  *Known-exploited vulnerability unpatched* alert ([alerts.md](alerts.md)).

Compliance itself is unchanged: an endpoint is compliant when no required update is missing,
whatever the CVEs. Limits: at most 200 CVEs are kept per update; titles, severity and CVSS scores
are available for Microsoft CVEs only; Microsoft's own "Exploited: Yes" is shown on the update
page but only the CISA catalog marks an update known-exploited.

## Update states and verification

Each endpoint/update pair has a state. The full model is in
[architecture.md](architecture.md#update-state-model-two-layers). The parts that matter for
compliance:

* **Only a scan marks an update `Installed`.** A successful install result from the agent moves
  the update to `PendingVerification`, or to `PendingReboot` when Windows asks for a restart.
  These states still count as not installed.
* If the next scan still offers a `PendingVerification` update (the same revision), it becomes
  **`Reoffered`** (*Offered again* in the console). Windows confirmed the installation, but
  Windows Update keeps offering it: a Windows Update detection problem, often seen with the
  Windows Security platform update KB5007651. A `Reoffered` update:
  * is never shown as installed and is not counted as failed or missing for compliance (it still
    counts as an open known-exploited vulnerability when its CVEs are known-exploited);
  * is not installed again by *Install all missing updates* or scheduled installations, so it
    does not repeat at every maintenance window. Select it on the endpoint's **Updates** tab to
    install it anyway;
  * becomes `Missing` again when Windows offers a new revision of it, and `Installed` when a
    scan lists it as installed.

  Updates that need a restart (such as cumulative updates) go to `PendingReboot` instead, so they
  never become `Reoffered`.
* After an install job, the agent scans again. If a restart is needed, it scans again after the
  computer restarts. Installing updates never restarts a computer: a user, an administrator
  (with **Restart…** on an endpoint, or **Restart all that need it** on an organization or
  site) or a restart schedule in policy restarts it.
* `Superseded`, `NotApplicable`, `Excluded` and `Reoffered` updates never count.

## Operating system support status

Whether the operating system itself is still serviced is reported **separately**, as the
endpoint's *OS support status*. It does not change the compliance status:

| Status | Meaning |
|---|---|
| `Supported` | Within the end-of-servicing date for this product, build and edition group |
| `ExtendedSecurityUpdates` | Past end of servicing, but covered by an ESU program that has not ended. The endpoint must have an ESU license detected by the agent, or an administrator must mark it as enrolled |
| `Unsupported` | Past end of servicing and not covered by ESU |
| `Unknown` | The build or edition is not in the lifecycle table |

The dates come from an editable table under **Settings → OS lifecycle**. It is seeded with
Microsoft's published dates. Verify those against Microsoft's lifecycle pages and keep them up
to date. Windows 10 22H2 is **not** treated as supported after 2025-10-14 unless ESU applies.

A fully patched Windows 10 22H2 machine without ESU is therefore `Compliant`, because nothing
Windows Update offers is missing, and also `Unsupported`, because Windows Update no longer
offers it security fixes. Reports show both columns.

The table also has entries for Debian 11 to 13, Ubuntu 20.04 to 26.04 LTS, Red Hat Enterprise
Linux, Rocky Linux, AlmaLinux and Oracle Linux 8 to 10, CentOS Stream 9 and 10, and Fedora 44
and 45, matched by the distribution and its major release (Ubuntu by `YY.MM`). The Debian dates
include Debian LTS, which needs no subscription. The Fedora dates are the `SUPPORT_END` values
from each release's `/etc/os-release`; Fedora releases a new version every six months, so add
each new release under **Settings → OS lifecycle** (product `Fedora`, build number = release).
For Ubuntu, `ExtendedSecurityUpdates` means Ubuntu Pro (ESM) is enabled on the endpoint, as
reported by `pro status`. Other releases (Ubuntu interim releases such as 26.10, Fedora releases
that are not in the table) are `Unknown`.

## Percentages and snapshots

* **Compliance percentage** = compliant endpoints ÷ active endpoints × 100, rounded to one
  decimal place. Revoked and decommissioned endpoints are excluded. With no active endpoints the
  percentage is 0.
* **Daily snapshots.** Every 30 minutes the worker records, for each organization and the current
  UTC date, the number of endpoints in each status, the number offline, and the total number of
  missing required updates. The last write of the day stands as that day's figure. Snapshots
  drive the trend chart and are kept for the audit-log retention period (default 365 days).

## Reports

Under **Reports**, and through the API (see [api.md](api.md#dashboard-reports-audit-settings)):

* **Compliance**: one row per active endpoint: hostname, organization, site, operating system
  and build, compliance status, missing required, missing total and failed counts, restart
  pending, online, OS support status, last scan and last check-in. It can be filtered by
  organization, site, endpoint, OS and compliance status, and exported as CSV.
* **Compliance trend**: the daily snapshots for a date range (default: the last 30 days), summed
  over all permitted organizations or for one organization.
* **Installations**: one row per update in each EasyPatch install job: result, skip reason, error
  code and message, whether a restart was required, and who requested the job. It can be
  exported as CSV, up to 50,000 rows.

Tenant-restricted users only see the organizations they are assigned to, in reports and in CSV
exports.

## Monthly reports

**Reports → Monthly reports** produces a PDF per organization and calendar month, for example to
send to a customer. It contains:

* a title block with the organization, the month and, when set, a *Prepared by* line (**Settings
  → Server → Monthly reports**, for example your MSP's name);
* a summary: compliant endpoints now; compliance on the first and last daily snapshot of the
  month; updates installed during the month (counted only when a scan confirmed them); failed
  installation attempts during the month; required updates outstanding, endpoints missing a fix
  for a known-exploited vulnerability, endpoints waiting for a restart, endpoints with an
  unsupported operating system and endpoints not seen for more than 7 days (all now);
* the compliance trend of the month from the daily snapshots (at least two are needed);
* a table per site, the 15 most widely missing required updates (known-exploited first) and the
  operating systems in use;
* optionally, a table of every endpoint (up to 5,000) on separate pages.

Values marked *now* are taken when the report is generated: a report for an earlier month shows
the current state for those. Months use UTC dates, like the snapshots. The current month can be
generated as *month to date*; months more than 10 years back cannot.

**On demand.** Administrators (Admin and SuperAdmin) choose an organization and a month and select
**Generate PDF**. Read-only users can download existing reports. Any report can be emailed from the
list (**Email this report**); the recipients default to the organization's report recipients.

**Scheduled email.** Per organization, off by default: turn on *Email last month's report
automatically*, enter up to 20 recipients (plain addresses) and choose the day of the month (1 to
28, in the organization's time zone). From that day on, the worker generates the previous month's
report once and emails it with the PDF attached. Months that ended before the schedule was turned
on are not sent automatically. A deleted scheduled report is not generated or sent again.
Organizations east of UTC wait until the month has also ended in UTC. Archived and inactive
organizations get no scheduled reports. The schedule shows the next report and its date.

**Email delivery** uses the SMTP server under **Settings → Notifications**, and only with
STARTTLS or TLS: with *None* the console refuses to queue reports and the worker refuses to send
them. *Skip certificate validation* still encrypts the connection but does not verify the mail
server's identity ([security.md](security.md#notifications-and-webhooks)). Failed sends are retried (after 1 minute, doubling up to 1 hour) and given up after 24 hours;
the list shows *Queued*, *Retrying*, *Sent* or *Not sent* with the error. Reports larger than
15 MB are not emailed. The worker checks for due reports and queued emails every minute.

**Storage.** The PDFs are stored in the database and deleted after **Settings → Server → Data
retention → Monthly reports** (default 24 months). They are part of the database backup.

The PDFs use the embedded Liberation Sans font (SIL Open Font License), which covers Latin, Greek
and Cyrillic; characters of other scripts (for example Chinese or Japanese organization names)
appear as empty boxes. They are produced with PDFsharp/MigraDoc 6.2.4 (MIT license; later
versions are AGPL-licensed).
