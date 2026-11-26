# Roles and permissions

Source of truth: `server/internal/rbac/rbac.go`. Tests in `rbac_test.go`
enforce that higher roles are strict supersets of lower ones.

## Scopes

* **Platform** — Super Administrator only.
* **Organization** — every site in one organization.
* **Site** — one site. Site-scoped roles can read the parent organization's
  record but never manage the organization, its users or its patching
  rules (`patch.configure`).

## Permissions

| Permission | Read-Only | Technician | Site Admin | Org Admin | Super Admin |
|---|:-:|:-:|:-:|:-:|:-:|
| `org.view`, `site.view`, `device.view`, `script.view`, `job.view`, `software.view`, `patch.view`, `monitoring.view`, `alert.view`, `report.view`, `doc.view` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `device.edit`, `device.remote_desktop`, `device.rdp_credentials.save`, `device.terminal`, `device.files`, `doc.manage`, `log.view`, `eventlog.view` | | ✓ | ✓ | ✓ | ✓ |
| `script.run`, `job.manage`, `job.view_sensitive`, `software.manage`, `patch.manage`, `alert.manage` | | ✓ | ✓ | ✓ | ✓ |
| `site.manage`, `device.retire`, `device.harden`, `script.manage`, `monitoring.manage`, `enrollment.manage`, `user.view`, `audit.view` | | | ✓ | ✓ | ✓ |
| `org.manage`, `user.manage`, `patch.configure`, `log.view_sensitive` | | | | ✓ | ✓ |
| `org.create`, `settings.manage` | | | | | ✓ |
| `defender.view`, `ad.view`, `ad.helpdesk`, `dhcp.view`, `print.view`, `backup.view`, `defender.manage`, `print.manage`, `backup.manage` | | ✓ | ✓ | ✓ | ✓ |
| `ca.view`, `dns.view`, `shares.view`, `ad.view_sensitive`, `dns.manage`, `dhcp.manage`, `shares.manage` | | | ✓ | ✓ | ✓ |
| `ca.manage`, `ad.manage`, `ad.reset_password` | | | | ✓ | ✓ |
| `quickassist.view`, `quickassist.link.create`, `quickassist.session` (Quick Assist, [ADR-0080](../architecture/adr/0080-quick-assist.md)) | | ✓ | ✓ | ✓ | ✓ |
| `quickassist.link.permanent`, `quickassist.session.takeover`, `quickassist.install` | | | | ✓ | ✓ |
| `notification.manage` (an organization's notification channels: change, test, reveal; the platform's own are a super administrator's; [ADR-0053](../architecture/adr/0053-one-notification-sender.md)) | | | | ✓ | ✓ |

`job.view_sensitive` opens what a run printed and a job's argument values,
which can hold secrets; `job.view` shows the jobs and runs without them.
Read-Only does not hold it: it is the natural role for a customer's own
staff, and a script's output is where a technician's recovery password or
token ends up. Every read is recorded in the audit log
([Scripts and jobs](../operations/scripts-and-jobs.md#who-sees-output-and-arguments),
[ADR-0063](../architecture/adr/0063-who-sees-job-output-and-arguments.md)).

`doc.view` and `doc.manage` read and change the customer record: an
organization's contact information and hours, sites' addresses and hours,
contacts and places. They apply where the role is, and a site-scoped role
sees its sites' contacts and places, not the organization's own contacts
([The customer record](../operations/customer-record.md#who-can-see-and-change-what),
[ADR-0066](../architecture/adr/0066-customer-documentation-and-assets.md)).

`eventlog.view` opens the Event logs tab of a Windows device: its channels, and a query over them with each event's fields, message and XML, for every
channel but Security and without sensitive fields; reading a result needs `job.view_sensitive` as well, and only the person who asked reads it
([ADR-0068](../architecture/adr/0068-remote-event-viewer.md)). `log.view_sensitive` (ADR-0060's) opens the Security log and the sensitive fields
(command lines, scripts, service and task definitions) in that tab: it is held from Organization Administrator up and **only from an
organization-wide grant**, never from a site's. A query that asked for sensitive data is read again only by someone who still holds it.

`log.view` reads a device's agent logs: the records of the EasyRMM agent,
the EasyPatch agent and MeshAgent. It is held from Technician up, not by
Read-Only, as logs can hold user names, paths and host names. Turning
verbose logging on or off for a device or a group needs `device.edit`
([Agent logs](../operations/agent-logs.md),
[ADR-0069](../architecture/adr/0069-recovery-agent-logs-and-one-device-tree.md)).

The Windows management modules ([ADR-0073](../architecture/adr/0073-windows-management-modules.md))
each have a `.view` and a `.manage` permission (Active Directory also has
`ad.reset_password`, `ad.view_sensitive` and `ad.helpdesk`, which lets a Technician unlock, enable, disable and reset the password of an
ordinary user, never a protected or service account). Read-Only holds none of them:
module state (users, shares, printers, certificates, backup paths) is more
than a status light. Active Directory, certificate authority, DNS and DHCP
power reaches the whole domain, not one site, so `ad.manage` and
`ca.manage` start at Organization Administrator.

## Granting roles

A user may grant or revoke an assignment only if:

* they are a Super Administrator, or
* they hold `user.manage` over the assignment's scope **and** the role's rank
  is at or below their own best role in that scope.

Only Super Administrators grant Super Administrator.

## What one organization learns about others

Organizations are separated by row-level security under every query, and
by a permission check against each row's organization and site above it.
Two platform-wide facts still cross the boundary, and are kept to a
minimum:

* **Organization names are unique on the server**, so that they are never
  ambiguous in a Super Administrator's lists. Renaming an organization
  therefore needs `org.manage` platform-wide (a Super Administrator).
  Otherwise an Organization Administrator could try names until one was
  "already taken" and learn another customer's name. Organization
  Administrators still edit their organization's notes, sites and users.
* **Accounts are platform-wide**, so that one person can hold roles in
  several organizations. Inviting an email address that already has an
  account answers "An account with this email address already exists",
  which tells an Organization Administrator that the address is in use on
  this server, though not where. No answer could hide this, because the
  outcome differs either way: an account is created, or it is not. Closing
  it would take invitations that an existing account accepts first. If
  customers' administrators must not learn whether an address has an
  account, keep `user.manage` with your own staff: give customers Site
  Administrator or lower, and invite their users yourself.

Exports name the organizations whose data they contain. The `report.export`
audit entry is written once for each organization the export's rows come
from, under that organization (and its site, when all the rows share one).
Its administrators see the entry, and an export can be recorded only where
its data came from. An export with no rows is recorded at platform level.
