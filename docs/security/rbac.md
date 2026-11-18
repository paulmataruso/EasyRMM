# Roles and permissions

Source of truth: `server/internal/rbac/rbac.go`. Tests in `rbac_test.go`
enforce that higher roles are strict supersets of lower ones.

## Scopes

* **Platform** — Super Administrator only.
* **Organization** — every site in one organization.
* **Site** — one site. Site-scoped roles can read the parent organization's
  record but never manage the organization or its users.

## Permissions

| Permission | Read-Only | Technician | Site Admin | Org Admin | Super Admin |
|---|:-:|:-:|:-:|:-:|:-:|
| `org.view`, `site.view`, `device.view`, `script.view`, `job.view`, `software.view`, `patch.view`, `monitoring.view`, `alert.view`, `report.view` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `device.edit`, `device.remote_desktop`, `device.terminal`, `device.files` | | ✓ | ✓ | ✓ | ✓ |
| `script.run`, `job.manage`, `software.manage`, `patch.manage`, `alert.manage` | | ✓ | ✓ | ✓ | ✓ |
| `site.manage`, `device.retire`, `script.manage`, `monitoring.manage`, `enrollment.manage`, `user.view`, `audit.view` | | | ✓ | ✓ | ✓ |
| `org.manage`, `user.manage` | | | | ✓ | ✓ |
| `org.create`, `settings.manage` | | | | | ✓ |

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
