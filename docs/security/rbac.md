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
