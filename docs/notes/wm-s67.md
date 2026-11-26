# wm-s67: snapshots and alerts (ADR-0073 slices 6 and 7)

## Changelog lines

- Windows module state is kept as snapshots: the typed result of a module's read action, per computer, with its age. A stale one is returned at once and refreshed; the server also reads `defender.status` hourly on every computer where Defender's module is on; snapshots are kept 7 days (15 minutes for a sensitive one).
- Monitoring gains Windows module alert kinds from a registry. Defender's first four: real-time protection off (with a grace period), Tamper Protection off, signatures out of date, no recent scan. They are judged from the snapshot, skip organizations outside the development scope and modules that are off, and resolve on "module off", "role removed" or "not applicable".
- Default policies of a module are created for an organization when a Defender computer first appears or the module is turned on, once, marked "default": they can be turned on or off, not edited or deleted. The two age rules start off.

## Implementation-status rows

- Snapshots (table, freshness, on-demand and scheduled refresh, retention, role-removal clearing): built and tested on real PostgreSQL; no HTTP endpoint yet (slice 8's UI frame will call `modsnap.Service.Get` and `Refresh`).
- Module alert registry, default policies, grace conditions, best match, module-off and role-removal resolution: built and tested on real PostgreSQL with `defender.status` snapshots written as the result path writes them.
- Not built: Defender's event-driven kinds (threat, remediation failed, update failed, config changed, exclusion changed, tamper blocked, unhealthy, out of support); refreshing a default policy on upgrade where the user has not changed it (ADR-0073 section 6).

## Privacy notes

- A snapshot holds the typed result of a read action as stored for the run; `defender.status` carries versions and switches, no personal data. A sensitive action's snapshot is deleted after 15 minutes and is served only with its sensitive permission.

## For later slices

- A module registers `monitoring.RegisterModuleAlerts(...)` in `app.go` (`defender.AlertKinds()` is the model) and gives an action `Freshness` (snapshot) and optionally `Schedule` (at least hourly, no required parameters).
- `windows_module_snapshots` and `windows_module_conditions` are "follows the device" in `TestMoveDispositionOfEveryTable` (no organization or site column).
- Migrations: 00056 (snapshots), 00057 (kind checks become a shape check; `module`, `default_key` on `alert_policies`; three new resolutions; `windows_module_conditions`).
