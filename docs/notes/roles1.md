# roles1: the DNS Server and DHCP Server modules (ADR-0076, slices D1, D2, the zone half of D3, H1 to H3, most of H4, and H5)

## Changelog lines

- Windows servers with the DNS Server role show a DNS view in a new "Roles" tab: the server's state, its zones, and the records of a zone, which an administrator can add, change and remove. Records that let computers find domain controllers (`_msdcs`, the locator SRV records, DomainDnsZones and ForestDnsZones) and those zones are never changed or removed; the server refuses them before a job exists and the script refuses them again.
- Zones can be created, removed and set to none or secure dynamic updates; removing a zone, removing every record of a name and allowing unauthenticated updates ask for a typed confirmation and a second factor.
- Servers with the DHCP Server role show a DHCP view: scopes with how full they are, reservations, excluded ranges, options and (for Site Administrators and above) leases. A new scope starts inactive. Deactivating or removing a scope, and changing the gateway or DNS servers clients receive, ask for a typed confirmation and a second factor. Authorization in Active Directory is shown, with the command an administrator runs, and not offered as a button.
- New alerts, on by default: DNS service stopped (10 minutes, critical), DHCP scope nearly full (95 percent for an hour, warning), DHCP not authorized (warning) and DHCP service stopped (10 minutes, critical).

## Implementation-status rows

- DNS Server module: reads (status, zones, one zone, records), record add, change, remove and remove-all, zone create, remove and dynamic-update setting, service-stopped alert: built, unit and integration tested (real PostgreSQL), vitest, one e2e flow. **Scripts not run against a real DNS server.** Not built: forwarders, scavenging, transfers, replication scope, cache, reload, service restart, the zone-deleted and forwarders-changed alerts (event reader).
- DHCP Server module: reads (status, scopes, scope, exclusions, reservations, options, leases), scope create, change, activate, deactivate, remove, exclusions, reservations, options (two actions), lease remove and lease to reservation, and the three alerts: built and tested as above. **Scripts not run against a real DHCP server.** Not built: failover read and replicate, service restart.
- All 33 scripts pass the AST check and PSScriptAnalyzer with PowerShell 7.5 in Docker, and say `module_missing` there (the role-absent path, with the Windows runner step below). **Not run in Windows PowerShell 5.1.** The Windows runner step `TestScriptsOnWindows` (job "Agent tests on Windows") runs the role-absent path; real role tests (T1 and T2 of ADR-0076) are a later manual step and have not been run.
- Organization-level Overview cards (X3) not built; the device Roles tab has the cards.

## Privacy notes

- DHCP leases (hardware addresses, host names) are read on demand, held 15 minutes, never stored as a snapshot, and open only with `dhcp.manage`. Scope, reservation and option reads are snapshots/results of the usual retention; reservations hold hardware addresses and host names the administrator typed. Alerts name a scope ID, never a lease.
- DNS record data and names are organization data and are in the audit as parameters of a change.

## For the integrator

- Shared: `server/internal/winmod/rolekit` (parsers, refusal helpers, the service-stopped alert kind) and `server/internal/winmod/roles` (one list of every role's actions and alerts; app.go calls `roles.Actions()` and `roles.Register()`, so another role adds a line in `roles.go`, not in app.go). `rolekit/rolekittest` runs a role's scripts on the Windows runner. Web: `pages/devices/modules/winmod.ts` (run an action and follow it, `useWinmodRead`, `useWinmodChange`) and `roles/registry.ts` (one line per role view in the Roles tab).
- Framework edits: `winmod.Action.Guard` (winmod.go, called from validate.go) and `moduleTabs.tsx` (`views` for a tab with a view per module). The other role builder may add the same things; keep one.
- `scripts/ci/check-winmod-ast.ps1` taint is by variable name across a file, so helper functions use `$fx_` names (see the generator note below); no new AST rule was needed.
- Scripts were produced by a small generator; the committed `.ps1` files and `pins.go` are the source. Editing a script means updating its line in `pins.go` (a test fails otherwise).
- No migrations used (90241 to 90249 are free).

## ADR amendments

See "Amendments from building DNS and DHCP" in ADR-0076: no dynamic tier (separate actions, stricter for options 3 and 6), no framework confirmation at tier 2, page sizes, service state read from the snapshot, leases opened by `dhcp.manage`, scopes in failover not removed.
