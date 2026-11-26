# bkp: Windows Backup (ADR-0077), first build

## Changelog lines

- Windows Backup module for servers: Windows Server Backup state (last and next run, targets and space, versions), run now and stop, set the policy, back up to a local volume, a network share (with an account) or a whole disk, restore files to a new folder or over the originals, remove old versions after a preview, and install the feature. Tier 3 actions (format a disk, overwrite on restore, delete versions, remove the policy, full backups, install) need `backup.destroy`, a typed confirmation and a second factor.
- Backup alerts: last backup failed, no recent successful backup, target not found, target nearly full, backup running too long, and not configured, with server defaults.
- A Backup card on the organization and site pages. Desktops show what Windows allows: the Windows 11 Backup app has no management interface.
- New permissions `backup.view_sensitive` and `backup.destroy` (Site Administrator and above). A server without the Windows Server Backup feature reports the `windows_backup` role as `not_installed`.

## Implementation-status rows

- Windows Backup, server reads, run and stop, policy, targets, restore, prune, install, alerts, cards: built; Go unit and integration tests (real PostgreSQL), Vitest. **Not run on a real server** (R1 to R12 of ADR-0077 outstanding); the scripts map Windows Server Backup's result properties by name and are unverified against a real server. The Windows runner step runs the read-only scripts (`TestReadScriptsOnWindows`); a runner without the feature must answer `module_missing`.
- Event reader and event-based alerts, workstation rules, the group column, the Events panel, `backup_not_installed`: not built (see the ADR's amendment).
- Desktop System Image Backup and the File History policy switch: not built; gated on R11.
- Non-system volume recovery (B12): not built; gated on R12.

## Privacy notes

- `backup.status` stores no path, share name or account. `backup.sensitive` (paths, included folders) is kept 15 minutes and served only with `backup.view_sensitive`.
- The share password is a sealed secret: never in `jobs.params`, `jobs.body`, the audit, logs or a result; the audit records the share and account only as length and hash. Windows keeps it inside its own policy.

## Integrator notes

- No migration was needed (the ADR's `backup_events` waits for the event reader); migrations 90251 to 90259 are unused.
- Hotspot edits: `app.go` (catalogue, alert registration, `backupapi` route), `rbac.go` (two permissions), `agentproto/roles.go` and `agent/roles/detect.go` (role state `not_installed`), `winmod.go` / `validate.go` / `jobs/winmod.go` (an `Action.Confirm` flag and a `Param.Pattern`/`Check`), `moduleTabs.tsx`, the two overview pages (one card line each), `types.ts`, `winmod-helper-pins.json`, `check-powershell.ps1`.
- Web e2e: not added; Vitest covers the tab and the card.
- The event reader (agent/winevents) comes later, with log collection (ADR-0060, wave 5); until then alerts come from the hourly status read, as the ADR's amendment says.
- `Action.SubjectIsDeviceName`: the server compares the confirmation subject with the device's real name (trimmed, case-insensitive) and refuses a mismatch.
