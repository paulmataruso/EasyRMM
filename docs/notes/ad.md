# ad: Active Directory management (ADR-0075), first build

Branch `ws/ad`. No migration was needed (migrations 90231 to 90239 are unused): snapshots, results, secrets and alert policies are ADR-0073's.

## Changelog lines

- Active Directory on a domain controller: the device page has a Directory tab (shown where the agent found the `ad_ds` role and the viewer holds `ad.view`) with the domain, its controller, the password policy, the Recycle Bin state and health checks (replication, operations masters, directory services, SYSVOL and NETLOGON), the users and the groups with their direct members.
- Help-desk actions on users: unlock, enable, disable and reset a password (typed or generated, shown once), and, for Organization Administrators, delete, with typed confirmation and step-up where a credential or access changes. The domain's powerful accounts (Domain, Enterprise and Schema Administrators and everything nested in them, krbtgt, the built-in Administrator, accounts with adminCount set, computer accounts, managed service accounts) are never changed; a service account needs a second confirmation from an administrator.
- New permission `ad.helpdesk` (Technician and above).
- New alert kind `ad_replication_failed`, with the default policy "Directory: replication failing" (on, 120 minutes).
- The actions for creating, editing and moving users, creating groups and changing group membership exist in the catalogue and are tested; the console does not offer them yet.

## Implementation-status rows

- `active_directory` catalogue (19 actions), guard, results, alert kind: built; unit, real-PostgreSQL and stand-in tests pass.
- The scripts: parse, pass the AST check, and pass 148 checks against a stand-in ActiveDirectory module under PowerShell 7 (`scripts/ci/winmod-ad`). **Not run on a real domain controller or against the real cmdlets.** Every real-controller step of ADR-0075 section 9 is still to do, starting with the SYSTEM write gate, `Get-ADDomainController -Identity <this computer>`, `Get-ADReplicationFailure`'s properties and the 20,000-object bound.
- Controller selection and pin, `ou_tree` picker, computer actions, privileged-membership alert, lockout alert, organization health card, create/edit/move/membership dialogs: not built.

## Privacy notes

- Personal fields (mail, telephone, title, department, company, office, last sign-in, groups) are in `user_get` only, which needs `ad.view_sensitive` and whose result is kept ten minutes. Lists carry the name, sign-in name, UPN and flags only. Nothing from the directory is copied into EasyRMM's tables beyond the typed result of a run and, for `status` and `health_read`, a snapshot.
- A password (typed or generated) and the credential fallback's password are sealed secrets: not in `jobs.params`, the audit, logs or results; a generated password is in the one answer to the request. The credential fallback's user name is audited as a length and a hash.
- The directory's own audit names the controller's computer account as the actor; EasyRMM's audit row records who asked.

## For the integrator

- `server/internal/app/app.go`: the catalogue line is `winmod.NewCatalog(slices.Concat(defender.Actions(), activedirectory.Actions())...)`; other modules extend the same line. One `RegisterModuleAlerts` block added.
- `web/src/pages/devices/modules/moduleTabs.tsx`: one entry added to `DEVICE_MODULE_TABS`.
- `winmod.Param` gained `Pattern`, `AllowEmpty`, `Needs`, `Generate`, `RefuseWellKnown` and the `DN` type; `WinmodRun` gained `Generated`. Other modules may use them.
- `web/e2e/console.spec.ts` has one test appended after the step-up test (it relies on a fresh step-up, and handles the dialog if it lapsed); `web/e2e/agent.ts`'s `JobPayload` gained `params`.
- `scripts/ci/winmod-ad/run.ps1` is run by `TestScriptsAgainstAStandInDirectory` where `pwsh` exists (not on Windows). `gen.sh` in the package builds the scripts from `src/` and rewrites `pins.go`.
