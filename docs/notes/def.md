# def: Windows Defender management (ADR-0074)

## Changelog lines

- Microsoft Defender can be managed from the device's Security tab: quick, full and custom scans, signature updates, cancelling a scan, removing active threats, the quarantine (restore, with a step-up), protection settings, Attack Surface Reduction rules, Controlled Folder Access and exclusions. Settings that Group Policy, Intune or Tamper Protection own are shown locked and are never written; Tamper Protection is shown read-only.
- EasyRMM's own Defender exclusions (ADR-0070) cannot be removed or weakened from the module, on the server and on the computer.
- Two permissions: `defender.view_sensitive` (file paths, user names and administrators' exclusions) and `defender.weaken` (anything that lowers protection or restores a threat); both start at Site Administrator.
- The agent reads Defender's event log once a heartbeat and the server turns it into eight alert kinds (threat found, threat not removed, signature update failing, settings changed, exclusions changed, Tamper Protection blocked a change, not healthy, out of support) with thirteen default policies per organization.
- Site and organization Overview have a Security card, and both levels have a Security tab with one row per computer, read from what is stored.

## Implementation-status rows

- Defender catalog (25 actions), scripts, parameter checks, `ours` guard, permissions, role unions: built; Go and integration tests; the scripts pass the AST check and PSScriptAnalyzer; **not run against a real Defender** (the Windows runner step runs the reads and the refusals on a runner whose Defender state is unknown).
- Defender event reader (`agent/winevents`: parse, storm summaries, bookmark, epoch, gap): built and tested; the wevtapi source is compiled for Windows and **not run**.
- Event store, ingest, acknowledgement, own-change marking, derived snapshot, alert kinds, default policies, retention: built; tested against real PostgreSQL.
- Console: Security tab panels, org and site cards and tabs: built; Vitest.
- Not built: Facts `detail` and its hourly timer, `DefenderPolicy.module`, the server-side `managed_by_policy` from a snapshot, the group page column, the e2e spec. Not verified: R1 to R12 of the ADR (real devices), Server Core.

## Privacy notes

- `defender_events.sensitive` holds paths, user names, process names and the old and new value of a configuration change; it is cleared after 30 days and the row deleted after 90. `summary` never holds them (a test feeds events through the normaliser).
- An exclusion's value is audited as its length and SHA-256; its reason as written.
- Only a holder of `defender.view_sensitive` reads the sensitive reads and the sensitive part of an event.

## For the integrator

- Migration `90221_defender_events.sql`; `defender_events` is "stays" in the move test (one added token).
- Hotspot edits: `rbac.go` (a const block and two role lines), `agentproto.go` (one field), `agentproto/defender.go` (two fields), `agents/heartbeat.go`, `agents/service.go`, `agents/defender.go`, `agent/runner/runner.go` and `defender.go`, `agent/cmd/easyrmm-agent/main.go` (one block), `app.go` (imports, five lines), `levelTabs.tsx` (one line), the org and site pages (one card each), `web/src/api/types.ts` (two permissions), `jobs/winmod.go` (`NeedsConfirm`), `winmod.go` and `validate.go` (`Confirm`, `Check`), `WinmodAst.ps1` (rule `defender-list`).
- `TestDefaultPoliciesAreCreatedOnce` now expects 13 defaults (ten on, three off).
- No `devscope` change: every automatic behavior here goes through `modules.Allowed`, which includes it.
