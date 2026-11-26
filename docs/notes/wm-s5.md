# wm-s5: the `winmod` job kind (ADR-0073 slice 5)

## Changelog lines

- Windows management modules have one job kind, `winmod`: fixed, versioned actions from a catalogue whose scripts are pinned by SHA-256, with typed parameters checked on the server and passed on stdin, and typed results. These jobs are hidden from the Jobs list.
- First action: `defender.status`, a read-only read of Defender's state (`POST /api/v1/devices/{id}/winmod/defender.status`, then `GET /api/v1/winmod/runs/{id}`).
- Secrets in an action's parameters are sealed with the server key, put into the signed job only at delivery and deleted then; a redelivery is refused. Destructive and credential actions need a typed confirmation and a step-up.

## Implementation-status rows

- `winmod` job kind, catalogue, pinned scripts, validation, typed results, secrets, confirmation, step-up, audit, retention, Jobs-list exclusion: built and tested (real PostgreSQL; real agent worker on Linux with shell scripts).
- `defender.status` PowerShell script: written, schema and hash tested; **not run** on Windows yet. The Windows runner step (`TestStatusScriptOnWindows`, job "Agent tests on Windows") runs it in CI.
- Step-up in the winmod path is tested with the same verifier stub as Windows hardening; the real session check is `httpapi.Sessions.VerifyStepUp`, wired in `app.go`.

## Privacy notes

- `jobs.params` holds parameters without secrets; the audit holds each plain value, a sensitive value as its length and SHA-256, and a secret as `(secret)`. Nothing logs params.
- A winmod job and its typed result are deleted after the action's retention (an hour for reads).
- A job that carried a secret keeps no raw output.

## For later slices

- Add a module's actions with `winmod.NewCatalogue(...)` in `app.go` (`defender.Actions()` is the model); `SensitivePermission` is required for a sensitive action.
- Slice 6 (snapshots) reads `winmod_run_results` or stores its own; slice 9's AST check should walk `server/internal/winmod/**/*.ps1`.
- `windows_module_snapshots` is not in migration 90161.

## Other notes

- `winmod_run_results` is "stays" in `TestMoveDispositionOfEveryTable` (like `job_runs`: a result stays with the org and site it was read under); add it to ADR-0069's list when that ADR is next touched.
- Existing tests that assume their own migration is the last (`TestStepUpMigrationGoesDownAndUp`, `TestHardeningGuardMigrationDownUp`, and the move test's `hardening_guards` row) already fail on integration; this slice does not change that. The new migration test goes down to the version before its own and up again, so it holds whatever follows.
- `scripts/ci/check-powershell.ps1` (PSScriptAnalyzer) does not yet scan `server/internal/winmod`; slice 9's AST check should cover it.
