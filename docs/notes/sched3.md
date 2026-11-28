# Feature 11 slice 3: more actions for scheduled tasks

Licensed under FSL-1.1-ALv2; licensor DHI Technical Services LLC.

Slice 3 of feature 11 in `docs/architecture/feature-plan-msp.md` is "more
actions as fixed-script job kinds on both platforms: software, restart,
shutdown, and starting, stopping and restarting a service; exclusivity classes
per device; a restart's offline and online are expected". There is no
`docs/notes/sched1.md` in the tree; the plan and `sched2.md` were the source.
Slices 4 (failure notices, retrying what failed, approvals, dry run) and 5
(calendar, execution report) are not built.

## CHANGELOG

* **Step kinds.** A scheduled task now does one of: run a library script (as
  before), a software action (install, update or uninstall through winget,
  Chocolatey or the system's package manager), restart, shut down, or start,
  stop or restart a service. `automations.step_kind` and `automations.step`
  (jsonb) hold it; `script_id` and `script_sha256` are null for the others
  (migration `90631`).
* **Maintenance jobs.** A new job kind `maintenance` (`jobs.maintenance`
  holds the action) runs one of EasyRMM's own scripts compiled into the
  server (`jobs/maintenance/linux.sh`, `windows.ps1`): the same pattern as
  `software`. A restart or shutdown starts one minute after the script runs so
  the run can report first. Action arguments are checked against fixed lists
  and a service-name pattern (never start with a dash); they are never part of
  the script's text. Audit action `device.maintenance_action`.
* **Exclusivity per device.** `oneMaintenanceAtATime` (jobs/delivery.go, also
  used by `Waiting`): a maintenance run waits for any hardening, software or
  maintenance run of the device that is sent, running, or queued before it, and
  those wait for an active or earlier maintenance run. A hardening confirm
  waits for nothing, as in ADR-0054. Other devices are not held.
* **Expected offline.** A succeeded restart (20 minutes) or shutdown (12 hours)
  writes `device_expected_offline` (one row per device; a longer expectation is
  never shortened). Monitoring opens no new `offline`, `remote_down` or
  `agent_silent` alert for such a device while the row is current; an alert
  already open is kept and resolves as it did before.
* **Permissions at each run.** A software task needs `software.manage`, every
  other step `script.run` (a restart or service action is what a script could
  do). Saved with the editor as owner; checked again at each run and each
  stagger batch; the run fails with "The owner may no longer ..." if lost.
* **Targets.** Each step knows its platforms (a script's shell, a package
  manager's, a restart's both or one chosen, a service's one chosen) and the
  task reaches only those devices. A maintenance step makes one job per
  platform; a staggered run keeps every job's id in the run's history.
* **API.** `POST /scheduled-tasks` takes `stepKind` (default `script`) and
  `step`; `PATCH` takes `step` (the kind cannot change). Task JSON carries
  `stepKind`, `step`, and `scriptId` is null for non-script steps.
* **Web.** The Scheduled tasks form has an Action selector with the fields for
  each kind; the list names the step; the Jobs list can filter by
  "Restarts and services".
* **Coverage floor.** `server/internal/schedule` 80% in
  `scripts/ci/check-coverage.sh` (measured 81.5% with the integration tests).

## IMPLEMENTATION_STATUS

Built and tested against real PostgreSQL (integration tag):

* restart and shutdown tasks across Linux and Windows devices, per-platform
  jobs, platform-limited tasks; staggered restart keeps the platforms apart and
  reaches every device once;
* software and service steps, validation of every step shape, step edits, the
  owner's permission re-check at run time;
* maintenance jobs: signed payload, arguments, audit, platform and permission
  refusals; expected-offline rows for restart and shutdown only, failed
  restarts say nothing, a restart never shortens a shutdown's wait;
* exclusivity: software ahead of restart ahead of a service action on one
  device, one at a time, another device unaffected;
* monitoring: expected-offline holds a new offline alert, expires, and does not
  resolve an alert already open;
* the Linux script is syntax-checked and refuses unknown actions in a unit test.

Not built or not verified:

* **The scripts have not been run on real computers.** `windows.ps1` was not
  executed anywhere (no Windows host); `linux.sh`'s service and shutdown paths
  were not run, only its syntax and argument refusals.
* **Restart "through the engine where linked"** (the patching engine, its
  prompts) is not done: every restart goes through the agent's script. A device
  with the EasyPatch agent can be restarted twice (engine and task); no
  coordination exists yet. The plan lists this as slice 3; it needs the engine
  ADR's contract and is left for a follow-up.
* **Collisions with patching** (msiexec 1618, restarts inside patch windows):
  exclusivity covers EasyRMM's own jobs (hardening, software, maintenance), not
  the engine's installs or Windows Update.
* **Expected offline is not an ADR-0053 planned restart** (that slice 7 is not
  built): no notice is suppressed or sent, only the three alert kinds above.
  The `suppressed` alert resolution is not used.
* Slice 4 (failure notices, retry of what failed, approvals for sensitive
  tasks, servers confirmed by name, dry run) and slice 5 (calendar, report).
  A fleet-wide restart task has stagger, window and step-up from slice 2 and
  F5 but no approval and no dry run yet.
* The Jobs list shows a maintenance job's name ("Restart service cron"); the
  job page has no maintenance-specific panel.
* `jobs` coverage was not re-measured for the new code; its tests are
  integration tests and the package floor (85%) was not run in full here.

## For the integrator

* Migration `90631_sched3_actions.sql` uses the number range given for this
  workstream, which sorts after `00093`. A later migration numbered `00094` or
  above will sort before it; goose needs out-of-order allowed, or renumber this
  one to the next free number at merge.
* The migration grants `SELECT (maintenance) ON jobs` by column: the server's
  role has no table-wide read on `jobs` (it hides the arguments, ADR-0063).
* `monitoring/evaluate.go` and `remote.go` each gain one join and one WHERE
  line; the ADR-0085 suppression logic is untouched.
* Decided in review: restarts and service actions need `script.run`, not a new
  permission; a new permission would also need roles, docs and a migration of
  role definitions for something a script already allows.
* ADR text, `docs/architecture/database.md`, CHANGELOG, ROADMAP and
  IMPLEMENTATION_STATUS (top-level) were not touched.
