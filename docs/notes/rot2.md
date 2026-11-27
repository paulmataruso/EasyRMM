# rot2: ADR-0057 slice 2, rotation

Branch `ws/rot2` from `integration/2026-11`. No migration (the ring's tables from
slice 1 are enough: an open rotation is the newest key when it was made for a
planned or moving rotation and has not been cut over to, compromised or lost).

## What is built

* `jobkeys/rotate.go`: `Start` (planned, moving, compromised), `Finish`, `Forget`,
  `SweepSeeds` (the automatic deletion of a seed no device may still trust, run
  hourly beside the purge), `ReplaceLost`, `Recover`, `Snapshot`, `NewHost` (a ring
  for host commands that loads nothing, so it works when the server cannot start
  because a seed does not open). Each change runs in one transaction that takes the
  ring's advisory lock, then checks again, inside it, the updater's guard
  (`updater.Guard`: the hold file itself, not the flag, and a status whose attempt is
  running) and, for `Start` and `Finish`, that no older server is seen (a connection
  named plain `easyrmm-server`, or an instance of an older version seen in the last
  2 minutes; a version that does not parse, such as `dev`, is never older).
  `NextGeneration` now reads the table's highest generation inside the lock instead of
  this server's loaded ring.
* `jobkeys/offer.go`: `Ring.Offer`, the five rules of "What the server offers each
  device", signs and records the hand-over or cut-over (`issued_instructions`, the
  fingerprint as ID) and writes the cut-over to the device's row, so the key chosen
  follows it. `agents/heartbeat.go` asks after `planUpdate`, never while an update is
  open or placed in the answer, and only where `devscope.Allowed(org)`.
* Floor change event: `Ring.OnFloorChange`, called by every reload that finds the
  floor moved. The server that moved it reloads at once; the others within 30 s.
  `app.go` connects it to `agentchannel.Hub.Refresh`, which closes every connection
  with `closing` reason `refresh`.
* Channel: `agentchannel.Options.KeyFor` looks the key up for each message
  (`ring.For`); `Key` stays for tests and tools.
* Quick Assist: `Service.UseRing`. Tickets are signed with the newest key and verify
  under any key of the ring; a runner is given the newest key and
  `job_key_given_generation` records it, so `For` signs for it with that key.
* API (`httpapi/jobkeyapi`, `settings.manage`, step-up on every change):
  `GET /api/v1/settings/job-key`; `POST .../rotate {reason}`, `.../finish
  {backupTakenSinceStart}`, `.../forget {generation}`, `.../replace-lost`,
  `.../recover {generation}`. The console never skips the 24 hours.
* Host: `easyrmm-server job-key status | rotate --reason R | finish --backup-taken
  [--now] | forget G | replace-lost | recover G`.
* Audit: `job_key.rotate`, `job_key.finish`, `job_key.forget` (by `person` or
  `server`), `job_key.replace_lost`, `job_key.recover`; each carries `via`.

## Decisions to review

* The API paths are the ones the task named (`/rotate`, `/finish`, `/forget`,
  `/replace-lost`, `/recover`), not the ADR's (`/rotations`, `/keys/{g}/forget`).
  The ADR puts `replace-lost` and `recover` on the host only; the API offers them
  too, behind step-up, as asked. They only act when a seed does not open, which a
  running server cannot have (`replace-lost` then answers "nothing lost").
* `replace-lost` checks `tls.internal_ca` and `meshcentral.secrets`, the two sealed
  settings the ADR names; the "other sealed values the database holds" fallback is not
  built.
* The floor event is a reload comparison, not a PostgreSQL notification: every server
  sees it within `ReloadEvery`.
* "While an upgrade is under way" reads `status.json` `attempt.result == running`
  in the updater's status directory; an unreadable status counts as under way.
* Statement IDs are random UUIDs (the replay set is per statement); the instruction
  log and `issued_instructions` use the fingerprint of the key introduced, as slice 1
  decided.

## For the integrator

* The ADR says slice 2 does not merge before an updater with ADR-0052's rollback
  guards is released; the guards themselves (`--strand-agents`, the backup's
  generation in the updater's status) are the updater's and are not here.
* Not done: the bundle test (needs Docker machines with systemd), the console
  (slice 3), the `incident` commands beyond `restored` (slice 4), the banners, and
  the `GET` view's device counts.
* Changelog line: "The server's job key can be rotated from the API and the host:
  planned, for a move, or after a compromise; agents follow with a signed hand-over
  and cut-over (ADR-0057)."
