# Notes for the integrator: Quick Assist EasyPatch ad hoc (ADR-0080 QA6), builder `qa6`

Branch `ws/qa6`, cut from `integration/2026-11` (233ef6d2). Migration 00098
(renumber if it collides).

## CHANGELOG lines

* Quick Assist (ADR-0080 QA6): an elevated session of an organization linked to
  EasyPatch gets an EasyPatch enrollment token (single use, one hour) in the
  runner's status answer, once, after the technician accepts. The runner
  starts the EasyPatch agent beside it as a confined child with
  `run --adhoc --data-dir <session folder>/EasyPatch --registry-key <session id>
  --lock easyrmm-qa-ep-<session id>`, so the technician sees and installs the
  computer's updates during the session. At the end the runner stops it and
  removes its folder and registry key, and the server revokes the token and
  the endpoint the agent made in the patching engine.

## IMPLEMENTATION_STATUS rows

| Area | State |
| --- | --- |
| EasyPatch ad-hoc mode (QA6): server token and endpoint removal | Built; tested against real PostgreSQL and the patching engine's stand-in |
| EasyPatch ad-hoc mode (QA6): runner child, stop and cleanup check | Built; tested on Linux with a real child process; compiles for Windows; never run on Windows |
| EasyPatch ad-hoc mode (QA6): the agent enrolling itself | **Not built**, see below |

## What was built

* `server/migrations/00098_quick_assist_easypatch.sql`: on
  `quick_assist_sessions`, `easypatch_state` (`none`, `issuing`, `issued`,
  `unavailable`, `removed`), `easypatch_token_id`, `easypatch_site_id`. The
  token's secret is never stored.
* `server/internal/easypatch/adhoc.go`: `AdHocToken` (engine site named like
  the Quick Assist site, made when missing; nil when patching is not set up
  or the organization is not linked) and `AdHocRemove` (revokes the token and
  the active endpoint with the device's name in that site; an endpoint of the
  same name in another site is never touched).
* `server/internal/quickassist/session.go`: `Status` claims the token once
  (`none` to `issuing`), makes it after its transaction, and returns
  `easypatchToken` and `easypatchServer`. An engine error puts the claim back,
  so the next poll tries again; "nothing to give" is remembered
  (`unavailable`). `RunnerEnd` (both branches) and `Sweep` call
  `removeSessionPatch`, which runs after the commit like the MeshAgent node
  removal and puts the state back when the engine fails, so the next sweep
  retries. `Sweep` also covers lost sessions and sessions a technician ended
  whose runner never reported. Wired in `app.go` (`SetPatchIssuer`).
* `agent/client/quickassist.go`: `QAState.EasyPatchToken`, `.EasyPatchServer`.
* `agent/quickassist/easypatch.go` (+ `_windows.go`, `_other.go`): `epRun`,
  started only when the runner is elevated, a token was given and no real
  EasyPatch is on the computer; the file is looked for beside the runner
  (`EasyPatch.Agent[.exe]`, `EasyPatchAgent[.exe]`) or `Options.EasyPatch`;
  without it the session goes on and the user is told. The token and server
  go in the child's environment (`EASYPATCH_ENROLLMENT_TOKEN`,
  `EASYPATCH_SERVER`), never on its command line. `stop` kills it, removes
  the folder and `HKLM\SOFTWARE\EasyPatchAdHoc\<session id>`. The cleanup
  report has a check `easypatch_removed` (in the manifest hash) when the
  agent ran.

## Deviations from the brief

* **No `easypatch_device_id`.** The server cannot know the endpoint id of an
  agent that enrolled by itself, and the session's device is never linked to
  an EasyPatch device (the device reports no EasyPatch inventory). The session
  keeps the token id and the engine site id instead, and the endpoint is found
  at the end by device name in that site. The site is Quick Assist's own, so
  nothing but sessions enrolls there.
* **Registry key** is the session id, not `EasyPatchAdHoc\<id>`: the agent's
  own name rule (`^[A-Za-z0-9][A-Za-z0-9.-]{0,63}$`) refuses a backslash and it
  adds the `SOFTWARE\EasyPatchAdHoc\` prefix itself.
* **Token on Status, not in `Accept`.** The engine is another service, and a
  call to it inside Accept's transaction would hold the row.

## For the integrator (open points)

* **The C# agent cannot enroll ad hoc yet.** `AdHocMode.cs` makes `run` use its
  own data directory, key and lock, but enrollment is the separate `enroll`
  command (`Cli.EnrollAsync`), which takes no `--adhoc` flags, and `run` reads
  neither a token nor a server from its environment. The runner passes
  `EASYPATCH_ENROLLMENT_TOKEN` and `EASYPATCH_SERVER` to `run --adhoc`; the
  agent must enroll from them when it is not enrolled in its ad-hoc data
  directory (or `enroll` must take the ad-hoc flags and the runner call it
  first). Until then the child starts and the engine sees no endpoint. This is
  the one piece left of QA6; nothing in Go needs to change but the call.
* The EasyPatch agent file must be shipped beside the runner (the runner does
  not download it). Nothing builds that package yet.
* Windows: the code compiles (`GOOS=windows go vet ./agent/quickassist/`) and
  was never run on Windows.
* A session whose runner dies between claim and issue stays `issuing` and
  gets no token; the session carries on without patching.
* `scripts/ci/check-coverage.sh` floors hold: `agent/quickassist` is 43.2%
  alone and 67% with the server e2e tests (floor 45, measured combined).
