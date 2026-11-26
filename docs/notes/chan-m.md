# chan-m: ADR-0059 slices M1 to M5 (the channel's messages)

## Changelog lines
* The agent channel now carries work (ADR-0059): job pushes (a live agent holds no long poll), repair instructions, settings after a device moves, verbose and follow log instructions, check-in wakes (a removal wakes the agent), and live log batches while someone follows the Logs page. Each was stored first and is also found by the heartbeat or poll, which remain the fallback. Still off by default (`EASYRMM_AGENT_CHANNEL`).
* The agent reports `transport.lastReplayed` when its channel upgrade was replayed by someone else.

## Implementation status rows
* Agent channel messages (M1 to M5): built; integration-tested on Linux with the real agent runner, job worker, log shipper and channel against the real server app and PostgreSQL (job pushes, no poll held, repair, settings, verbose, follow with batches over the channel, removal wake, fallback with the channel off or closed, dev scope). Not built: M5's console and docs part (connection state on the device page, Settings page, `docs/deployment/nginx.md`, metrics, release note), automatic repairs and group verbose pushes, H1 to H3. Windows: builds and lints, not run.

## Privacy
Nothing new is stored. Log batches move over the channel instead of HTTPS while followed; the rows are the same. The server logs a device id when an upgrade of it was replayed.

## For the integrator
* Dev scope: every push goes through `Hub.Push` (`devscope.Allowed(org)`), the claim loop checks it each time, and wakes go through Push.
* Hotspots touched, small and additive: `agentproto/channel.go` (`ChannelReport.LastReplayed`), `agent/runner/runner.go` (fields `Nudge`, `OnJobsWaiting`, `meshMu`, a 3-line `JobsWaiting` block and a guard at the top of `applyMeshSettings`), `agent/runner/repair.go` (a `Nudge` after a step), `app.go` (`d.wireChannel()`), `agentapi.go` (`jobsWaiting` for live devices, a replayed log line).
* No migrations.
* `go vet -tags integration,vm` under `GOOS=windows` fails in `server/internal/database/leader_keepalive_integration_test.go` (not touched here). `agent/runner` `TestChannelWakeBringsTheHeartbeatForward` flakes under heavy load (its own race, not changed here).
