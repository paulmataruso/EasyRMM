# ADR-0027: Coordinated agent updates

* Status: Accepted (2026-11-16).
* Refines: ADR-0009 (agent protocol: how agent builds are signed),
  ADR-0008 (agent packaging).

## Context
Installed agents stayed on the build they were installed with: the only way
to update one was to run the install command on the computer again. A fleet
has to follow the server's build without anyone visiting each computer,
and without every agent restarting at the same moment, or an update that
breaks agents breaking all of them.

Three facts shape the design:

* **A build cannot name its own version reliably.** Agents are built with
  `-trimpath` and the version passed by `-ldflags -X`; Go's build
  information does not record linker flags under `-trimpath`, so the
  server cannot read a file's version. It can hash it.
* **MeshAgent updates itself.** MeshCentral replaces its agents when its
  own build of them changes, and the gateway lets that through
  (ADR-0014). This ADR is about the EasyRMM agent only.
* **The server can already run anything on a device**: a signed script job
  runs as LocalSystem or root (ADR-0009). Whoever controls the server's job
  key controls the fleet, with or without updates.

## Decision
* **A build is identified by its SHA-256.** The agent reports the hash of
  its own executable with every heartbeat (`agentSha256`). A device is
  current when that equals the hash of the server's build for its platform
  and architecture. The agent directory's `VERSION` file (written by
  `make build-agents` and the image) gives builds a name for people; it is
  not used to decide anything. Agents older than this ADR report no hash:
  they are shown as unable to update themselves and need the install
  command once more.
* **The server decides who updates, a few at a time.** The rollout setting
  (**Settings → Agent updates**, `settings.manage`) is a mode and a limit:
  * *Automatically* (default): every agent on another build is updated.
  * *When asked*: only devices someone asked for: one device from its page
    (`device.edit`), or every outdated device from the settings page.
  * *Off*: no update starts; ones under way finish.

  At most **Devices at once** (default 20, up to 1000) updates are open at
  a time: an attempt holds its place until the agent comes back with the
  new build, reports a failure, or 15 minutes pass. The decision is made
  in the device's heartbeat, under a transaction-level advisory lock so
  that concurrent heartbeats cannot exceed the limit, and in a savepoint
  so that a failure in it never fails the heartbeat.
* **The instruction is signed with the server's job key**, which every
  agent pinned at enrollment: device ID, file name, size, SHA-256, version,
  an attempt ID and a 10-minute validity, under a domain-separation
  context of its own so that it can never be mistaken for a job. The agent
  refuses an instruction for another device, an expired one, one with
  unknown fields or a bad signature. The download itself
  (`/api/agent/v1/download/<file>`) is not trusted: the agent checks its
  size and hash against the instruction.
* **The agent installs it carefully.**
  1. It stops taking new script jobs and waits for running ones (up to
     10 minutes; past that the attempt fails and jobs resume).
  2. It downloads to `easyrmm-agent.new`, checks size and hash, and runs it
     with `version`, which must print the instruction's version and the
     platform: a build that cannot start never replaces a working one.
  3. It writes a marker (`update.json` in its state folder), renames the
     running executable to `.old` and the new one into its place, and
     restarts into it: on Linux by `exec` (same process ID, so systemd or a
     container's init sees nothing), as a Windows service by exiting with
     an error so the service manager's recovery starts it again (10
     seconds), and from a console by starting it.
* **The new build is on probation until it reaches the server.** Its first
  heartbeat that gets through confirms it and removes `.old`. It goes back
  to the previous build, and reports why, when it has started three times
  without getting through (it crashes) or has not got through for
  10 minutes. Errors are reported with the next heartbeats, matched to the
  attempt by its ID.
* **Failures back off, then stop.** A failed attempt is retried after 15
  minutes, then after an hour; after three the device is marked failed
  (audited) until someone asks again or the server ships another build. A
  new build retargets open updates and starts their count afresh.
* **Audit**: `device.agent_update` (success or failure, recorded as the
  agent), `device.agent_update_request`, `agent_updates.request_all` and
  `agent_updates.update` (the setting).

## Consequences
* Agents follow the server: upgrading the server image upgrades the fleet,
  20 devices at a time by default. Setting the mode to *When asked* or
  *Off* holds them back, for example to try a release on a few devices
  first.
* Builds are not signed with an offline release key, as ADR-0009
  anticipated: the instruction is signed with the server's job key, and the
  build is trusted because the server vouches for its hash. Since the job
  key already lets the server run any script on any device, a release key
  would not protect a fleet whose server is compromised; it would protect
  against a server serving a build that the project did not release. That
  needs release signing in CI, kept away from untrusted pull requests, and
  is left for when releases are published.
* A build that runs but hangs without crashing, and keeps failing to reach
  the server, is undone after 10 minutes only if its heartbeat loop still
  runs; one that hangs before its first heartbeat stays until someone
  restarts it.
* On Windows, each update ends the service with an error, so the System
  event log records that the service terminated unexpectedly before it is
  started again.
* Verified on the preview with two Linux agents running as their
  containers' first process: with one update at a time, both moved to a
  new build one after the other in about 10 seconds without the
  containers restarting, MeshAgent came back, and the audit log recorded
  both. A build made to crash on start was started three times, undone,
  and reported; the server queued the next attempt for 15 minutes later,
  and moving the server to another build retargeted both at their next
  heartbeats, and they updated to it. Updating a Windows agent has not yet
  been run.
