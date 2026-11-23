# ADR-0031: The EasyRMM agent installs the EasyPatch agent

* Status: Accepted (2026-11-16).
* Builds on: ADR-0030 (EasyPatch connector), ADR-0027 (signed instructions in
  the heartbeat), ADR-0010.

## Context
ADR-0030 links a device to EasyPatch once an EasyPatch agent runs on it, but
someone still has to install that agent another way. The specification asks
for one installation that brings both agents, without duplicate agents and
without two products fighting over the same machine.

EasyPatch 1.9.0 already provides what an installer needs, all reachable with
an Operator API token:

* `GET /api/v1/agent-packages`: each package's file name, format (`msi`,
  `deb`, `rpm`), architecture (`x64`, `arm64`), version, size and SHA-256;
* `GET /downloads/agent/{file}`: the package itself;
* `POST /api/v1/enrollment-tokens`: tokens for an organization (and
  optionally a site), single-use, expiring after an hour or more.

Its agents enroll with a token from standard input (Linux,
`easypatch-agent enroll --server … --token-file -`) or from the
`EASYPATCH_ENROLLMENT_TOKEN` environment variable (Windows,
`EasyPatch.Agent.exe enroll --server …`), never from the command line. The
Windows MSI takes the server (`SERVERURL`) and, for a private certificate
authority, its certificate (`SERVERCACERT`, base64 DER) for the agent's own
connection. The Linux agent trusts only the system's certificate store and
needs systemd.

## Decision
* **Who asks.** Someone with `patch.manage` at the device's site chooses
  **Install EasyPatch agent** for devices that have none (Patching, or the
  device's Patches tab). Or a super administrator turns on **Install
  automatically** for a linked organization (Settings → EasyPatch). Then
  every device there whose agent reports no active EasyPatch agent gets one,
  so the EasyRMM install command brings EasyPatch too. Either way the
  device must have an enrolled EasyRMM agent and be in a linked
  organization, and EasyPatch must be connected with an Operator token.
* **Never a second agent, never a move.** A device whose EasyPatch agent is
  enrolled is left alone, whatever server it is enrolled with. EasyRMM never
  uses `--force`, so it never moves an endpoint from another EasyPatch
  server. *Amended by ADR-0069: an agent that stopped working is repaired in
  place, by a restart or by reinstalling the package of the version it has
  (`msiexec /fa`, `apt-get install --reinstall`, `dnf reinstall`), which
  never runs this install path and keeps the enrollment. The EasyPatch agent
  in turn restarts the EasyRMM agent and repairs it from its recovery copy
  (the engine's `RepairCompanion` job), and returns the agents' logs.*
* **The instruction travels in the heartbeat, signed.** Like an agent
  update (ADR-0027), the install is an instruction in the heartbeat answer.
  It is signed with the server's job key over a context string of its own,
  and is bound to the device, valid for 15 minutes. It carries EasyPatch's
  public address, the CA certificate when EasyRMM's EasyPatch settings have
  one, the packages for the device's platform and architecture (name,
  address, format, size, SHA-256 as EasyPatch's API reports them), and an
  enrollment token. The server creates the token for that attempt: single
  use, valid for an hour, for the linked EasyPatch organization, and for the
  EasyPatch site with the device's site name when there is one. Its
  description names the device. The token is never stored in EasyRMM. The
  server revokes it when the attempt fails, and EasyPatch retires it once it
  is used.
* **Only agents that can install are sent one.** An agent that can install
  says so in its heartbeat, with the outcome of its last attempt. A request
  for an older agent waits until that agent updates itself (ADR-0027).
* **The agent installs.** It refuses an instruction that fails any check.
  It downloads the package from EasyPatch over https, trusting the system's
  authorities and the CA from the instruction, into its own state directory,
  and checks the size and SHA-256. Then:
  * **Linux** needs systemd and either apt-get (`.deb`) or dnf (`.rpm`). It
    runs `apt-get install` or `dnf install` on the file, then
    `/opt/easypatch/easypatch-agent enroll --server <url> --token-file -`
    with the token on standard input.
  * **Windows** runs `msiexec /i <file> /qn /norestart SERVERURL=<url>`
    (plus `SERVERCACERT` when there is a CA; exit codes 3010 and 1641 count
    as success), then `EasyPatch.Agent.exe enroll --server <url>` with the
    token in its environment only.

  One install runs at a time, for at most 20 minutes. The agent reports the
  outcome (EasyPatch's exit codes turned into words) with its next
  heartbeats, and sends its inventory again at once. ADR-0030 then links the
  device.
* **State and retries.** One row per device in `easypatch_installs`:
  waiting, sent, succeeded or failed, with the attempt count, the last error
  and who asked. A sent attempt without an answer within 30 minutes has
  failed. Automatic installs try three times, an hour apart. After that, and
  after a requested install fails, it takes someone's request to try again.
* **Audit.** `patch.agent_install` per device requested;
  `easypatch.organization_update` when automatic installs are turned on or
  off. Each attempt's outcome is in the device's install state.

## Consequences
* On Linux, an EasyPatch server with a private CA needs that CA in the
  device's certificate store. EasyRMM does not change a device's trust store
  and says so when enrollment cannot reach EasyPatch. On Windows the MSI
  records the CA for the EasyPatch agent alone.
* Linux devices without systemd (most containers) cannot run the EasyPatch
  agent; the install fails with that reason before downloading anything.
* EasyRMM does not uninstall or upgrade the EasyPatch agent: EasyPatch
  updates its own agents and removes them from its console. Uninstalling
  the EasyRMM agent leaves the EasyPatch agent in place.
* Devices go to the EasyPatch site with the same name as their EasyRMM site,
  or to no site (the organization's policy applies). They can be moved in
  EasyPatch.
