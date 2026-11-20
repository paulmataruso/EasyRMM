# ADR-0015: Deployment tokens, agent enrollment and MeshAgent delivery

* Status: Accepted (2026-11-15). Supersedes the MeshAgent sourcing in
  ADR-0008; phases ADR-0009.

## Context
ADR-0008 planned to extract MeshAgent binaries from the pinned MeshCentral
image at release time and bundle them in our packages. MeshCentral 1.3.1
does not ship them in its image: on first start it downloads its default
agents from GitHub releases into its data directory, and it customizes the
Windows agent for the server that serves it. Bundling would pin a MeshAgent
that the running MeshCentral did not choose and cannot update consistently.

ADR-0009 describes the full agent protocol. The first endpoint release has no
jobs to deliver yet, only enrollment, health and the MeshAgent install.

## Decision
* **Deployment tokens** belong to a site (optionally a device group), are
  created by people with `enrollment.manage` there, carry a name, an expiry
  (at most 90 days) and an optional use limit, and can be revoked. The token
  (`ert_` + 32 random bytes, base64url) is shown once; only its SHA-256 is
  stored. Creation, revocation and every enrollment are audited. *Amended by
  [ADR-0047](0047-tokens-shown-again.md): the secret is also kept, sealed, so
  an active token can be shown again to those who manage it.*
* **Enrollment** (`POST /api/agent/v1/enroll`, rate-limited per address):
  the agent sends the token, an Ed25519 public key it generated, and its
  facts (hostname, OS, architecture, version). The server checks and uses the
  token under a row lock and creates the device in the token's site. The
  private key never leaves the device.
* **Signed requests.** Every later call carries
  `Authorization: EasyRMM-Agent device=…, ts=…, nonce=…, sig=…`, an Ed25519
  signature over the method, path and query, timestamp, nonce and the
  body's SHA-256. Requests outside ±5 minutes, reused nonces (kept until
  the request's timestamp plus six minutes, past which it is refused anyway)
  and bodies over 1 MiB are refused.
  Since the security review before the first release, the header is checked before the body
  is read. A request that names no enrolled device, or a device over its
  limits, is refused unread, and a body must arrive within two minutes.
  The timestamp is checked again once the body has arrived. Each device
  may send one signed request a second, after a burst of 120; inventory
  uploads, after six, one every ten minutes; and keep four job polls open
  at once. An agent needs a small part of that. Limits are spent only by
  requests whose signature is verified, so naming another device does not
  use up its allowance. Requests over them get 429 `rate_limited`, and the
  agent backs off as after any failure.
* **Heartbeat** every 60 seconds (`POST /api/agent/v1/heartbeat`) refreshes
  the device's facts and online state. The WebSocket channel of ADR-0009
  arrives with jobs (phase 7).
* **MeshAgent comes from the running MeshCentral, through EasyRMM.** The
  agent asks EasyRMM for the MeshAgent binary for its architecture and the
  settings (`.msh`) of its site's device group, with signed requests. The
  server fetches both from MeshCentral over loopback as its service account
  (`/meshagents`, `/meshsettings`), so the agent version always matches the
  server and the `.msh` is never published unauthenticated.
* **MeshAgent runs beside the agent, not inside it.** `easyrmm-agent
  install` (the normal path) gives MeshAgent its own systemd unit,
  `easyrmm-meshagent.service`. `easyrmm-agent enroll` followed by `run` (for
  containers and other machines without systemd) starts MeshAgent as a child
  process and restarts it when it exits. MeshAgent runs without arguments, as
  a persistent agent; its database lives next to the binary.
* **Correlation.** After installing MeshAgent the agent reads its node
  identifier (`meshagent -nodeid`) and reports it in its heartbeat. The
  server links the MeshCentral node to the enrolled device, but only within
  the device's own site: a node in another site's device group is refused.
  If discovery had already created a separate device for that node, the two
  are merged into the enrolled one (its session history moves along); if
  another enrolled device held the node, that device gives it up. Each link
  is audited as `device.remote_link`.
* **Online** means the agent reported in within the last three minutes or
  MeshAgent is connected to MeshCentral. Remote sessions are offered only
  while MeshAgent is connected.
* **Installers.** The server hands out the agent builds in
  `EASYRMM_AGENT_DIR` (the Docker image includes the Linux builds) with a
  `SHA256SUMS` file, and an install script that downloads the right build,
  checks it, and runs `easyrmm-agent install` with the token in the
  environment. Downloads use HTTPS only, except for a server on loopback.
  The Windows agent, MSI and service are a later step.

## Consequences
* Installation needs the EasyRMM server to be reachable, which it must be
  for enrollment anyway. Offline install media are not supported.
* Our packages contain only the EasyRMM agent and are the same for every
  server.
* A device's MeshCentral and EasyRMM identities stay linked even when
  MeshAgent connects before the EasyRMM agent reports.
* Device status no longer depends on MeshCentral: a server with remote access
  turned off still lists enrolled devices and their health.
* MeshCentral 1.3.1 reports connection changes as `nodeconnect` events
  without an `etype`; the synchronizer matches them by action so a device
  that disconnects shows as offline within seconds, not at the next full
  sync.
