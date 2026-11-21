# ADR-0061: Moving EasyRMM to a new name

* Status: Proposed (2026-11-21), revised after review. Not implemented.
* Builds on: ADR-0055 (proposed: Let's Encrypt in one step; when a name is
  trusted and reachable, 5b3; agent trust, 5b1; MeshCentral's name; `tls
  reset`; and its section "Step-up authentication", the one definition
  this ADR uses), ADR-0057 (proposed: rotating the job key; everything
  this ADR signs goes through its ring, and its refusal of a rollback is
  the pattern for this one), [ADR-0009](0009-agent-protocol.md) as amended
  by pull request #52 (protocol levels: new request fields only to a
  level-2 server, new instructions only to builds that reported
  understanding them),
  [ADR-0016](0016-ip-address-access.md) (IP access and the internal
  authority), [ADR-0014](0014-remote-access-gateway-and-device-discovery.md)
  (how MeshCentral reads the certificate its agents see),
  [ADR-0015](0015-enrollment-and-meshagent-delivery.md) (signed requests,
  MeshAgent's signed downloads), [ADR-0017](0017-scripts-and-jobs.md) (the
  job key), [ADR-0027](0027-agent-updates.md) (agent updates),
  [ADR-0031](0031-easypatch-agent-install.md),
  [ADR-0039](0039-agents-on-easyrmms-name.md) and
  [ADR-0045](0045-importing-a-standalone-easypatch.md) (the EasyPatch agent,
  its paths on EasyRMM's name, an imported EasyPatch's names),
  [ADR-0032](0032-webauthn-passkeys.md) (passkeys),
  [ADR-0034](0034-oidc-single-sign-on.md) and
  [ADR-0044](0044-authentik-when-chosen.md) (single sign-on, Authentik),
  [ADR-0050](0050-removing-a-device.md) (agent reports on a path of their
  own), [ADR-0052](0052-the-host-updater.md) (backups, rollback, `hold`,
  the updater's status).
* Needs first: the separate fix, being built, in which
  `ServerConfig.Render` writes MeshCentral's `allowedOrigin` with the host
  name of every MeshCentral origin, IPv6 addresses in brackets as
  `URL.hostname` gives them. Without it MeshCentral 1.3.1 refuses remote
  sessions on any MeshCentral host but its `cert` name, which the review
  confirmed by running MeshCentral's own check in the pinned image (IP
  access in a DNS install is refused today).
* Amends: [ADR-0032](0032-webauthn-passkeys.md), "Relying party": a
  credential keeps the relying party ID it was registered under, and the
  console's current origins use it through Related Origin Requests;
  [ADR-0034](0034-oidc-single-sign-on.md), "One redirect URI": one per
  console name, confirmed per provider;
  [ADR-0044](0044-authentik-when-chosen.md): the blueprint reads the
  console's names from files the server writes, and `authentik-setup`
  stays running to apply it when they change;
  [ADR-0031](0031-easypatch-agent-install.md): install instructions name
  EasyRMM's own address, not the engine's `PublicUrl`;
  [ADR-0052](0052-the-host-updater.md), "Rollback": refused across step 1
  or 2 of a move, as across a key rotation's cut-over; ADR-0055: what
  wins when `.env`, `tls reset` or **Remove name** meet a move
  ("Precedence over ADR-0055", below).
* Part of [the feature plan](../feature-plan.md): feature 5, slice 5c. It
  comes last in the plan's order and needs F0 (ADR-0057) and 5b1 to 5b3
  (ADR-0055).

## Context
The owner asked for Let's Encrypt "for everything"; ADR-0055 gives an
install on an IP address a trusted name, and serves the console there. What
it leaves on the old address is everything held outside the server's own
configuration: the agents on every computer, MeshCentral's agent address,
single sign-on's redirect URIs, Authentik's blueprint and the engine's
public URL. The same problem appears when an MSP changes its console's
name (a new domain, a merger, a rebrand). This ADR decides how all of it
moves.

### What holds the address on each computer
Each computer runs up to three agents, and each keeps the address it was
installed with.

* **EasyRMM's agent**: `server` in `agent.json` (`Config.Server` in
  `agent/state/state.go`), and in `pending.json` while it waits for
  approval. The service builds one client from it at start (`run` in
  `agent/cmd/easyrmm-agent/main.go`); heartbeats, jobs, updates and
  MeshAgent's downloads use that client, and the uninstaller builds its own
  from the same field (`removal.go`). Nothing changes it after enrollment:
  `install` with another server refuses ("run uninstall first", `main.go`).
  `SaveConfig` writes only the fields the running build knows, so an older
  build drops any field added later. The agent trusts the system's roots,
  or with `--ca-file` only that file (`client.New` in
  `agent/client/client.go` replaces `RootCAs`); ADR-0055 (5b1) makes that
  both for DNS names and keeps the file alone for IP addresses.
  `ParseServer` allows plain `http` on loopback, for tests.
* **MeshAgent**: `MeshServer=wss://<name>:<port>/agent.ashx` in
  `meshagent.msh` beside its executable (`settings()` in
  `agent/meshagent/meshagent.go`). EasyRMM's agent installs that file as the
  server fetched it from MeshCentral and signed it (`installMesh` in
  `agent/runner/runner.go`; `SignDownload` in
  `internal/agentproto/download.go`), already edits one line of it before
  writing (`WithServiceName`), and starts MeshAgent with no arguments
  (`spawn`). MeshCentral 1.3.1 writes the line from its `cert` setting and
  `aliasPort` (`getMshFromRequest` and `getWebServerName` in its
  `webserver.js`), which EasyRMM sets from `EASYRMM_MESH_PUBLIC_URL`
  (`MeshServerConfig` in `server/internal/app/app.go`,
  `ServerConfig.Render` in `server/internal/meshcentral/config.go`).
  MeshAgent imports the `.msh` into its database at every start, unless a
  `.mshx` beside it is imported instead, and `--name=value` arguments
  override what it holds (`importSettings` and the argument loop in
  `meshcore/agentcore.c` of MeshAgent's repository, read at its main
  branch; the build MeshCentral 1.3.1 ships was not checked). `MeshServer`
  and `ServerID` may each be a comma-separated list, tried in turn.
* **MeshAgent's pin**: `ServerID` in the same file is the hash of
  MeshCentral's agent certificate (`agentCertificateHashBase64`). MeshCentral
  makes that certificate only when it has none (`MeshCentralAgentServer`,
  generated when `r.agent == null` in its `certoperations.js`), so a new
  `cert` name keeps it. A new name does make MeshCentral issue itself a new
  web certificate and a new code-signing certificate (`forceWebCertGen`,
  `forceCodeCertGen`). A `cert` without a dot puts MeshCentral in LAN-only
  mode, where the `.msh` says `MeshServer=local` (`meshcentral.js`).
  `Render` never sets `agentSignLock`.
* **The EasyPatch agent**: `ServerUrl` in its state (`AgentState` in
  `easypatch/agent/EasyPatch.Agent.Core/State/AgentState.cs`), set only at
  enrollment (`EnrollmentManager.cs`), and in its bootstrap configuration
  beside the authority it may trust (`ServerCaCertificate`: the registry on
  Windows, `RegistryBootstrapConfigSource.cs`; `agent.conf` on Linux,
  `ConfFileBootstrapSource.cs`). Its `enroll` command refuses another
  server unless given `--force`, which unenrolls and discards the agent's
  identity (`Cli.cs`). EasyRMM's agent installed it with an instruction
  naming the engine's public URL, whatever address EasyRMM's agent itself
  uses (`install.go` in `server/internal/easypatch`), and reports its
  version and address in the inventory (`agent/inventory/easypatch.go`).
  So in a DNS install, a computer enrolled through IP access has its
  EasyRMM agent on the address and its EasyPatch agent on the name. EasyRMM
  links an EasyPatch agent to its device only when its address is the
  engine's URL as EasyRMM reaches it, the engine's public URL or an
  imported EasyPatch's (`verify` in `server/internal/easypatch/links.go`).

### MeshCentral accepts one certificate
MeshCentral 1.3.1 lets a MeshAgent in only when the hash of the TLS
certificate the agent reports having seen is that of the certificate it
last read from `certUrl`, or of its own default web certificate, which
EasyRMM's edge never serves (the agent authentication request in
`meshagent.js`; `webserver.js`; `updateProxyCertificates` in
`meshcentral.js`). Every other agent is held. MeshAgents therefore cannot
use two addresses with two certificates at the same time, even though
MeshAgent itself accepts a list. Today they use one: every `.msh` names
MeshCentral's `cert`, whatever console origin installed the device
([docker.md](../../deployment/docker.md): "MeshAgent on each device keeps
using the MeshCentral name").

MeshCentral reads `certUrl` with its `cert` name as the TLS server name
(`loadCertificate` in `certoperations.js`, called from `meshcentral.js`
with `settings.cert`). ADR-0055 ("MeshCentral's name") makes that read get
exactly the certificate agents get for the name, in every mode, and holds
each change of it until 3 minutes after MeshCentral's last read. `certUrl`'s
port is MeshCentral's when it differs from the console's: 4443 on an IP
install (`defaultCertURL` in `server/internal/config/config.go`).

Browsers meet a second check: MeshCentral opens `control.ashx` only for an
`Origin` whose host is its `cert` name, unless the domain's `allowedOrigin`
lists others (`CheckWebServerOriginName` in `webserver.js`); the gateway
passes the browser's `Origin` through (`server/internal/remote/gateway.go`).
The fix this ADR needs first writes that list.

### The name elsewhere in the deployment
| What | Where | Today |
|---|---|---|
| Routing and certificates | `Config.Origins` (`server/internal/config/origins.go`), `newRouter` (`server/internal/app/origins.go`), `edge.certificates` | Built at start; ADR-0055 rebuilds them for added names |
| CSRF origin check | `httpapi.NewSessions`, given every console origin (`Build`) | At start |
| CSP `frame-src`, MeshCentral's `allowedFramingOrigins` | `Handler`, `MeshServerConfig` | At start |
| Install commands | `enrollapi.New` (the public URL first), `agentapi.New` (a script per origin) | At start; ADR-0055 renders them again |
| Links in email | `auth.Config.PublicURL` (password reset, `server/internal/auth/service.go`) | The public URL |
| Authenticator issuer | `EasyRMM (<host>)` (`Build`) | The public URL's host |
| Security keys and passkeys | `configureWebAuthn` (`server/internal/auth/webauthn.go`): relying party ID the public URL's host, one origin; `user_webauthn_credentials` (`server/migrations/00015_webauthn.sql`) keeps no relying party ID. Passkey sign-in needs no password (`BeginPasskeyLogin`) | A new host makes every key useless ([ADR-0032](0032-webauthn-passkeys.md), [docker.md](../../deployment/docker.md)) |
| Single sign-on | One redirect URI, `<public URL>/api/v1/auth/sso/callback` (`CallbackPath`, `server/internal/sso/sso.go`), registered at each provider; buttons on other origins point there | The public URL |
| Authentik | Its blueprint takes `public_url` from `EASYRMM_PUBLIC_URL` (`!Env`) for the redirect URI (strict), the enrollment flow's last redirect (`target_static`) and the application's launch link (`meta_launch_url`) (`docker/authentik/blueprints/easyrmm.yaml`). Authentik 2026.8.5's worker applies a blueprint again only when the file's own bytes change (`check_blueprint_v1_file` and the file watcher in `authentik/blueprints/v1/tasks.py`); `authentik-setup` runs once per start and only waits for it (`docker/authentik/setup.py`) | `.env`, but a changed `.env` alone is never applied |
| The engine | `EasyPatch__PublicUrl: ${EASYRMM_PUBLIC_URL}` (`deploy/docker-compose.yml`): its server-info, which EasyRMM reads for install instructions and link matching, and links in its alert messages (`AlertEngine.cs`, `NotificationEndpoints.cs`) | `.env` |
| An imported EasyPatch's names | `EASYRMM_PATCHING_AGENT_HOSTNAMES`: agent paths served, everything else redirected to the console (`AgentHost` in `server/internal/easypatch/agentedge.go`) | `.env` |
| Audit forwarding | The syslog `HOSTNAME` (`auditfwd.New`) | The public URL's host |
| `easyrmm-server recover` | Its sign-in link (`server/internal/app/recover.go`) | The public URL |
| `setup.sh --upgrade` | Reads both URLs from `.env` (`deploy/scripts/setup.sh`) | `.env` |

### What vouches for the server
* An EasyRMM agent signs each request with its device key over the method,
  path, time, a single-use nonce and the body's hash; the host it dialled
  is not part of it (`message` in `internal/agentproto/agentproto.go`).
  The server's answers are vouched for by TLS against the agent's roots,
  and its instructions by the job key. Agents pin no TLS key. A name that
  resolves elsewhere for some computers (a hijacked or lapsed domain,
  split-horizon DNS gone wrong) with a certificate the agent trusts is
  therefore believed for TLS; only the job key tells this server from
  another.
* An address is reached through the internal authority alone (the CA
  file), a name also through the system's roots (5b1).
* The EasyPatch agent signs its requests (`AgentApiClient.cs`), but the
  engine's answers and jobs are not signed; only agent updates are
  checked, against release keys built into the agent (`ReleaseKeyRing.cs`).
  Whoever answers TLS for its address can give it jobs.

## Decision

### What a move is
* **A move takes the deployment from one name pair to another**: a console
  name and its MeshCentral name, such as `rmm.example.net` and
  `mesh.rmm.example.net` to `rmm.example.com` and `mesh.rmm.example.com`,
  or `203.0.113.10` and `203.0.113.10:4443` to a name pair. One move at a
  time.
* **Its old addresses**, the ones agents are moved from: the old pair; on
  an install whose public URL is an IP address, also every address IP
  access serves. On a DNS install, IP access's addresses are left alone:
  they are the way in when DNS fails (ADR-0016), and agents enrolled
  through them stay on them (their EasyPatch agents, on the old name,
  move).
* **The new pair must be trusted and reachable first**, as ADR-0055
  defines them (5b3): this server holds a Let's Encrypt certificate for
  both names and has reached itself through them, and the daily check or a
  browser has confirmed it recently. ADR-0055 allows one added pair on an
  IP install; this ADR lets a DNS install add one the same way, for a
  move. The MeshCentral name must be on the same site as the console's (as
  `validateMesh` requires) and contain a dot (MeshCentral's LAN-only rule
  above).
* **Nobody can move EasyRMM's agents to a server that does not hold the
  job key.** Each agent moves only after it has checked, from its own
  network, that the new address answers with a job key signature over a
  fresh nonce of its own (below). A super administrator chooses *which* of
  this server's trusted names agents use, never another server.
* **Old addresses keep working** for everything that still uses them until
  the old name is removed, which is the cut-off.
* **`name_moves`**, a platform table like `settings`, outside row-level
  security: one row per move, with the pairs it moves from and to, who
  started it and how (console or host), when each step was taken and by
  whom, any override with its list, and how it ended (finished, or moved
  back). The **primary** pair is the target of the last move not moved
  back, or `.env`'s when there has been none. The **move generation**, a
  number kept beside it, goes up with every step 1 or 2, a **Move back**'s
  included; the updater reads it (Rollback, below). Every server on the
  database reloads both on `NOTIFY`, as ADR-0055's certificates do.

### The steps
A move has five steps. The console takes them in this order and shows,
for each, what it changes, what it is waiting for and what is still on the
old name.

| Step | What changes | Waits for |
|---|---|---|
| 1. **Agents** | The new pair becomes the primary for everything new. EasyRMM's agents and EasyPatch agents on the old addresses move as they check in | The new pair trusted, and reachable when checked again now; every device seen in the last 30 days able to move, or **Start anyway**; on a DNS install, until slice 7, no security key or passkey registered |
| 2. **Remote access** | MeshCentral moves to the new MeshCentral name; MeshAgents follow through their EasyRMM agent. Skipped when remote access is off | Step 1 |
| 3. **Sign-in** | Each single sign-on provider confirmed at the new name; Authentik's redirect URI added | Step 1 |
| 4. **Browsers** | The old console name sends browsers to the new one | Steps 1 and 3; nobody left whose only second factor is a key that has not worked at the new name, or **Redirect anyway** |
| 5. **Remove the old name** | The old pair is no longer served | Steps 1 to 4; the updater's rollback window open at step 1 closed, plus an hour; nothing seen in the last 30 days still on it, or **Remove anyway** |

**Move back** is offered until step 5: a move to the old pair, which is
still trusted. Agents, MeshAgents and EasyPatch agents follow it the way
they followed the move; browsers are no longer redirected; nothing done at
providers has to be undone, since the old redirect URI stays registered.
Step 2 and its reversal are at least 10 minutes apart, ADR-0055's rule for
MeshCentral's name.

### Step 1: what becomes the new name at once
From step 1 the primary pair is the new one for the following. On an IP
install ADR-0055 already gave the added name the first four (5b3); on a
DNS install they change here.

* install commands, with the new name's command first (rendered again, as
  ADR-0055 does for an added name);
* links in email and `easyrmm-server recover`'s link;
* the authenticator issuer, for new enrolments (existing entries keep
  their label and keep working);
* the relying party new security keys are registered under (Passkeys,
  below);
* EasyPatch install instructions: they name EasyRMM's primary console
  origin, read from `name_moves`, not the engine's `PublicUrl` (amends
  [ADR-0031](0031-easypatch-agent-install.md)), and link matching
  (`verify` in `links.go`) accepts every console origin the server serves,
  old names included;
* the audit forwarder's `HOSTNAME`. The move's own audit record, which
  collectors receive before the change, names both.

The old console name stays a console origin (CSRF check, framing, its
install command, sign-in) until step 4, and serves agents until step 5.

### EasyRMM's agent: a signed move and a check from the computer
* **Offered by capability.** The agent reports in its heartbeat that it
  understands move instructions, as 5b1's agent reports trust
  instructions, and the server sends one only to a build that reported it
  (ADR-0009 as amended). It is offered, while a move is in progress, to a
  device whose requests arrive on an old address (the route ADR-0055
  records), and again an hour after a failure, or at once on **Try
  again**.
* **The instruction**, `move` in the heartbeat answer, signed with the job
  key under its own context (`EASYRMM-MOVE-SIG-V1`) like every
  instruction, over `{"v", "id", "deviceId", "agent": "easyrmm", "from",
  "to", "nonce", "issuedAt"}`, where `nonce` is the heartbeat request's
  own, as MeshAgent's downloads are bound to theirs (`SignDownload`). The
  agent refuses one for another device; for another nonce than the
  request it sent; with unknown fields; whose `from` is not its current
  server; whose `to` is not an `https` origin (stricter than `ParseServer`:
  no plain `http`, loopback included); whose `issuedAt` is not later than
  that of the last move it applied; and whose signature does not verify
  with a key it trusts (ADR-0057). A recorded answer is therefore useless
  in any other exchange.
* **The check, at the new address.** The agent sends `POST
  /api/agent/v1/address` to `to`, signed with its device key as every
  request is, with `{"address": to}` in the body, following no redirect.
  The server answers with a confirmation signed with the job key
  (`EASYRMM-ADDRESS-SIG-V1`) over the device, the request's nonce and the
  address. It signs only for an enrolled device, for an address it serves
  agents on, and when the request's `Host` is that address. The agent
  verifies it with the keys it trusts, against its own nonce and the
  address it dialled. Any other answer, a `404` from a server that
  predates this ADR included, is a failed check.
* **The switch.** Once no job and no EasyPatch install is running (as an
  update waits, `Busy` in `agent/update/update.go`), the agent writes
  `agent.json` with the new `server`, adds the address it left to the
  addresses kept in `address.json` (the last one is the previous address)
  with the move's `issuedAt`, a file of its own that older builds
  neither read nor rewrite (so a downgrade and an update back keep it),
  and restarts its service, as after an update (ADR-0027). The server sees
  the device's next heartbeat arrive on the new name.
* **Failures** (the name does not resolve on that network, a firewall, a
  certificate the agent does not trust, a check that fails) leave the agent
  where it was. It reports them, signed, on `POST /api/agent/v1/move` at
  its current address, a path of its own as removal reports are
  (ADR-0050), so no heartbeat field depends on the server's level. A
  confirmation that does not verify is audited and raises an alert: it
  means the new name reaches another party from that device.
* **Agents that cannot move**: builds that have not reported the
  capability ignore `move` (answers are read leniently). Step 1 is refused
  while a device seen in the last 30 days on an old address runs one, or
  trusts only its CA file and would not trust the new name's certificate
  (5b1). The page lists them, offers **Update these agents** (ADR-0027's
  rollout) and, with step-up, **Start anyway**, for the agents the rollout
  cannot reach: those that cannot update themselves (ADR-0027), and
  rollouts set to *When asked* or *Off*. The list is kept with the move.
* **Agents waiting for approval** keep asking on the old address, which
  serves enrollment until step 5; once approved, they move like the others.

### Three other ways an agent's address changes
Each ends with the same check, so the job key always decides.

* **Falling back.** When every request to its server has failed for an
  hour and `address.json` holds a previous address, the agent runs the
  check there; if it passes, it switches back, waiting for running work as
  above, and reports it on `/move`. This covers a restore, onto a version
  with this ADR, of a backup from before the new name was added (Rollback,
  below). Ordinary downtime does not trigger it: then the previous address
  fails too. A lapsed old domain cannot use it: whoever holds it cannot
  sign. A server from before this ADR answers `404`, so the agent stays.
* **By hand.** `easyrmm-agent set-server https://rmm.example.com`, run as
  root or administrator on the computer, runs the check and switches;
  `https` only. It is for a computer that comes back after the old name
  was removed. Its MeshAgent has then been held since step 2, so
  MeshCentral's terminal cannot reach it: the command is run through Group
  Policy, Intune or at the computer (it carries no secret). ADR-0057's
  `trust-key` is run the same way. The agent reports the change on `/move`,
  and the server audits it. `easyrmm-agent status` shows the address and
  the previous one.
* **Installing again.** An install command run on a computer whose agent
  is enrolled at another address: when that address is one the agent
  moved from (`address.json`), `install` says "Already enrolled; this
  server is now at <address>" and succeeds, even after the old name is
  removed. Otherwise it runs the check there: if this same server confirms
  it for this device, it switches as `set-server` does; if not, it refuses
  as today. Scripts that run the install command at every start (Group
  Policy, Intune) so keep working through a move.

### The EasyPatch agent
* **Its own instruction.** While a move is in progress, the server offers
  `move` with `"agent": "easypatch"` to every device whose EasyPatch agent
  reports an old address of the move in the inventory,
  whatever address the device's EasyRMM agent uses. That covers devices
  enrolled through IP access in a DNS install, whose EasyRMM agent does
  not move, and EasyPatch agents whose earlier move failed. It needs both
  capabilities: EasyRMM's agent's, and the EasyPatch agent's `set-server`,
  which its `status --json` lists and EasyRMM's agent passes on in the
  inventory (a request field added after level 2).
* **What EasyRMM's agent does with it**: the same checks of the
  instruction, with `from` the EasyPatch agent's current address; the
  address check at `to`, through a client trusting what 5b1 gives that kind
  of address; then the EasyPatch agent's new `set-server <url>` command, on
  Windows and Linux. That command checks in with the engine at the new
  address with the EasyPatch agent's own credential, then writes
  `ServerUrl` in its state and its bootstrap configuration, keeping the
  authority it trusts, and restarts its service. The result goes to
  `/move`; a failure is offered again after an hour.
* **After EasyRMM's agent changes its own address** (a move, a fall-back,
  by hand), it moves the EasyPatch agent at once when that agent is on the
  address it left, with the check it has just made.
* **The address check comes first** because the EasyPatch agent believes
  any party that answers TLS for its address (Context): its own check-in
  proves only that something answered.
* EasyPatch agents from before `set-server` stay on the old name; step 1
  lists them as **update the EasyPatch agent** (the engine's automatic
  agent updates). EasyPatch agents on an imported EasyPatch's names
  ([ADR-0045](0045-importing-a-standalone-easypatch.md)) are not on an
  old address and are left there.

### MeshAgent follows MeshCentral's name
MeshAgent cannot be moved one device at a time (MeshCentral accepts one
certificate), so it does not get an instruction of its own. A standing
rule replaces it:

* **The heartbeat answer names MeshCentral's agent address** (`meshAgent`
  gains `server`: `wss://` and MeshCentral's `cert` and `aliasPort`, what
  MeshCentral writes in every `.msh`). The agent acts only when the field
  is present, so a server without it changes nothing. When it differs
  from the `MeshServer` line of the installed `meshagent.msh`, the agent
  fetches the settings again through the signed download it already uses,
  requires that their `MeshServer` is the address named and their
  `ServerID` the installed one, replaces only the `MeshServer` line, and
  restarts MeshAgent. At most once in 10 minutes. It refuses, and reports,
  when a `.mshx` lies beside MeshAgent, which would be imported instead.
  The answer's field is only a hint: what is written comes from the signed
  download, and MeshAgent's pin and device group never change.
* **Step 2** writes MeshCentral's `config.json` with the new name as
  `cert` and its port as `aliasPort`; MeshCentral's start script restarts
  it (`docker/meshcentral/start.sh`), which ends open remote sessions (the
  page says so before the operator confirms). It reads `certUrl` as it
  starts, with the new name as the server name, so it gets that name's
  certificate (ADR-0055, "MeshCentral's name"). From then on MeshAgents on
  the old address are held, and each moves at its EasyRMM agent's next
  heartbeat: within a minute or two for computers that are on. A computer
  that is off moves when it comes back, if its EasyRMM agent can still
  reach the server (until step 5).
* **`certUrl`'s port follows MeshCentral's** (`defaultCertURL`: 4443 to
  443 when an IP install moves to a name). An `EASYRMM_MESH_CERT_URL` set
  in `.env` is kept, and the page warns that it must reach the new name.
  Everything else about the read is ADR-0055's.
* **`allowedOrigin`** comes from the fix this ADR needs first, which
  derives it from the MeshCentral origins served, so the old MeshCentral
  name stays in it until step 5 with no work here.
* **MeshCentral's new certificates**: its own web certificate is never
  served by the edge. Whether its new code-signing certificate makes
  Windows MeshAgents download a re-signed build is checked in slice 5, and
  the page says so before step 2 if it does.
* **Why step 2 waits for the operator**: a device whose EasyRMM agent
  cannot reach the new names loses remote access at step 2. The page shows
  how many devices have moved and lists those whose check failed, with the
  reason, before it is taken.

The rule also repairs what is broken today: an operator who changes
`EASYRMM_MESH_PUBLIC_URL` by hand strands every MeshAgent; with the rule
they follow.

### Step 3: single sign-on and Authentik
* **One redirect URI per console name**: `<name>/api/v1/auth/sso/callback`
  (amends [ADR-0034](0034-oidc-single-sign-on.md)). A sign-in uses the
  callback on the name it starts at when that name is **confirmed** for
  the provider; otherwise its buttons point to a name that is, as they
  point to the public URL from other origins today.
* **Confirmed** means a sign-in through the provider completed at that
  name, which can only happen once the provider accepts that redirect URI.
  The page shows, for each provider, the exact URI to register and **Test
  at rmm.example.com**, which runs a sign-in there. Any real sign-in that
  completes there confirms it too. The old name stays confirmed.
* **Authentik** (amends [ADR-0044](0044-authentik-when-chosen.md)):
  * The server writes the console's names into
    `<data root>/authentik/names/`, one file each: `primary` and, from
    step 1 until step 5, `old`, and rewrites them at each start and each
    change. The directory is mounted read-write into the server and
    read-only into Authentik's containers; `setup.sh` writes `primary`
    from `.env` when it is missing, so Authentik never starts without it.
  * The blueprint reads them with `!File`. Because `!If` in a list item
    leaves a `null` item (`If.resolve` in Authentik 2026.8.5's
    `authentik/blueprints/v1/common.py`), it chooses the whole
    `redirect_uris` list: `!If [!File [<old>, ""], [<old entry>, <primary
    entry>], [<primary entry>]]`. The enrollment flow's last redirect
    (`target_static`) and the application's `meta_launch_url` read
    `primary` too; nothing in the blueprint reads `EASYRMM_PUBLIC_URL` any
    more.
  * Authentik's worker applies a blueprint again only when the blueprint
    file changes (Context), so `authentik-setup` stays running (`restart:
    unless-stopped`): after its present work it watches the names
    directory and runs `ak apply_blueprint` on EasyRMM's blueprint when a
    file there changes. The server keeps only the power to write the two
    files; it cannot reach Authentik's management. A compromised server
    could name a host of its own in them, but it already holds the client
    secret those codes need.
  * The test sign-in at the new name confirms Authentik like any
    provider.
* **Authentik's own name does not move.** `EASYRMM_AUTHENTIK_HOSTNAME` is
  a DNS name even on an IP install, served by EasyRMM's edge
  (`server/internal/config/authentik.go`), and its users' security keys
  are bound to it. Moving it is left out (open question).

### Step 4: browsers
* **The old console name redirects** every browser request to the same
  path on the new name, as an imported EasyPatch's names redirect to the
  console (`AgentHost`), except agent paths, ACME challenges and
  `/.well-known/webauthn`. Sessions are per host (`__Host-` cookies), so
  people sign in again at the new name; the page says so.
* **IP access's addresses are never redirected**: they are there for when
  DNS fails (ADR-0016).
* Step 4 waits for every enabled provider to be confirmed at the new name
  (a redirect would otherwise send people round between the two), and for
  the passkey list below to be empty, or **Redirect anyway**.

### Passkeys
An IP install had none before ADR-0055 added its name (browsers refuse
WebAuthn on addresses); keys registered since are under that name, which
is the new one, so the common case loses nothing. For a move between names
(slice 7; until then step 1 is refused on a DNS install with keys):

* **A credential keeps the relying party ID it was registered under**:
  `user_webauthn_credentials` gains `rp_id`, filled by the migration with
  the ID in force, and `last_used_origin`. The server keeps one
  `webauthn.WebAuthn` per ID in use. New keys are registered at the primary
  name, under its ID (amends [ADR-0032](0032-webauthn-passkeys.md)).
* **Origins**: until step 4, keys under the old ID are accepted from the
  old and the new console origins, keys under the new ID from the new
  one. From step 4, every ID accepts only the console's current origins,
  so an assertion made at the old name, which is a phishing site once the
  domain lapses, is refused, passkey sign-in (which asks no password)
  included.
* **Old keys work at the new name** through Related Origin Requests: the
  old name serves `/.well-known/webauthn` listing the console's current
  origins, built with `protocol.NewRelatedOrigins` and served at
  `protocol.WellKnownPathWebAuthn` (go-webauthn v0.18.2, which `go.mod`
  pins; it has no configuration field for this, and
  `(*WebAuthn).RelatedOrigins` would list the configured origins, the old
  one included). A browser asks for one ID at a time, so the second-factor
  step asks for the person's keys under the new ID, then under the old
  one if those are all they have; passkey sign-in offers **Use a passkey
  from rmm.example.net** beside the usual button.
* **Browser support**, as the review recorded it: Chrome and Edge 128 and
  later, Safari 18 and later, Firefox 152 and later after a prompt;
  Firefox refuses it under conditional mediation, so the old ID is asked
  for only from the button, never from autofill. Elsewhere people use
  their authenticator app or a recovery code, or register a key again.
* **Step 4's list**: people whose only second factor is a key under the
  old ID that has not yet worked at the new name (`last_used_origin`). On
  a browser without support, or one that declines the prompt, they would
  be locked out once the old name redirects. So step 4 waits while the
  list is not empty, as ADR-0055's **Remove name** does for keys; each
  must add an authenticator app or a key at the new name, or a super
  administrator resets their second factor. **Redirect anyway** (step-up)
  is the override.
* **Everyone with keys only under the old ID is asked to add one** at the
  new name, on their account page and in a banner after sign-in. The page
  counts the keys left under the old ID and when each was last used.
* **The old name keeps serving `/.well-known/webauthn`** while any key is
  registered under it, also after step 5. Removing the name for good asks
  first to remove those keys, listing their owners; people left without a
  second factor are listed apart, for a super administrator to reset
  theirs.

### Step 5: removing the old name
* **When**: once the **Roll back** that the updater's status offered when
  step 1 was taken, if any, has expired (its "until when", ADR-0052,
  recorded with the move at step 1), plus an hour;
  and when no device seen in the last 30 days still has an EasyRMM agent,
  MeshAgent or EasyPatch agent on an old address, and no agent waits for
  approval there. Otherwise the page lists them and **Remove anyway**
  (step-up) is the override. The wait is read, not copied: a forced
  rollback (`--strand-agents`, below) before it strands only the agents
  that had moved, never those still on the old name.
* **What it does**: the old pair is no longer served (421
  `name_retired`, with the command that moves a computer by hand), its
  certificate is no longer renewed unless passkeys still need its
  `/.well-known/webauthn` (above), and **Move back** is gone. The move is
  finished.
* **An old IP address** stays served while IP access is on (the default,
  ADR-0016), so a computer that never moved keeps its EasyRMM agent; its
  MeshAgent follows MeshCentral's name like every other and connects only
  if the computer can reach it. With `EASYRMM_IP_ACCESS=false` the address
  is an old address like a name, and step 5 removes it.
* **Install commands already handed out** (scripts, Group Policy, Intune,
  packages' `install.conf` and transforms from feature 6) name the old
  address. The page says so at step 1 and again before step 5.
* **EasyPatch agents left on the old name** are listed first, with why:
  once the old domain lapses, whoever holds it can give them jobs
  (Context).

### Moving from an IP address to a name
The case the plan builds feature 5 around: `EASYRMM_PUBLIC_URL` is
`https://203.0.113.10`, MeshCentral is on `https://203.0.113.10:4443`, the
mode is `internal` and IP access is on. ADR-0055 added `rmm.example.com`
and `mesh.rmm.example.com` with Let's Encrypt; the console already works
there, with passkeys.

1. **Agents**: EasyRMM's agents trust their CA file and, for DNS names,
   the system's roots too (5b1); each checks `https://rmm.example.com`
   against Let's Encrypt's chain and the job key, moves, and moves its
   EasyPatch agent, which trusts the system's store.
2. **Remote access**: MeshCentral's `cert` becomes `mesh.rmm.example.com`,
   its port 443, and `certUrl` follows; MeshAgents follow within a
   heartbeat. Remote sessions from the IP console still open on
   `https://203.0.113.10:4443`, through `allowedOrigin`.
3. **Sign-in**: each provider confirmed at the name; Authentik's redirect
   URI added.
4. **Browsers**: nothing to redirect: the IP console is IP access.
5. **Finish**: nothing is removed while IP access is on; computers that
   never moved keep their EasyRMM agent on the address.

Nothing is lost: keys registered since the name was added are already
under it, and old authenticator app entries keep working. A customer's
firewall that allows the server's address still matches when the name
resolves to it; MeshAgent's port changes from 4443 to 443, which the page
says at step 2, with every address and port computers must reach.

### Names in `.env`
`EASYRMM_PUBLIC_URL` and `EASYRMM_MESH_PUBLIC_URL` stay in `.env` as the
pair an install starts with.

* **A console move does not change `.env`**: the server cannot write the
  host's configuration, and the updater takes nothing from it but a
  version (ADR-0052). Once a move is finished the page shows the two lines
  to put in `.env`, and why: `setup.sh --upgrade` and the engine's
  `EasyPatch__PublicUrl` read them. Until then `.env` naming the old pair
  changes nothing.
* **Recorded per server.** Each server records the pair its `.env` gave
  it, under an ID it makes at its first start and keeps in its data
  directory, beside its entry in ADR-0057's `server_instances`. A server
  compares its `.env` only with its own record, so servers whose `.env`s
  differ never undo each other's moves; the page warns while they differ.
* **A changed `.env` starts a move**: when a server's `.env` names another
  pair than it recorded, and that pair is not the primary, a move to it
  starts at step 1, recorded as started on the host. The pair `.env` named
  before is the old pair, and MeshCentral keeps its name until step 2, as
  in any move. Today that edit strands every agent; with this it moves
  them. The edit is root's on the host, so no step-up applies; each
  agent's own check still does, and the trust and reachability checks
  run as for any move: a pair that fails them is served as `.env` says,
  but no agent is offered a move to it until it passes.
* **Changed during a move**: back to the move's old pair, it is a **Move
  back** from the host; to a third pair, nothing starts, an alert names
  both, and the record keeps the earlier pair, so the change is acted on
  at the first start after the move ends.
* **Never while held.** A start while the updater's `hold` exists
  (ADR-0052) records and starts nothing; the comparison is made when the
  server is released, so an upgrade that rolls back leaves no trace.
* **Before slice 4**, a change of `EASYRMM_MESH_PUBLIC_URL` applies to
  MeshCentral at once, as today, and MeshAgents follow by slice 3's rule.
* **The engine's `EasyPatch__PublicUrl`** is no longer read by EasyRMM
  (step 1). What still reads it when slice 4 is built (today the links in
  the engine's alert messages, which ADR-0053's sender takes over) gets
  EasyRMM's primary name from EasyRMM instead, and the setting is removed
  once nothing reads it (ADR-0048's rule).
* **Moving to another IP address of this server** works the same way, when
  `EASYRMM_IP_ADDRESSES` lists both: an address the host has lost takes
  its agents with it unless they moved first.

### Precedence over ADR-0055
* **`.env` names a name ADR-0055 added**: ADR-0055's rule comes first (the
  name stops being an added one, `tls.name_superseded`), then the rule
  above starts a move to it.
* **`tls reset`** during a move ends it as **Move back** would, from the
  host and without step-up: the primary returns to `.env`'s pair, and
  MeshCentral to `.env`'s name if step 2 was taken. The new pair stops
  being trusted but keeps its agent route while devices seen in the last
  30 days use it (ADR-0055, "Recovery"), so agents that moved keep working
  and are offered the move back; their MeshAgents follow MeshCentral. After
  a finished move, its pair is the primary, not an added name, and `tls
  reset` keeps trusting it (ADR-0055's reset otherwise stops trusting
  names added in the console).
* **A new pair that stops being trusted** during a move (renewals fail,
  reachability's grace ends) keeps its agent route as ADR-0055 says; no
  further moves to it are offered until it is trusted again, and the page
  says why.
* **Remove name** on a name of a move in progress, or on the primary, is
  refused: removing the old pair is step 5.

### Rollback
* **Move back** (above), until step 5.
* **The updater refuses Roll back across step 1 or 2 of a move** (amends
  [ADR-0052](0052-the-host-updater.md), as ADR-0057 does for a cut-over).
  Rolling back to a version from before this ADR leaves agents that moved
  facing a server that answers `/address` with `404`, so their fall-back
  fails, and MeshAgents on the new MeshCentral name held, since `certUrl`
  then gives the old name's certificate. So, as for the key generation:
  * at step 3 of an upgrade the updater records the move generation with
    the backup, by the same fixed `psql` query (0 for a database without
    `name_moves`; "unknown" if it cannot read it);
  * a rollback after a confirmed upgrade, once `hold` is written and the
    server reports it is held, reads the live generation and is refused
    when it is higher than the backup's, or when the backup's is unknown
    or missing and the live one is above 0, or when the live one cannot be
    read: "Agents moved to a new address after this backup, on <time>;
    restoring it would leave them unable to reach the server";
  * `--strand-agents`, on the host only, rolls back anyway (ADR-0057's
    override), and the record says so;
  * the updater's status gains the backup's move generation, so the
    console hides **Roll back**, with the reason, before anyone tries;
  * it ships no later than slice 4, which first takes step 1.
* **A rollback that crosses no step 1 or 2** restores the same move state,
  on a version that has this ADR; agents keep working.
* **A restore by hand** (`docs/operations/backup-restore.md`) is not
  refused by anything. Onto a version with this ADR, from a backup that
  predates the new name: agents that moved fall back within an hour, their
  EasyPatch agents with them, and MeshAgents follow MeshCentral's name.
  Onto a version from before this ADR: agents that moved are stranded
  (its `404` fails their fall-back) unless its `.env` names their
  address, and need `set-server` or a reinstall. The restore guide says to
  restore a backup from after the move's last step 1 or 2, and what each
  other case costs.
* **A job key rotation** (ADR-0057) is independent: each device follows each
  by its own statements, and the move is signed with the key from the
  device's report. The guide advises finishing one before starting the
  other.

### What a move does not protect against
* **A party with a certificate the agents trust for the new name**, which
  relays to this server, passes the check. It can then read what EasyRMM's
  agents send and drop what they receive, but forge no instruction. It can
  give EasyPatch agents jobs, since the engine's are unsigned (Context).
  A party with that position on today's DNS name has the same reach.
* **An IP install's agents** reach its address only through the internal
  authority. After the move they trust the system's roots for the name
  too (5b1), so any public authority that issues a certificate for it can
  stand there. The page recommends a CAA record naming Let's Encrypt with
  this server's account (`accounturi`), which ADR-0055's checks already
  read.
* **The old domain**: until step 5, agents still on it are as exposed to
  its loss as on any day: a lapsed old domain can relay them, and give
  their EasyPatch agents jobs. The page says to keep it registered until
  step 5, and as long as passkeys need it. After step 5 the server refuses
  the old name, so nothing can be relayed to it, but EasyPatch agents left
  there would take a new holder's jobs; step 5 lists them first.
* **A malicious super administrator** can move agents only between this
  server's own trusted names, and gains nothing a super administrator
  does not already have through jobs.

### Who
* **Super administrators** (`settings.manage`, platform-wide) see the page
  and take every step. Organization administrators see, under
  `device.view`, which of their devices are still on the old name.
* **Step-up authentication**, as ADR-0055 defines it ("Step-up
  authentication": a second factor confirmed within 5 minutes, or a fresh
  provider sign-in bound to the session's own user), for steps 1, 2, 4 and
  5, **Start anyway**, **Redirect anyway**, **Remove anyway**, **Move
  back** and removing keys under an old relying party ID.
* **Every super administrator is told** when a step is taken, an override
  is used, a move is moved back or finished, a move starts or is refused
  from `.env`, and when agents report a confirmation that does not verify:
  a notice in the console and an email through ADR-0053's sender once it
  exists.
* **On the host**: `.env` (above), `tls reset`, and `docker compose exec
  server easyrmm-server names status` to read the move's state. On the
  computer: `easyrmm-agent set-server`, as root or administrator.

### Console
* Settings → **Certificates** (ADR-0055): **Move here** on a trusted name
  opens the move's page: the five steps, each with what it changes and what
  it waits for; counts of devices moved, waiting (offline since when),
  unable to move (with the reason) and failed (with the reason), for each
  of the three agents; providers and their confirmation; keys left under
  the old relying party ID; **Move back**; **Try again** for failed
  devices.
* **Devices**: an *Address* column and filter (*Moved*, *Waiting*,
  *Cannot move*, *Check failed*); a device's page shows the address of each
  of its agents.
* A banner for super administrators while a move is in progress, and until
  `.env` names the primary.

### API
* `GET /api/v1/settings/names`: the names and their roles, the move in
  progress, each step's state and the counts.
* `POST /api/v1/settings/names/moves` (`to`), and on the move `POST
  …/steps/{remote-access|browsers|remove}`, `POST …/back`; `anyway: true`
  for the overrides; step-up as above. `POST
  /api/v1/devices/{id}/move/retry`. Super administrators only, except the
  device's retry (`device.edit`).
* `GET /api/v1/auth/sso/{id}/start?test=1` at a name runs the test
  sign-in.
* Agents: `POST /api/agent/v1/address` (the check) and `POST
  /api/agent/v1/move` (reports), both signed with the device key.

### Audit records
| Action | When | Details |
|---|---|---|
| `name_move.start` | Step 1, from the console or `.env` | From and to; devices able, waiting and unable to move; console or host; with **Start anyway**, the list |
| `name_move.step` | Steps 2 to 5 | The step; with an override, what it overrode |
| `name_move.back` | Moved back, from the console, `.env` or `tls reset` | The step it had reached |
| `name_move.env_refuse` | `.env` names a third pair during a move | Both pairs, the server |
| `name_move.keys_remove` | Keys under an old relying party ID removed | The name, how many, whose |
| `sso.provider_confirm` | A provider's sign-in first completes at a name | The provider and the name |
| `device.address_refuse` | An agent reports a confirmation that does not verify | The address, which agent, and the reason (recorded as the agent) |
| `device.address_set` | An agent reports a change made with `set-server` or `install` | From and to (recorded as the agent) |
| `device.address_fallback` | An agent fell back to its previous address | From and to (recorded as the agent) |

The names follow the existing actions' form (`device.remove`,
`sso.provider_update`). One device's successful move is not audited: its
row keeps when it moved, and the step records count them, as ADR-0057 does
for keys. Other failed checks are kept on the device, not in the audit
log. Forwarding ([ADR-0023](0023-audit-forwarding.md)) carries these like
any other.

### Where this departs from the plan
* **MeshAgent moves by a standing rule, in one step**, not by an
  instruction per device: MeshCentral 1.3.1 accepts one certificate, so
  MeshAgents cannot be split across two addresses. Step 2 is the
  operator's.
* **The cut-off is removing the old name**, offered once the updater's
  rollback window has closed and gated on what is still there, not a date.
* **Rollback across a move is refused**, as across a key rotation.
* **Passkeys**: the plan relied on Related Origin Requests alone. Keeping
  each key's relying party ID, narrowing origins at step 4 and asking
  people to register again lets the old name go eventually and keeps a
  lapsed domain from signing anyone in.
* **The engine's public URL is not moved**: EasyRMM stops depending on it.
* **Authentik's own name does not move**; only EasyRMM's redirect URI
  there, applied by a service that watches the names.
* **The plan's one signed instruction is two signatures**: the
  instruction, bound to the agent's request, and the new address's
  confirmation of a nonce the agent sent there.
* **Added**: the fall-back, `set-server` and an idempotent `install`; a
  hand edit of `.env` that starts a move instead of stranding agents; and
  MeshAgents that follow MeshCentral's name whatever changed it.
* **Signed settings (ADR-0058) are not how agents learn an address**: a
  setting can be set per organization or site, and an address must not be;
  a move needs a check against the new address from each computer, which a
  setting has no place for. The move travels as an instruction in the
  heartbeat answer.

## Testing
* **Unit** (`internal/agentproto`, the agent; also on CI's Windows runner,
  which runs `./agent/...` and `./internal/agentproto/...`):
  * the move instruction and the confirmation signed and verified, and
    each refusal: another device, another nonce, unknown fields, a `from`
    that is not the current address, a `to` in plain `http` (loopback
    included), an `issuedAt` not later than the last applied, an untrusted
    key, a key from before a rotation's cut-over with ADR-0057's ring;
  * the check following no redirect, and a `404` counted as a failure;
  * the switch waiting for running work, writing `agent.json` and
    `address.json` before the restart, and `address.json` surviving a
    `SaveConfig` that knows nothing of it;
  * the fall-back after an hour of failures, with a fake clock, and not
    during downtime of both; `set-server`, `install` again and `status`;
  * replacing only `MeshServer` in a `.msh` (Windows line endings, the
    service name line kept), refused when `ServerID` or the address
    differ, or a `.mshx` exists; nothing done without `meshAgent.server`.
* **The EasyPatch agent** (`EasyPatch.Agent.Tests`): `set-server` checks
  in at the new address before it writes; writes the state and the
  bootstrap configuration; keeps the authority; refuses an address that
  does not answer; lists itself in `status --json`. These tests run on
  Linux today (`scripts/build-agent.sh` in the EasyPatch agent workflow);
  slice 2 also runs them on the workflow's Windows runner, so that the
  registry is written in a test.
* **Integration** (PostgreSQL, race detector):
  * `name_moves`, the primary and the generation; the instruction offered
    only to devices on an old address with the capability, again after an
    hour; EasyPatch moves offered to devices whose EasyRMM agent stays on
    an IP-access address; the confirmation signed only for served
    addresses and a matching `Host`;
  * step 1's gates (capability, trust, reachability checked again, keys on
    a DNS install before slice 7) and **Start anyway**; step 4's passkey
    list and **Redirect anyway**; step 5's wait, from an updater status the
    test writes, and **Remove anyway**; **Move back**;
  * `.env` with **two servers on one database**: different `.env`s do not
    undo each other; one changed starts one move; changed back during the
    move moves back; a third pair is refused with an alert and acted on
    after the move; a held start does nothing;
  * `tls reset` during a move and after one; a new name that stops being
    trusted;
  * link matching across names; WebAuthn credentials under two relying
    party IDs, the well-known document, and an assertion with the old
    origin refused from step 4, passkey sign-in included;
  * a provider confirmed by a sign-in at a name (against the test OpenID
    provider already used, `ssotest`); permissions, step-up and the audit
    records.
* **Contract** (`scripts/contract/easypatch.sh`): slices 2 and 4 add a
  second public address, at which a simulated EasyPatch agent checks in
  after `set-server`, and check that install instructions name EasyRMM's
  address and that link matching follows. New Go packages get floors in
  `scripts/ci/check-coverage.sh` in the slice that adds them.
* **Console**: the move's page, the overrides' lists, the devices' column
  and filter, the re-registration prompt.
* **The bundle test, with real agents, every machine on the host's network
  only** (`--network host`, as `scripts/e2e/bundle.sh` runs its machine;
  never a bridge network), with ADR-0055's Pebble and BIND on host
  networking.
  * **From an address to a name**, starting from the IP install at
    `https://127.0.0.1`:
    1. machine 1, today's Debian machine with systemd, enrolled on the
       address, with its MeshAgent and EasyPatch agent; machine 2
       enrolled, then its agent stopped; machine 3 with the last release's
       agent, by its tag, checked against that release's `SHA256SUMS`;
    2. slice 1 and 2's check: `easyrmm-agent set-server` moves machine 1
       to the host's other address (IP access serves both, no DNS); its
       EasyPatch agent follows, and a patch scan reaches the engine there;
       then back;
    3. the name `rmm.example.com` added (ADR-0055), then step 1 through
       the API (through the console from slice 4's console work on):
       refused for machine 3 until the rollout updates it; machine 1's
       agent checks, moves, its EasyPatch agent follows, a script runs and
       a patch scan reaches the engine through the name;
    4. step 2: MeshCentral logs its new certificate, machine 1's MeshAgent
       reconnects on `mesh.rmm.example.com` and a remote session opens;
       one opens from the IP console too;
    5. machine 2 started: it moves, then its MeshAgent, within two
       heartbeats;
    6. a hijacked name: machine 2's `/etc/hosts` points the name at a
       server of the test's own in a network namespace joined by a veth
       pair (no bridge, as feature 7's webhook receiver), with a
       certificate machine 2 trusts and another key: the check fails, the
       agent stays, `device.address_refuse` is audited;
    7. **Move back**: every agent and MeshAgent follows; then the move
       again, and step 5 against an updater status the test writes (the
       test's only shortcut, recorded as such);
    8. `set-server` on a machine left on the removed name: it reaches the
       server again; the install command run again on a moved machine
       succeeds.
  * **From a name to a name**: a DNS install at `rmm.example.net`, moved
    to `rmm.example.com`, both from BIND and Pebble. Machine 4 is enrolled
    through IP access: its EasyRMM agent stays on the address and its
    EasyPatch agent moves to the new name. Machine 5 is enrolled through
    the name. With Chromium's virtual authenticator through Playwright
    (new to the suites): a key registered at the old name, used at the new
    one through the well-known document, refused at the old origin after
    step 4, and a key-only person listed by step 4 until they add one. If
    the virtual authenticator does not exercise Related Origin Requests,
    the slice says so and that check moves to the browsers by hand.
  * The machines share the host's network; if two MeshAgents cannot share
    one network namespace, the slice that finds it says how it was solved,
    never with a bridge network (as ADR-0057's test).
* **Single sign-on and Authentik**: the Authentik bundle test
  (`scripts/e2e/authentik.sh`) gains a move: without restarting Authentik,
  the provider's redirect URIs gain the new name's, its enrollment
  redirect and launch link follow, and a sign-in through Authentik there
  completes.
* **Rollback**: ADR-0052's upgrade test gains a real agent: after a
  confirmed upgrade, a name added and step 1 taken, **Roll back** is
  refused with the message and hidden in the console; `--strand-agents`
  rolls back and the record says so; a rollback with no step 1 or 2 since
  its backup goes ahead and the agent keeps working. The backup-restore
  drill (`scripts/drill/`) restores by hand, onto the same version, a
  backup from before the name was added: the agent falls back within the
  real hour; recorded in [drills.md](../../development/drills.md).
* **Unverified until the Windows end-to-end harness exists**, and marked
  so in IMPLEMENTATION_STATUS: the `.msh` rewrite with MeshAgent's Windows
  service restarted, and the EasyPatch agent's `set-server` writing the
  registry and restarting its service on a real Windows computer.
* **By hand**, recorded in IMPLEMENTATION_STATUS: real browsers (Chrome,
  Edge, Safari, Firefox) with a real security key and a synced passkey.
* **Then** the owner's next full instance with DNS: an IP install moved to
  its real name, with their Windows and Linux computers.

## Slices
Each merges, is verified on its own, and leaves nothing unused.

1. **The check, `set-server`, `install` again and the fall-back** (EasyRMM's
   agent and the server): `/address`, `/move`, `address.json`, the
   capability report, `status`. Useful alone: a computer is moved by hand
   between two addresses the server serves. Verified in the bundle by
   moving machine 1 between `https://127.0.0.1` and the host's other
   address.
2. **The EasyPatch agent's `set-server`** and its listing in `status
   --json`, and EasyRMM's agent running it after its own change of
   address. Verified in the same bundle step: machine 1's EasyPatch agent
   follows its `set-server`, the engine sees it check in at the other
   address and a patch scan completes there; and by the contract test.
3. **MeshAgent follows MeshCentral's name** (the rule above, `certUrl`'s
   port). Needs the `allowedOrigin` fix merged. Verified in the bundle by
   changing MeshCentral's address in `.env` and restarting the server: on
   the IP install only its port may change (`validateMesh` requires the
   same address), so `EASYRMM_MESH_PUBLIC_URL` and `EASYRMM_IP_MESH_PORT`
   move from 4443 to another port. The MeshAgents follow, which today they
   cannot.
4. **The move of agents** (step 1 and **Move back**): `name_moves` and the
   generation, the updater's refusal (released with or before it), the
   primary, a DNS install adding a name, the signed instruction for both
   agents, the failure reports, `.env` per server, the precedence over
   ADR-0055, link matching and install instructions from EasyRMM's names,
   the engine's `PublicUrl` no longer read, step-up, notices, the page and
   the devices' column, audit. Needs F0 and 5b1 to 5b3; the contract test.
5. **MeshCentral's move** (step 2), and the code-signing check above.
6. **Sign-in and browsers** (steps 3 and 4): redirect URIs per name,
   confirmation, Authentik's names files, the blueprint and the watching
   `authentik-setup`, the redirect.
7. **Passkeys on the new name**: `rp_id`, `last_used_origin`, one
   relying party per ID, the well-known document, origins narrowed from
   step 4, step 4's list, the prompts, the count. It lifts step 1's
   refusal on DNS installs with keys.
8. **Removing the old name** (step 5), its wait read from the updater's
   status, the restore guide, the drill, and the guide's page on moving.

Slices 1 to 6 complete the IP-to-name case.

## Consequences
* An install on an IP address gets agents, remote access, single sign-on
  and Authentik onto its name from the console, with no computer visited.
* A name can change without reinstalling anything; passkeys survive it in
  browsers that support Related Origin Requests, and everyone is asked to
  register again so the old name can go.
* No one can move EasyRMM's agents to a server without the job key, and
  each computer checks the new address itself before any of its agents
  moves.
* An IP install's agents trust the public roots for their new name, where
  they trusted one authority for the address.
* MeshAgents follow MeshCentral's name whatever changes it; remote access
  to a computer is interrupted for about a heartbeat at step 2.
* A hand edit of the names in `.env` moves agents instead of stranding
  them.
* The updater cannot roll back across a move's step 1 or 2 without
  `--strand-agents`.
* Install commands handed out before a move stop working on computers
  never enrolled when its old name is removed; on enrolled ones they keep
  working.
* The EasyPatch agent gains a command, and its older builds stay on the old
  name until updated. `authentik-setup` becomes a long-running service.
* Old names stay served, and their certificates renewed, until someone
  removes them; one that passkeys still use keeps serving one file.

## Alternatives considered
* **Signed settings for the address** (ADR-0058): above.
* **Moving MeshAgents device by device**: MeshAgent itself accepts several
  servers and server IDs, comma-separated and tried in turn
  (`agentcore.c`), so a `.msh` could name both addresses. The obstacle is
  MeshCentral, which holds whichever agents report a certificate other
  than the one it read from `certUrl`. Turning its check off
  (`ignoreAgentHashCheck`) would let a TLS-intercepting party read remote
  sessions.
* **One certificate naming both MeshCentral names during a move between
  names**: MeshAgents on either address would see the same certificate,
  so they could move one by one. It does not help the common case, since
  ADR-0055 keeps IP addresses on the internal authority; it would be a
  second mechanism beside the one that case needs, and it departs from
  ADR-0055's one certificate per name.
* **The server rewriting Authentik's blueprint**: the blueprint makes the
  flows and the second-factor requirement; a server that could write it
  could weaken sign-in. It writes only the names.
* **The server changing `.env` or Authentik through the updater**: the
  updater takes nothing but a version from the server (ADR-0052).
* **Serving old names for ever**: agents would never need to move, but a
  lapsed domain would stay an address every agent uses.
* **A second relying party ID only, without Related Origin Requests**: old
  keys would stop working at the new name at once.
* **Unsigned moves, trusting TLS**: TLS without a pinned key is what the
  job key exists not to rely on.
