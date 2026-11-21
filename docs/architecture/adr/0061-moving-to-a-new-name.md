# ADR-0061: Moving EasyRMM to a new name

* Status: Proposed (2026-11-21), revised after review. Not implemented.
* Builds on: ADR-0055 (proposed: Let's Encrypt in one step; when a name is
  trusted and reachable, 5b3; agent trust, 5b1; MeshCentral's name; `tls
  reset`; and its section "Step-up authentication", the one definition
  this ADR uses), ADR-0057 (proposed: rotating the job key; everything
  this ADR signs goes through its ring, and the rollback guard written with
  it covers moves too), [ADR-0009](0009-agent-protocol.md) as amended
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
  the updater's status, and its section "Rollback guards (amended
  2026-11-21)", added with ADR-0057, which refuses a rollback across a
  move and which this ADR cites rather than repeats).
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
  [ADR-0044](0044-authentik-when-chosen.md): `authentik-setup` stays
  running, validates the console's names from files the server writes and
  reconciles them into the blueprint instance's context, which the
  blueprint reads;
  [ADR-0031](0031-easypatch-agent-install.md): install instructions name
  EasyRMM's own address, not the engine's `PublicUrl`;
  ADR-0055: what
  wins when `.env`, `tls reset` or **Remove name** meet a move
  ("Precedence over ADR-0055", below).
* Part of [the feature plan](../feature-plan.md): feature 5, slice 5c. It
  comes last in the plan's order and needs F0 (ADR-0057) and 5b1 to 5b3
  (ADR-0055).

## Context
Feature 5 of the plan is Let's Encrypt in one step; ADR-0055 gives an
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
* **The new pair must be trusted and reachable first.** For names, as
  ADR-0055 defines them (5b3): this server holds a Let's Encrypt
  certificate for both and has reached itself through them, and the
  daily check or a browser has confirmed it recently. ADR-0055 allows one
  added pair on an IP install; this ADR lets a DNS install add one the
  same way, for a move. For an IP address, which no public authority
  certifies, trusted means served with a certificate from EasyRMM's
  internal authority, the trust agents on an IP install already use
  (ADR-0016; 5b1 keeps it for addresses). It counts as reachable when a
  browser loaded the console through it in the last 24 hours, or when
  the server reached itself through it; that self-check needs hairpin
  NAT, which ADR-0055 only warns about, so when neither holds step 1
  warns and does not refuse. Nothing depends on that check for safety:
  each agent's own `/address` check decides whether it moves. Step 1's
  gate checks whichever applies. The MeshCentral name must be on the same
  site as the console's (as `validateMesh` requires) and contain a dot
  (MeshCentral's LAN-only rule above).
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
  back, or the initial pair when there has been none, so a `.env` that
  changes on its own never changes the primary. Every server on the
  database reloads it on `NOTIFY`, as ADR-0055's certificates do.
* **The initial pair**, kept beside the rows, is written once, at the
  first start of slice 4's build: from that server's record ("Names in
  `.env`"), which slice 1 began keeping, so a `.env` edited just before
  the upgrade is not taken for the pair agents use. With no record, it
  is taken from `.env` only when no device has been seen in the last 30
  days, or every such device has a recorded origin (the origin of its
  signed requests, ADR-0055) that the server serves with that `.env`; a
  device seen with no recorded origin counts as not matching. Otherwise
  nothing is adopted until a super administrator, with step-up, chooses
  with **Confirm** between `.env`'s pair and an **agents' pair**:
  * **The agents' MeshCentral name.** At that start the server reads
    `cert` and `aliasPort` from MeshCentral's existing `config.json`
    once, before rendering it, and stores them in the database. With no
    `config.json` (remote access never on, or the folder lost), the
    agents' pairs use `.env`'s MeshCentral name, and the banner says so.
  * **The candidates**: each console origin the devices seen in the last
    30 days use, leaving out addresses IP access serves anyway (unless
    the public URL is itself an IP address), with its device count. Each
    is paired with that MeshCentral name and checked as `validateMesh`
    and MeshCentral's dot rule check a pair; one that fails is listed
    with the reason and cannot be chosen. When the devices are split,
    every candidate is listed.
  * **Until Confirm**: `config.json` is rendered as at every start
    (`Render` and `WriteConfig` in `server/internal/meshcentral`, with
    the `allowedOrigin` fix), with `cert`, `aliasPort` and `certUrl`'s
    port pinned to the stored MeshCentral name, and `allowedOrigin` and
    the framing origins built from every origin served. The server
    serves `.env`'s console as it does today, the candidates' console
    origins as agent routes, and the stored MeshCentral name with its
    route, so MeshAgents and `certUrl`'s read keep working; the edge
    listens on the stored `aliasPort` too, which covers an IP install
    whose `EASYRMM_IP_MESH_PORT` changed in the same jump. It refuses
    moves and offers, and shows an alert and a banner naming the pairs.
  * **Their certificates**: until Confirm, and afterwards while they are
    old addresses, the stored MeshCentral name and each candidate's
    console origin take the mode's source, as the primary does: in
    `acme` mode `acmeHosts` (`server/internal/app/edge.go`), and so
    autocert's host policy, gains them; in `internal` mode the authority
    issues for them; in `manual` mode they come from the operator's
    files, and the banner names any the files do not cover.
  * **The gates**: before Confirm is accepted, step 1's gates run against
    the chosen pair: every device seen in the last 30 days trusting its
    certificate, reachability (a warning for an IP target), `validateMesh`
    and the dot rule. A choice that fails is listed with the reason and
    cannot be chosen, as for the candidates above.
  * **What Confirm writes**, one rule for every choice: the chosen pair
    becomes the initial pair; for an agents' pair, that is the candidate
    origin and `https://<cert>:<aliasPort>`, and the stored pin is
    deleted. Every other candidate origin with devices seen in the last
    30 days becomes an old address of a move to the chosen pair, which
    Confirm records in `name_moves` with itself as step 1; so does the
    pinned MeshCentral name when `.env`'s pair is chosen and names
    another. Those old addresses are then handled exactly as a move's
    old name: served as agent routes, with their certificates and the
    stored `aliasPort`, while devices use them; their agents sent the
    ordinary move instruction; MeshCentral keeping the pinned name until
    step 2; and removed by step 5's rule. Confirm is audited as
    `name_move.initial`, naming the move it starts.
  * Choosing an agents' pair leaves `.env` naming another pair, which is
    then offered as below.
* **The move generation**, `moveGeneration`, a number kept beside it,
  changes with every step 1 or 2, a **Move back**'s included, and never
  goes backwards, even across a restore: each new value is the larger of
  the time in milliseconds and the last value plus one, the rule ADR-0052's
  "Rollback guards" sets for both values it guards. A database without
  `name_moves` has 0, the baseline. The updater reads it (Rollback,
  below).
* **Steps 1 and 2 are serialized against a rollback**, however they are
  taken (the console, `names move --to-env`, **Move back**, `tls
  reset`): each takes the move's advisory lock, checks inside it that
  the updater's `hold` file does not exist, by looking at the file, not
  at the flag the server refreshes every second (ADR-0052), and only then
  writes the step and the new generation, in the same transaction. A
  step begun before a rollback's hold has therefore either committed,
  and is seen by the rollback, or does not happen.

### The steps
A move has five steps. The console takes them in this order and shows,
for each, what it changes, what it is waiting for and what is still on the
old name.

| Step | What changes | Waits for |
|---|---|---|
| 1. **Agents** | The new pair becomes the primary for everything new. EasyRMM's agents and EasyPatch agents on the old addresses move as they check in | The new pair trusted, and reachable when checked again now (for an IP target, a warning if not, never a wait); every device seen in the last 30 days able to move, or **Start anyway**; on a DNS install, until slice 7, no security key or passkey registered (and none registered until the move ends) |
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
  below; on a DNS install before slice 7 no key is registered during a
  move);
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
* **Offered by capability.** A build that parses the instruction (slice 4,
  not before) reports `move.easyrmm` among the instructions it
  understands, as 5b1's agent reports trust instructions, and the server
  sends one only to a build that reported it (ADR-0009 as amended). It is
  offered to a device whose requests arrive on an old address (the route
  ADR-0055 records) of the latest move not moved back: during the move,
  and after it has finished for as long as that address is still served
  (an IP address IP access keeps), so an agent that fell back to it is
  moved again. After a failure it is offered again an hour later, or at
  once on **Try again**.
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
  server that answers `/move` with `404` (an older one, or one rolled
  back) gets nothing more: the agent drops the report and goes on, with
  no retry loop (ADR-0009). A confirmation that does not verify is
  audited and raises an alert: it means the new name reaches another
  party from that device.
* **Agents that cannot move**: builds that have not reported
  `move.easyrmm` are never sent one (and would ignore it: answers are
  read leniently). Step 1 is refused while a device seen in the last 30
  days on an old address runs one, or would not trust the target's
  certificate by what it trusts (5b1): one that trusts only its CA file,
  on a move to a name with a public certificate, or one that trusts only
  the system's roots, such as the agents of an `acme` install, on a move
  to an IP address served by the internal authority. The page lists
  them, offers **Update these agents** (ADR-0027's
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
* **Installing again.** `easyrmm-agent install` run on a computer whose
  agent is enrolled at another address: when that address is one the
  agent moved from (`address.json`), it says "Already enrolled; this
  server is now at <address>" and succeeds. Otherwise it runs the check
  there: if this same server confirms it for this device, it switches as
  `set-server` does; if not, it refuses as today. This holds only until
  step 5: an install command first fetches `install.sh` or `install.ps1`
  and the agent from the address it names, and once the old name answers
  421 the script fails before the agent's own `install` runs, on enrolled
  computers too. The retired name serves no scripts. So the page lists,
  from step 1, every kind of command that names the old address and its
  replacement (the command for scripts, Group Policy and Intune, and
  feature 6's packages' `install.conf` and transforms), to be replaced
  before step 5.

### The EasyPatch agent
* **Its own instruction.** The server offers `move` with `"agent":
  "easypatch"` to every device whose EasyPatch agent reports, in the
  inventory, an old address of the latest move not moved back, while that
  address is served, whatever address the device's EasyRMM agent uses.
  That covers devices enrolled through IP access in a DNS install, whose
  EasyRMM agent does not move, and EasyPatch agents whose earlier move
  failed. It needs two capabilities: EasyRMM's agent's `move.easypatch`
  (slice 4, like `move.easyrmm`), and the EasyPatch agent's `set-server`,
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
  completes there confirms it too. The old name stays confirmed. When
  slice 6 brings this in, each enabled provider starts out confirmed at
  the current primary, the one name its redirect URI was registered for
  until then.
* **Authentik** (amends [ADR-0044](0044-authentik-when-chosen.md)):
  * **The server writes the console's names** into
    `<data root>/authentik/names/`, one file each: `primary` and, from
    step 1 until step 5, `old`, rewritten at each start and each change.
    The directory is mounted read-write into the server and read-only into
    `authentik-setup` alone: never into Authentik's server or worker, and
    nothing in Authentik reads a file there.
  * **`authentik-setup` validates them.** It opens each file with
    `O_NOFOLLOW` and requires a regular file of at most 512 bytes, holding
    `https://host` or `https://host:port` with no path, query, fragment or
    credentials. A file that fails is not used, and the failure is
    reported (below); a missing `primary` leaves the context as it is.
    This matters because Authentik's containers, `authentik-setup`
    included, hold its secrets: `/easyrmm/secrets` is mounted into them and
    `AUTHENTIK_SECRET_KEY` is in their environment, and `!File` opens a
    path with a plain `open()` that follows links (`File.resolve` in
    `authentik/blueprints/v1/common.py`). A link planted among the names,
    read by the blueprint, could put a secret into a value any Authentik
    user can read, such as the application's `meta_launch_url`. So the
    blueprint uses no `!File`.
  * **The values reach the blueprint as its instance's context.**
    `authentik-setup` writes the validated values into the `context` of
    EasyRMM's `BlueprintInstance`, `public_url` (the primary) and, while
    there is one, `old_url`, and sends the worker's own apply task as
    Authentik's API does (`apply_blueprint.send_with_options` in
    Authentik 2026.8.5's `authentik/blueprints/api.py`). The task merges
    the instance's context over the file's (`Importer` in
    `authentik/blueprints/v1/importer.py`), and the blueprint reads the
    values with `!Context`, as it reads `public_url` today
    (`docker/authentik/blueprints/easyrmm.yaml`). The worker so never
    reads a file the server can write, applies the same values when it
    re-applies the blueprint for reasons of its own (a new blueprint
    file), and records a failure in the instance's status.
  * **Only the context sets them.** The file's `context` loses its
    `public_url: !Env EASYRMM_PUBLIC_URL`, so no apply ever takes these
    values from `.env`. The redirect URIs, the enrollment flow's last
    redirect and the launch link move out of the entries that create the
    provider, the stage and the application into entries of their own,
    with the same identifiers, only those attributes, and `conditions:
    [!Context public_url]`. Until `authentik-setup` has written the
    context, those entries are skipped (`check_all_conditions_match`,
    `importer.py`) and an existing object is updated only in the
    attributes given (`partial`, same file), so the values the instance
    already holds are kept: an upgrade's first apply by the worker
    changes nothing there. On a new install the worker creates the
    objects without them, and `authentik-setup`'s first reconcile, once
    the blueprint exists, adds them.
  * **The blueprint** chooses the whole `redirect_uris` list, because
    `!If` as a list item leaves a `null` item (`If.resolve`): `!If
    [!Context old_url, [<old entry>, <primary entry>], [<primary
    entry>]]`; an absent `old_url` resolves to `None`
    (`Context.resolve`), which `!If` takes as false. The enrollment
    flow's last redirect (`target_static`) and the application's
    `meta_launch_url` read `!Context public_url`.
  * **`authentik-setup` stays running** (`restart: unless-stopped`),
    since Authentik's worker applies a blueprint again only when the
    blueprint file changes (Context). It **reconciles** at every start,
    before it watches anything, and every 5 minutes: it compares the
    validated files with the instance's context and applies on any
    difference. Between those it watches the names directory and
    reconciles on a change. After an apply succeeds, the reconcile also
    reads Authentik's objects, the provider's `redirect_uris`, the
    stage's `target_static` and the application's `meta_launch_url`, and
    sends the apply again when they differ from the context. The
    redirect URIs are `{matching_mode, url, redirect_uri_type}` objects,
    so both sides are normalised first (the blueprint's values for each
    field, compared as a set): an earlier
    apply sent again and committed last cannot leave stale values. So
    changes made while it waited for the
    blueprint (up to 15 minutes at a first start), while the server
    started, or while it was down are applied too. Its loop also picks up
    a pending invitation, since `setup.sh --new-invitation` followed by
    `docker compose up -d` no longer restarts it.
  * **Its own healthcheck.** Without one it inherits the image's, `ak
    healthcheck` (the pinned image's `HEALTHCHECK`, as `docker image
    inspect` shows it), which fails for this service. ADR-0052's held
    start (step 6: `docker compose up -d --remove-orphans --wait`, every
    service healthy within 20 minutes) would then roll every upgrade with
    Authentik back. So the compose change that makes it long-running
    (slice 6) also gives it a check of its own, against a liveness tick.
    Its loop ticks every 30 seconds and touches
    `/tmp/easyrmm-setup-alive` at each tick (its `/tmp` is the tmpfs of
    `x-authentik-hardening`); the check passes while that file is under 2
    minutes old. Nothing in the loop blocks between ticks: the wait for
    the blueprint (up to `WAIT_SECONDS` in `docker/authentik/setup.py`)
    is a check made at each tick, and an apply is sent, recorded as
    pending in `names-status.json`, and its result read from the
    instance's status at the following ticks (an apply with no result
    after 10 minutes is recorded as failed and sent again at the next
    reconcile). When `WAIT_SECONDS` runs out with no blueprint, it
    records the error in `names-status.json`, from which the server
    raises an alert, and keeps ticking and checking. So the service is
    healthy within seconds of starting, while it may still wait for the
    blueprint, far inside ADR-0052's 20 minutes; `start_period` is 1
    minute. Whether the values are applied shows in the console (below),
    not in the health, so neither a slow first start nor a bad names file
    can roll an upgrade back.
  * **Failures show** in the instance's status and in EasyRMM's console:
    `authentik-setup` writes its last result (the values applied, when,
    or the error) to `names-status.json` in `<data root>/authentik/status/`,
    a directory only it can write, mounted read-only into the server. The
    server opens it with `O_NOFOLLOW`, requires a regular file of at most
    4 KiB with known fields, and shows it on the move's page and in
    Settings → Single sign-on.
  * **What remains**: the server can still choose any valid `https`
    origin as EasyRMM's address at Authentik, which is its job; it already
    holds the client secret those codes need. It reaches nothing else in
    Authentik.
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
is the new one and stays its relying party whether or not a move is in
progress, so the common case loses nothing.

**On a DNS install before slice 7**, step 1 is refused while any key is
registered, and while a move is in progress registering a new key is
refused, with the authenticator app offered instead. A key registered
during the move would be under the new name's ID, and a **Move back** or
`tls reset` would return the relying party to the old name and lock out
anyone whose only factor it was.

For a move between names (slice 7):

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
  address and stop working at step 5 on every computer, enrolled or not
  ("Installing again", above). The page lists them with their
  replacements from step 1, and again before step 5.
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
* **Recorded per server, from slice 1.** Each server makes a random ID at
  its first start and keeps it in its data directory
  (`<data root>/server/server-id`). The pair its `.env` names is kept in
  `server_env_pairs`, a platform table keyed by that ID, with when it was
  recorded and when the server was last seen (each start, and hourly
  while it runs). ADR-0057's `server_instances` rows are per process and
  are deleted at stop, so they are not used for this; each of them names
  its server's ID. Slice 1 writes the record, a release before anything
  acts on it, so that an install upgrading to slice 4 already has one.
  * A server compares its `.env` only with its own record, so servers
    whose `.env`s differ never undo each other's moves; the page warns
    while they differ.
  * Rows not seen for 30 days are ignored, and the page offers to
    **Forget** them (audited).
  * Two live server instances that name the same ID raise an alert: a
    data directory was cloned. A `server_instances` row counts as live
    only when it was seen in the last 2 minutes, and the alert needs both
    rows refreshed after the later of the two started, so a restarted
    server's last row never counts against it. Command-line subcommands
    (`names`, `tls reset`, `recover`) never register an instance. The
    guide says to delete the clone's `server-id` and restart it.
  * A record that cannot be written is logged, retried every minute and
    alerted; nothing is offered from that server's `.env` until it is
    written.
* **A `.env` that names another pair never moves anything by itself**,
  whatever made it differ: an edit, a restore that kept a newer `.env`, a
  new host, a change during a move. When a server's `.env` names a pair
  other than the primary, the server, in one transaction, records it and
  opens an alert and the banner **Move to the pair in `.env`** (audited as
  `name_move.env_offer`). Today that edit strands every agent; with this
  it strands none.
* **What is served while `.env` is only offered**: the pair `.env` names
  is served as an **agent route only**, so agents on it keep working;
  browsers there are redirected to the primary, as ADR-0055 does for an
  added name that is no longer trusted. Everything in the table under
  "The name elsewhere" stays on the primary: the relying party ID, the
  authenticator issuer, links in email, install commands, the single
  sign-on callback, the audit forwarder's `HOSTNAME`, `recover`'s link,
  Authentik's `primary`, and MeshCentral's name. From slice 4,
  `configureWebAuthn`, `enrollapi.New`, `auth.Config.PublicURL`,
  `auditfwd.New`, `recover` and the others there read the primary, not
  `EASYRMM_PUBLIC_URL`, and so do `defaultCertURL`
  (`server/internal/config/config.go`: `certUrl`'s port comes from the
  primary), `Origins` (`server/internal/config/origins.go`) and the
  target of `AgentHost`'s redirect (`server/internal/app/app.go`). The
  primary keeps its certificate source (ADR-0055): in `acme` mode it
  stays in autocert's host policy; in `manual` mode the offer warns when
  the certificate files no longer cover it.
* **The move starts only when someone chooses it**: in the console, with
  step-up, or on the host with `docker compose exec server easyrmm-server
  names move --to-env` (host access is the authority there, so no
  step-up; `--start-anyway` is **Start anyway**, and prints its list).
  Either way it is an ordinary step 1, with its own gates: the pair
  trusted and reachable, every device seen in the last 30 days able to
  move or **Start anyway**, no security key registered on a DNS install
  before slice 7, the move lock and the `hold` check; the server's record
  is written in the same transaction. Its old pair is the primary at that
  moment.
* **During a move**, a `.env` naming the move's old pair offers **Move
  back** the same way; any other pair is offered once the move ends.
  Nothing is queued. After a finished console move, a `.env` still naming
  the old pair gets a different banner: the two lines to write.
* **Never while held.** A start while the updater's `hold` exists
  (ADR-0052) records and offers nothing; the comparison is made when the
  server is released, so an upgrade that rolls back leaves no trace.
* **A restore** is compared like any start: the restored record and
  primary against the `.env` in place, so a `.env` kept from after the
  backup is offered, never acted on. `server-id` must be restored with
  the data directory; without it the server makes a new ID and record,
  and its old row is ignored after 30 days or forgotten.
* **`setup.sh --upgrade` warns** when `.env`'s `EASYRMM_PUBLIC_URL` or
  `EASYRMM_MESH_PUBLIC_URL` differs from the running server container's
  environment (`docker compose` passes both to it), naming both values
  and what the new version will do: offer the move, or, before slice 4,
  strand the agents. It only warns, so the updater's runs are unchanged.
* **Before slice 4**, a change of `EASYRMM_MESH_PUBLIC_URL` applies to
  MeshCentral at once, as today, and MeshAgents follow by slice 3's rule.
* **The engine's `EasyPatch__PublicUrl`** is no longer read by EasyRMM
  (step 1). What still reads it when slice 4 is built (today the links in
  the engine's alert messages, which ADR-0053's sender takes over) gets
  EasyRMM's primary name from EasyRMM instead, and the setting is removed
  once nothing reads it (ADR-0048's rule).
* **Moving to another IP address of this server** works the same way, when
  `EASYRMM_IP_ADDRESSES` lists both, with the trust of an IP target ("What
  a move is"): an address the host has lost takes its agents with it
  unless they moved first.

### Precedence over ADR-0055
* **`.env` names a name ADR-0055 added**: ADR-0055's rule comes first (the
  name stops being an added one, `tls.name_superseded`), then the rule
  above offers a move to it.
* **`tls reset`** during a move ends it as **Move back** would, from the
  host and without step-up: the primary returns to the move's old pair,
  and MeshCentral to its name if step 2 was taken; a `.env` naming
  another pair is then offered as above. The new pair stops
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
* **The updater refuses Roll back across step 1 or 2 of a move**, by
  ADR-0052's section "Rollback guards (amended 2026-11-21)", written once
  for this ADR and ADR-0057, which this ADR cites rather than repeats: the
  backup's `{jobKeyGeneration, moveGeneration}`, the wait for every server
  to be held, the read under the ring's lock and then the move lock, the
  refusals, the one `--strand-agents` override, and the updater's status
  that lets the console hide **Roll back**. It ships before this ADR's
  slice 4, the first that moves agents.
* **What this ADR adds to it**: `moveGeneration`, its baseline 0 and its
  rule of never going backwards ("What a move is", above); and steps 1
  and 2, **Move back** included, taking the move lock and checking the
  `hold` file itself inside it, so that a step admitted before a
  rollback's hold has committed by the time the rollback reads, or is
  refused.
* **What a forced rollback strands** is the amendment's list. Across step
  1 or 2, onto a version with this ADR, the cost is the agents' hour
  before they fall back (above). Onto a version from before this ADR,
  agents that moved cannot come back by any command on the computer: that
  server answers `/address` with `404`, so the fall-back, `set-server` and
  `install` at its address all fail their check, and their MeshAgents are
  on a MeshCentral name it does not serve. Only `easyrmm-agent uninstall`
  and enrolling again with the restored server's install command work,
  and each computer comes back as a new device
  ([ADR-0024](0024-enrollment-approval.md)), its history left with the old
  record and its EasyPatch agent enrolled again. The one exception is a
  restored `.env` that already names their new address. `--strand-agents`'s
  confirmation states this cost before it proceeds.
* **A rollback that crosses no step 1 or 2** restores the same move state,
  on a version that has this ADR; agents keep working.
* **A restore by hand** (`docs/operations/backup-restore.md`) is not
  refused by anything, and costs what a forced rollback costs: onto a
  version with this ADR, from a backup that predates the new name, agents
  that moved fall back within an hour, their EasyPatch agents with them,
  and MeshAgents follow MeshCentral's name; onto a version from before
  this ADR, uninstall and enroll again, as above. A `.env` newer than the
  backup, kept across the restore, starts no move: it is offered, as any
  `.env` naming another pair is ("Names in `.env`"). The restore guide
  says all of this, says to restore a backup from after the move's last
  step 1 or 2, and says that `server-id` must be restored with
  `/srv/easyrmm/server`. That directory's row in the guide's table of
  parts, which says "empty in the other modes" today, is corrected to
  name `server-id` in every mode (slice 8).
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
  back**, **Move to the pair in `.env`** and removing keys under an old
  relying party ID.
* **Every super administrator is told** when a step is taken, an override
  is used, a move is moved back or finished, a server's `.env` names
  another pair, a server record is forgotten, two servers share an ID, and
  when agents report a confirmation that does not verify:
  a notice in the console and an email through ADR-0053's sender once it
  exists.
* **On the host**: `.env` (above), `tls reset`, and `docker compose exec
  server easyrmm-server names status` to read the move's state and
  `names move --to-env` to start the move `.env` offers. On the
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
* A banner, with the alert, while a server's `.env` names a pair other
  than the primary: the pair, the server, and **Move to the pair in
  `.env`** (step-up), or **Move back** when it is a move's old pair;
  offered once no move is in progress otherwise.
* A banner when no initial pair could be adopted ("What a move is"):
  "Agents use <origin> (<count> devices)[, <origin> (<count> devices)…],
  with MeshCentral at <cert>; `.env` names <pair>. Until you confirm
  which pair EasyRMM starts from, all are served and no move can start."
  When there was no `config.json`, it says that the agents' pairs use
  `.env`'s MeshCentral name. **Confirm** (step-up) offers **Use `.env`'s
  pair** and **Use <origin>** for each candidate that passes the checks;
  the others are shown with the reason.
* The servers on the database with their ID, `.env` pair and last seen;
  **Forget** on those not seen for 30 days.
* Authentik's last apply (`names-status.json`) on the move's page and in
  Settings → Single sign-on, with the error when it failed.

### API
* `GET /api/v1/settings/names`: the names and their roles, the move in
  progress, each step's state and the counts.
* `POST /api/v1/settings/names/moves` (`to`; **Move to the pair in
  `.env`** is this call with that pair), `POST
  /api/v1/settings/names/initial` (**Confirm**, `{"pair": "env"}` or
  `{"pair": "agents", "origin": "<origin>"}`, one of the candidates `GET`
  lists with their device counts, MeshCentral name and checks), `DELETE
  /api/v1/settings/names/servers/{id}` (**Forget**), and on the move `POST
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
| `name_move.start` | Step 1, from the console (**Move to the pair in `.env`** included) or `names move --to-env` | From and to; devices able, waiting and unable to move; console or host; with **Start anyway**, the list |
| `name_move.step` | Steps 2 to 5 | The step; with an override, what it overrode |
| `name_move.back` | Moved back, from the console, `names move --to-env` or `tls reset` | The step it had reached |
| `name_move.env_offer` | A server's `.env` first names a pair other than the primary; recorded and offered, not acted on | The pair, the primary, the move's pairs if any, the server |
| `name_move.initial` | The initial pair adopted from a record or `.env`, or confirmed in the console | The pair, where it came from; when confirmed, the candidates with their device counts and the move Confirm started |
| `name_move.server_forget` | A server's record forgotten | The server's ID, its last pair, when it was last seen |
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
* **Rollback across a move is refused**, by the same guard as across a
  key rotation (ADR-0052's "Rollback guards").
* **Passkeys**: the plan relied on Related Origin Requests alone. Keeping
  each key's relying party ID, narrowing origins at step 4 and asking
  people to register again lets the old name go eventually and keeps a
  lapsed domain from signing anyone in.
* **The engine's public URL is not moved**: EasyRMM stops depending on it.
* **Authentik's own name does not move**; only EasyRMM's redirect URI
  there, applied by a service that validates the names and reconciles
  them into the blueprint's context.
* **The plan's one signed instruction is two signatures**: the
  instruction, bound to the agent's request, and the new address's
  confirmation of a nonce the agent sent there.
* **Added**: the fall-back, `set-server` and an idempotent `install`; a
  hand edit of `.env` that offers a move instead of stranding agents; and
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
    a `404` from `/move` dropped once, with no retry;
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
  * `name_moves` and the primary; the move generation never going
    backwards, with a fake clock set back as by a restore, and 0 without
    `name_moves`; steps 1 and 2 refused while `hold` exists, including a
    `hold` written between the step's first statement and its commit,
    since the check is inside the move lock;
  * the instructions offered only to builds that reported `move.easyrmm`
    or `move.easypatch`, on an old address of the latest move, again after
    an hour; offered again after the move has finished to an agent whose
    heartbeat arrives on an old IP address that is still served (it fell
    back); EasyPatch moves offered to devices whose EasyRMM agent stays on
    an IP-access address; the confirmation signed only for served
    addresses and a matching `Host`;
  * step 1's gates (capability, trust, reachability checked again, keys on
    a DNS install before slice 7) and **Start anyway**; on a DNS install
    before slice 7, registering a key during a move refused, with the
    authenticator app offered, and allowed again once the move ends or is
    moved back; step 4's passkey list and **Redirect anyway**; step 5's
    wait, from an updater status the test writes, and **Remove anyway**;
    **Move back**;
  * `.env` with **two servers on one database**: different `.env`s do not
    undo each other; a changed `.env` never starts a move, at that start
    or any later one: it is recorded with the alert, the banner and
    `name_move.env_offer` in one transaction, the `.env` pair is served
    as an agent route (a device on each pair keeps checking in), and the
    move starts only from
    **Move to the pair in `.env`** with step-up or from `names move
    --to-env`, each through step 1's gates (a device unable to move, a
    key on a DNS install before slice 7, `hold`), with the old pair the
    primary at that moment (a console move first, so that it differs
    from what `.env` named before); during a move, the old pair offers
    **Move back** and a third pair is offered only once the move ends;
    edited back to the primary, the banner clears; a held start records
    nothing; a record write that fails raises the alert and offers
    nothing;
  * the per-server record surviving a stop and start (`server-id` and
    `server_env_pairs`); a database restored from before a `.env` change,
    with that `.env` kept, offers it and starts nothing; rows not seen for
    30 days ignored and forgotten; two live instances with one ID raise
    the alert, while a restart's old row, a row older than 2 minutes and
    a command-line subcommand do not;
  * the initial pair, at slice 4's first start: from the record slice 1
    wrote, also when `.env` was edited just before the upgrade; with no
    record, from `.env` when the recorded origins of recent devices
    match it; a recent device with no recorded origin, or one on another
    origin, leaves it unadopted until **Confirm** with step-up: `cert`
    and `aliasPort` read once from the existing `config.json` and
    stored, `config.json` rendered with them pinned and `allowedOrigin`
    and framing from every origin served, the stored MeshCentral name
    served with its certificate (a MeshAgent on it stays connected and
    `certUrl`'s read gets that certificate), every candidate origin
    served to agents (a device on each keeps checking in), moves and
    offers refused; candidates leave out IP-access addresses on a DNS
    install, carry their device counts when the devices are split, and
    one that fails `validateMesh` or the dot rule cannot be chosen; with
    no `config.json`, the candidates use `.env`'s MeshCentral name; the
    edge listening on the stored `aliasPort`, also after
    `EASYRMM_IP_MESH_PORT` changed; `acmeHosts` holding the stored name
    and the candidates in `acme` mode, and the banner naming those a
    `manual` certificate does not cover; a choice failing step 1's gates
    (a device that would not trust its certificate, `validateMesh`, the
    dot rule) refused with the reason; **Confirm** of `.env`'s pair and
    of an agents' pair each writing the initial pair (for the latter,
    with `https://<cert>:<aliasPort>`, and the pin deleted) and recording
    a move from the other candidates (and, for `.env`'s pair, the pinned
    MeshCentral name): a device on another candidate is sent the move
    instruction and moves, its old address stays served with its
    certificate until step 5, and MeshCentral keeps the pinned name
    until step 2; `name_move.initial` names that move; the initial pair
    stays the primary until a move;
  * while `.env` is only offered: its pair answers agents and redirects
    browsers to the primary; the relying party ID, issuer, email links,
    install commands, single sign-on callback, audit `HOSTNAME`,
    `recover`'s link and Authentik's `primary` all name the primary; in
    `acme` mode the primary stays in the host policy, and in `manual`
    mode a certificate that no longer covers it is warned about;
  * an IP-to-IP move passing step 1 with the internal authority's
    certificate and a browser's load in the last 24 hours, or the
    self-check; with neither, step 1 warns and goes ahead, and an agent
    whose `/address` check fails there stays; step 1 refused for a device
    that would not trust the target's certificate (an `acme` install's
    agent, trusting the system's roots, on a move to an IP address);
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
       again; the address's install command run again on moved machine 1
       succeeds ("Already enrolled; this server is now at …"); then step 5
       against an updater status the test writes (the test's only
       shortcut, recorded as such);
    8. after step 5, IP access keeps the address: its install command
       still succeeds on machine 1; machine 2, sent back to the address
       with `set-server` as a fall-back would, is offered the move again
       and moves to the name.
  * **From a name to a name**: a DNS install at `rmm.example.net`, moved
    to `rmm.example.com`, both from BIND and Pebble. Machine 4 is enrolled
    through IP access: its EasyRMM agent stays on the address and its
    EasyPatch agent moves to the new name. Machine 5 is enrolled through
    the name, then its agent stopped before step 1; step 5 lists it and is
    taken with **Remove anyway**. Started, machine 5 gets 421; the old
    name's install command fails at its first download with 421, as the
    page warned, so it never reaches `easyrmm-agent install`;
    `set-server` to the new name brings machine 5 back, after which the
    new name's install command succeeds on it ("Already enrolled"). With
    Chromium's virtual authenticator through Playwright
    (new to the suites): a key registered at the old name, used at the new
    one through the well-known document, refused at the old origin after
    step 4, and a key-only person listed by step 4 until they add one. If
    the virtual authenticator does not exercise Related Origin Requests,
    the slice says so and that check moves to the browsers by hand.
  * The machines share the host's network; if two MeshAgents cannot share
    one network namespace, the slice that finds it says how it was solved,
    never with a bridge network (as ADR-0057's test).
* **`authentik-setup`'s checks** (a test of its own beside
  `docker/authentik/setup.py`): a names file that is a link, a FIFO,
  longer than 512 bytes, or a URL with a path, query, fragment,
  credentials or `http` is refused and reported; a valid change is
  written to the instance's context and applied; a change made while it
  was stopped is applied at its start, before it watches; one missed by
  the watch is applied at the 5-minute reconcile; a failed apply shows in
  `names-status.json`; with a fake clock, the liveness file stays fresh
  while it waits for the blueprint and while an apply is pending, and an
  apply with no result after 10 minutes is recorded as failed; with no
  context written, the conditional entries are skipped and the provider,
  stage and application keep their values; after an apply, objects that
  differ from the context once normalised (redirect URIs in another
  order or with other default fields compare equal; a stale apply
  committed last does not) make it send
  again; `WAIT_SECONDS` running out is recorded as an error while the
  loop keeps ticking.
* **Single sign-on and Authentik**: the Authentik bundle test
  (`scripts/e2e/authentik.sh`) gains a move: without restarting Authentik,
  the provider's redirect URIs gain the new name's, its enrollment
  redirect and launch link follow, and a sign-in through Authentik there
  completes; a link planted in the names directory changes nothing in
  Authentik and shows as an error in the console. Its readiness check
  changes: it requires `authentik-setup` to have exited 0 today
  (`ready` and `setup_state` in that script), and the service no longer
  exits, so it waits instead for the service to be running and
  `names-status.json` to report the values applied, and fails when the
  service has exited or reports an error. It also checks the service's
  own healthcheck: `healthy` within its 1-minute start period, while the
  first start still waits for the blueprint, and `unhealthy` when its
  loop is stopped.
* **Upgrading with Authentik**: ADR-0052's upgrade test gains a case with
  `--with-authentik`, so that the held start's `--wait` passes with the
  long-running `authentik-setup` healthy, and the upgrade is confirmed,
  not rolled back. The provider keeps its redirect URI, the stage and
  the application their values, through the worker's first apply of the
  new blueprint, before `authentik-setup` writes the context.
* **Rollback**: the guard's own tests are the amendment's. Here, ADR-0052's
  upgrade test gains a real agent: after a confirmed upgrade, a name added
  and step 1 taken, **Roll back** is refused with the message;
  `--strand-agents` rolls back, its confirmation names the devices that
  moved and the cost for the version it restores (the hour's fall-back
  with this ADR; before it, uninstall and enroll again as a new device),
  and the record lists the refusal it overrode; a rollback with no step 1
  or 2 since its backup goes ahead and the agent keeps working. The
  backup-restore drill (`scripts/drill/`) restores by hand, onto the same
  version, a backup from before the name was added: the agent falls back
  within the real hour; recorded in
  [drills.md](../../development/drills.md).
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
   agent and the server): `/address`, `/move`, `address.json`, `status`.
   No capability is reported yet: nothing parses `move`. Also the
   per-server record (`server-id`, `server_env_pairs` with last seen),
   written at every start and acted on by nothing yet, so that an install
   reaching slice 4 has one. Useful alone: a computer is moved by hand
   between two addresses the server serves. Verified in the bundle by
   moving machine 1 between `https://127.0.0.1` and the host's other
   address; the record by an integration test.
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
4. **The move of agents** (step 1 and **Move back**): `name_moves`, the
   move generation, steps 1 and 2 under the move lock with the `hold`
   file checked inside it, the primary and every reader of the name
   taking it instead of `EASYRMM_PUBLIC_URL`, an IP target's trust, a
   DNS install adding a name, the signed instruction for both agents and
   the build
   that parses it, which first reports `move.easyrmm` and
   `move.easypatch`, the failure reports, `.env` offered per server (an
   agent route only, the banner, `names move --to-env`, the initial pair
   and **Confirm**,
   **Forget**, the shared-ID alert), `setup.sh --upgrade`'s warning, the
   precedence over ADR-0055, link matching and install instructions from
   EasyRMM's names, the install commands' list on the page, the engine's
   `PublicUrl` no longer read, the refusal of new keys during a move on a
   DNS install, step-up, notices, the page and the devices' column,
   audit. Needs F0, 5b1 to 5b3, and ADR-0052's "Rollback guards" shipped;
   the contract test.
5. **MeshCentral's move** (step 2), and the code-signing check above.
6. **Sign-in and browsers** (steps 3 and 4): redirect URIs per name,
   confirmation, with each enabled provider starting out confirmed at
   the current primary, Authentik's names files, the blueprint's context
   and its conditional entries (no `!Env` left for these values), the
   long-running `authentik-setup` that validates and reconciles them,
   with its liveness tick and own healthcheck (a requirement of
   ADR-0052's held start),
   `names-status.json` in the console, the Authentik bundle test's
   readiness and health checks, the upgrade test with Authentik, the
   redirect.
7. **Passkeys on the new name**: `rp_id`, `last_used_origin`, one
   relying party per ID, the well-known document, origins narrowed from
   step 4, step 4's list, the prompts, the count. It lifts step 1's
   refusal on DNS installs with keys, and the refusal to register keys
   during a move.
8. **Removing the old name** (step 5), its wait read from the updater's
   status, the restore guide (the cost of restoring onto a version from
   before this ADR, a `.env` kept across a restore being only offered,
   and `server-id` in `/srv/easyrmm/server`'s row), the drill, and the
   guide's page on moving.

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
* A hand edit of the names in `.env` no longer strands agents: its pair
  is served to agents beside the primary, and the console or a host
  command starts the move when someone chooses it.
* The updater cannot roll back across a move's step 1 or 2 without
  `--strand-agents`; onto a version from before this ADR that leaves each
  moved computer to be uninstalled and enrolled again, as a new device.
* Install commands handed out before a move work until its old name is
  removed, and then on no computer, enrolled or not: the old name serves
  no scripts. Group Policy, Intune and packaged commands must be replaced
  before step 5; the page lists them.
* Nothing moves agents unattended: a `.env` naming another pair, after
  an edit, a restore or on a new host, waits for someone to choose the
  move in the console, with step-up, or on the host.
* The EasyPatch agent gains a command, and its older builds stay on the old
  name until updated. `authentik-setup` becomes a long-running service,
  and Authentik's containers never read a file the server can write.
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
* **The blueprint reading the names with `!File`**: simpler, but the
  worker would open server-writable paths, following links, inside a
  container that holds Authentik's secrets (Step 3).
* **Queuing a `.env` pair refused during a move**, to act on it when the
  move ends: a move would then start at some later restart with nobody
  watching.
* **A rollback guard of this ADR's own**: two guards for one rollback
  would differ in locking and in their generations; ADR-0052's amendment
  is the one.
* **The server changing `.env` or Authentik through the updater**: the
  updater takes nothing but a version from the server (ADR-0052).
* **Serving old names for ever**: agents would never need to move, but a
  lapsed domain would stay an address every agent uses.
* **A second relying party ID only, without Related Origin Requests**: old
  keys would stop working at the new name at once.
* **Unsigned moves, trusting TLS**: TLS without a pinned key is what the
  job key exists not to rely on.
