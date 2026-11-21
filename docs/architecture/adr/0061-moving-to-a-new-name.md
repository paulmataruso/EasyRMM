# ADR-0061: Moving EasyRMM to a new name

* Status: Proposed (2026-11-21). Not implemented.
* Builds on: ADR-0055 (proposed: Let's Encrypt in one step; when a name is
  trusted, the agent's trust for DNS names, step-up authentication,
  `tls reset`), ADR-0057 (proposed: rotating the job key; everything this
  ADR signs goes through its ring),
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
  own), [ADR-0052](0052-the-host-updater.md) (backups and rollback).
* Amends: [ADR-0032](0032-webauthn-passkeys.md), "Relying party": a
  credential keeps the relying party ID it was registered under, and other
  origins use it through Related Origin Requests;
  [ADR-0034](0034-oidc-single-sign-on.md), "One redirect URI": one per
  console name, confirmed per provider;
  [ADR-0044](0044-authentik-when-chosen.md): the blueprint's redirect URIs
  come from a file the server writes;
  [ADR-0031](0031-easypatch-agent-install.md): install instructions name
  EasyRMM's own address, not the engine's `PublicUrl`.
* Part of [the feature plan](../feature-plan.md): feature 5, slice 5c. It
  comes last in the plan's order and needs F0 (ADR-0057). ADR-0055 says
  where 5b stops and this begins.

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
  `install` refuses another server ("run uninstall first"). The agent
  trusts the system's roots, or with `--ca-file` only that file
  (`client.New` in `agent/client/client.go` replaces `RootCAs`); ADR-0055
  makes that both for DNS names.
* **MeshAgent**: `MeshServer=wss://<name>:<port>/agent.ashx` in
  `meshagent.msh` beside its executable (`settings()` in
  `agent/meshagent/meshagent.go`). EasyRMM's agent installs that file as the
  server fetched it from MeshCentral and signed it (`installMesh` in
  `agent/runner/runner.go`; `SignDownload` in
  `internal/agentproto/download.go`), and already edits one line of it
  before writing (`WithServiceName`). MeshCentral 1.3.1 writes the line
  from its `cert` setting and `aliasPort` (`getMshFromRequest` and
  `getWebServerName` in its `webserver.js`), which EasyRMM sets from
  `EASYRMM_MESH_PUBLIC_URL` (`MeshServerConfig` in
  `server/internal/app/app.go`, `ServerConfig.Render` in
  `server/internal/meshcentral/config.go`). MeshAgent reads the file again
  at every start and imports it into its database (`importSettings` in
  `meshcore/agentcore.c` of MeshAgent's repository; the build MeshCentral
  1.3.1 ships was not checked).
* **MeshAgent's pin**: `ServerID` in the same file is the hash of
  MeshCentral's agent certificate (`agentCertificateHashBase64`). MeshCentral
  makes that certificate only when it has none (`MeshCentralAgentServer`,
  generated when `r.agent == null` in its `certoperations.js`), so a new
  `cert` name keeps it. A new name does make MeshCentral issue itself a new
  web certificate and a new code-signing certificate (`forceWebCertGen`,
  `forceCodeCertGen`). A `cert` without a dot puts MeshCentral in LAN-only
  mode, where the `.msh` says `MeshServer=local` (`meshcentral.js`).
* **The EasyPatch agent**: `ServerUrl` in its state (`AgentState` in
  `easypatch/agent/EasyPatch.Agent.Core/State/AgentState.cs`), set only at
  enrollment (`EnrollmentManager.cs`), and in its bootstrap configuration
  beside the authority it may trust (`ServerCaCertificate`: the registry on
  Windows, `RegistryBootstrapConfigSource.cs`; `agent.conf` on Linux,
  `ConfFileBootstrapSource.cs`). Its `enroll` command refuses another
  server unless given `--force`, which unenrolls and discards the agent's
  identity (`Cli.cs`). EasyRMM's agent installed it with an instruction
  naming the engine's public URL (`install.go` in
  `server/internal/easypatch`) and reports its address in the inventory
  (`agent/inventory/easypatch.go`). EasyRMM links it to its device only
  when that address is the engine's URL as EasyRMM reaches it, the
  engine's public URL or an imported EasyPatch's (`verify` in
  `server/internal/easypatch/links.go`).

### MeshCentral accepts one certificate
MeshCentral 1.3.1 lets a MeshAgent in only when the hash of the TLS
certificate the agent reports having seen is that of the certificate it
last read from `certUrl`, or of its own default web certificate, which
EasyRMM's edge never serves (the agent authentication request in
`meshagent.js`; `webserver.js`; `updateProxyCertificates` in
`meshcentral.js`). Every other agent is held. MeshAgents therefore cannot
use two addresses with two certificates at the same time. Today they use
one: every `.msh` names MeshCentral's `cert`, whatever console origin
installed the device ([docker.md](../../deployment/docker.md): "MeshAgent
on each device keeps using the MeshCentral name").

The edge answers MeshCentral's own `certUrl` request, from this host, with
the certificate of `EASYRMM_MESH_PUBLIC_URL`'s name, except in `internal`
mode, where every connection gets the authority's (`edge.certificates` in
`server/internal/app/edge.go`). `certUrl`'s port is MeshCentral's when it
differs from the console's: 4443 on an IP install (`defaultCertURL` in
`server/internal/config/config.go`).

Browsers meet a second check: MeshCentral opens `control.ashx` only for an
`Origin` whose host is its `cert` name, unless the domain's `allowedOrigin`
lists others (`CheckWebServerOriginName` in `webserver.js`). EasyRMM sets
no `allowedOrigin`.

### The name elsewhere in the deployment
| What | Where | Today |
|---|---|---|
| Routing and certificates | `Config.Origins` (`server/internal/config/origins.go`), `newRouter` (`server/internal/app/origins.go`), `edge.certificates` | Built at start; ADR-0055 rebuilds them for added names |
| CSRF origin check | `httpapi.NewSessions`, given every console origin (`Build`) | At start |
| CSP `frame-src`, MeshCentral's `allowedFramingOrigins` | `Handler`, `MeshServerConfig` | At start |
| Install commands | `enrollapi.New` (the public URL first), `agentapi.New` (a script per origin) | At start; ADR-0055 renders them again |
| Links in email | `auth.Config.PublicURL` (password reset, `server/internal/auth/service.go`) | The public URL |
| Authenticator issuer | `EasyRMM (<host>)` (`Build`) | The public URL's host |
| Security keys and passkeys | `configureWebAuthn` (`server/internal/auth/webauthn.go`): relying party ID the public URL's host, one origin; `user_webauthn_credentials` (`server/migrations/00015_webauthn.sql`) keeps no relying party ID | A new host makes every key useless ([ADR-0032](0032-webauthn-passkeys.md), [docker.md](../../deployment/docker.md)) |
| Single sign-on | One redirect URI, `<public URL>/api/v1/auth/sso/callback` (`CallbackPath`, `server/internal/sso/sso.go`), registered at each provider; buttons on other origins point there | The public URL |
| Authentik | Its blueprint takes `public_url` from `EASYRMM_PUBLIC_URL` (`!Env`) for the redirect URI (strict), the enrollment redirect and the launch link (`docker/authentik/blueprints/easyrmm.yaml`), mounted read-only from the bundle | `.env` |
| The engine | `EasyPatch__PublicUrl: ${EASYRMM_PUBLIC_URL}` (`deploy/docker-compose.yml`): its server-info, which EasyRMM reads for install instructions and link matching, and links in its alert messages (`AlertEngine.cs`, `NotificationEndpoints.cs`) | `.env` |
| An imported EasyPatch's names | `EASYRMM_PATCHING_AGENT_HOSTNAMES`: agent paths served, everything else redirected to the console (`AgentHost` in `server/internal/easypatch/agentedge.go`) | `.env` |
| Audit forwarding | The syslog `HOSTNAME` (`auditfwd.New`) | The public URL's host |
| `easyrmm-server recover` | Its sign-in link (`server/internal/app/recover.go`) | The public URL |
| `setup.sh --upgrade` | Reads both URLs from `.env` (`deploy/scripts/setup.sh`) | `.env` |

### What vouches for the server
An agent signs each request with its device key over the method, path,
time, a single-use nonce and the body's hash; the host it dialled is not
part of it (`message` in `internal/agentproto/agentproto.go`). The server's
answers are vouched for by TLS against the agent's roots, and its
instructions by the job key. Agents pin no TLS key. A name that resolves
elsewhere for some computers (a hijacked or lapsed domain, split-horizon
DNS gone wrong) with a certificate the agent trusts is therefore believed
for TLS; only the job key tells this server from another.

## Decision

### What a move is
* **A move takes the deployment from one name pair to another**: a console
  name and its MeshCentral name, such as `rmm.example.net` and
  `mesh.rmm.example.net` to `rmm.example.com` and `mesh.rmm.example.com`,
  or `203.0.113.10` and `203.0.113.10:4443` to a name pair. One move at a
  time.
* **The new pair must be trusted first**, as ADR-0055 defines it: this
  server holds a certificate for both names obtained through HTTP-01 or
  TLS-ALPN-01, or a token served here was fetched through them. ADR-0055
  allows one added pair on an IP install; this ADR lets a DNS install add
  one the same way, for a move. The MeshCentral name must share a parent
  domain with the console name (as `validate` requires today) and contain
  a dot (MeshCentral's LAN-only rule above).
* **Nobody can move agents to a server that does not hold the job key.**
  Each agent moves only after it has checked, from its own network, that
  the new address answers with a job key signature over its own fresh
  nonce (below). A super administrator chooses *which* of this server's
  trusted names agents use, never another server.
* **Old names keep working** for everything that still uses them until
  someone removes them, which is the cut-off.
* **`name_moves`**, a platform table like `settings`, outside row-level
  security: one row per move, with the pairs it moves from and to, who
  started it and how (console or host), when each step was taken and by
  whom, and how it ended (finished, or moved back). The **primary** pair is
  the target of the last move not moved back, or `.env`'s when there has
  been none. Every server on the database reloads it on `NOTIFY`, as
  ADR-0055's certificates do.

### The steps
A move has five steps. The console takes them in this order and shows,
for each, what it changes, what it is waiting for and what is still on the
old name.

| Step | What changes | Waits for |
|---|---|---|
| 1. **Agents** | The new pair becomes the primary for everything new. Agents move as they check in | The new pair trusted; no device seen in the last 30 days whose agent cannot move |
| 2. **Remote access** | MeshCentral moves to the new MeshCentral name; MeshAgents follow their EasyRMM agent. Skipped when remote access is off | Step 1 |
| 3. **Sign-in** | Each single sign-on provider confirmed at the new name; Authentik's redirect URI added | Step 1 |
| 4. **Browsers** | The old console name sends browsers to the new one | Steps 1 and 3; passkeys (below) |
| 5. **Remove the old name** | The old pair is no longer served | Steps 1 to 4; 24 hours since step 1; nothing seen in the last 30 days still on it, or a confirmation that lists what is |

**Move back** is offered until step 5: a move to the old pair, which is
still trusted. Agents, MeshAgents and EasyPatch agents follow it the way
they followed the move; browsers are no longer redirected; nothing done at
providers has to be undone, since the old redirect URI stays registered.

### Step 1: what becomes the new name at once
From step 1 the primary pair is the new one for the following. On an IP
install ADR-0055 already gave the added name the first four; on a DNS
install they change here.

* install commands, with the new name's command first (rendered again, as
  ADR-0055 does for an added name);
* links in email and `easyrmm-server recover`'s link;
* the authenticator issuer, for new enrolments (existing entries keep
  their label and keep working);
* the relying party new security keys are registered under (passkeys,
  below; on a DNS install from slice 7 on, and until then the old name
  stays the relying party, so no key stops working);
* EasyPatch install instructions: they name EasyRMM's primary console
  origin, read from `name_moves`, not the engine's `PublicUrl`
  (amends [ADR-0031](0031-easypatch-agent-install.md)), and
  link matching (`verify` in `links.go`) accepts every console origin the
  server serves, old names included;
* the audit forwarder's `HOSTNAME`. The move's own audit record, which
  collectors receive before the change, names both.

The old console name stays a console origin (CSRF check, framing, its
install command, sign-in) until step 4, and serves agents until step 5.

### EasyRMM's agent: a signed move and a check from the computer
* **The instruction.** While a move is in progress, the heartbeat answer to
  a device whose requests arrive on an old name (ADR-0055 records each
  device's route) carries `move`, signed with the job key under its own
  context (`EASYRMM-MOVE-SIG-V1`) like every instruction: `{"v", "id",
  "deviceId", "to", "issuedAt", "expiresAt"}`, valid 10 minutes. The
  agent refuses one for another device, an expired one, one with unknown
  fields, one whose `to` is not an `https` origin (`ParseServer`), and one
  whose signature does not verify with a key it trusts (ADR-0057).
* **The check, at the new address.** The agent then sends `POST
  /api/agent/v1/address` to `to`, signed with its device key as every
  request is, with `{"address": to}` in the body. The server answers with a
  confirmation signed with the job key (`EASYRMM-ADDRESS-SIG-V1`) over the
  device, the request's single-use nonce and the address, as MeshAgent's
  downloads are signed over the device and the nonce. It signs only for an
  enrolled device, for an address it serves agents on, and when the
  request's `Host` is that address. The agent verifies the confirmation
  with the keys it trusts, against its own nonce and the address it
  dialled.
* **What the check proves**: that from this computer, through the roots
  this agent already trusts, the new address reaches a party that holds the
  job key, now. A hijacked name that answers with any certificate cannot
  sign the agent's nonce; a recorded answer cannot be replayed. A move
  never carries a certificate authority, so it cannot widen what an agent
  trusts.
* **The switch.** Only then does the agent write `agent.json` with the new
  `server`, the address it left as `previousServer`, the move's ID and
  when, and restart its service, as after an update (ADR-0027). The
  server sees the device's next heartbeat arrive on the new name.
* **Failures** (the name does not resolve on that network, a firewall, a
  certificate the agent does not trust, a signature that does not verify)
  leave the agent where it was. It reports them, signed, on `POST
  /api/agent/v1/move` at its current address, a path of its own as removal
  reports are (ADR-0050), so no heartbeat field is added that an older
  server would refuse. The server offers the move again after an hour, or
  at once when someone presses **Try again** on the device. A signature that
  does not verify is audited and raises an alert: it means the new name
  resolves elsewhere for that device.
* **What the check cannot stop**: a party that holds a certificate for the
  new name and relays to this server unchanged would pass it, and then sit
  between the agent and the server. It can read what the agent sends and
  drop what it receives, but forge no instruction. A party with that
  position on today's name has the same reach; the move adds nothing to it.
  Only names this server trusts are offered, and adding one needs step-up
  authentication (below).
* **Agents that cannot move**: builds from before this ADR ignore `move`
  (the agent reads answers leniently). The server knows them by the version
  their heartbeats report. Step 1 is refused while a device seen in the
  last 30 days runs one, and the page offers **Update these agents**
  (ADR-0027's rollout), as ADR-0055 does for trust. An agent that trusts
  only its CA file and would not trust the new name's certificate blocks
  in the same way (ADR-0055's rule).
* **Agents waiting for approval** keep asking on the old name, which serves
  enrollment until step 5; once approved, they move like the others.

### Two other ways an agent changes its address
Both end with the same check, so the job key always decides.

* **Falling back.** When every request to its server has failed for an
  hour and it remembers a `previousServer`, the agent runs the check there.
  If it passes, the agent switches back and reports it. This covers a
  restore to a server that no longer serves the new name, `tls reset`
  (below), and a new name whose certificate expired after its renewals
  failed (ADR-0055 then stops trusting it). Ordinary downtime does not
  trigger it: then the previous address fails too. A lapsed old domain
  cannot use it: whoever holds it cannot sign.
* **By hand.** `easyrmm-agent set-server https://rmm.example.com`, run as
  root or administrator on the computer, runs the check and switches. It is
  for a computer that comes back after the old name was removed, and
  carries no secret, so it can be run through MeshCentral's terminal,
  Group Policy or Intune (ADR-0057's `trust-key` is run the same way).
  The agent reports a change made by hand in its next request, and the
  server audits it. `easyrmm-agent status` shows the address and the one
  before it.

### MeshAgent follows MeshCentral's name
MeshAgent cannot be moved one device at a time (MeshCentral accepts one
certificate), so it does not get an instruction of its own. A standing
rule replaces it:

* **The heartbeat answer names MeshCentral's agent address** (`meshAgent`
  gains `server`: `wss://` and MeshCentral's `cert` and `aliasPort`, what
  MeshCentral writes in every `.msh`). When it differs from the
  `MeshServer` line of the installed `meshagent.msh`, the agent fetches the
  settings again through the signed download it already uses, requires
  that their `MeshServer` is the address named and their `ServerID` the
  installed one, replaces only the `MeshServer` line, and restarts
  MeshAgent. At most once in 10 minutes. The answer's field is only a hint:
  what is written comes from the signed download, and MeshAgent's pin and
  device group never change.
* **Step 2** writes MeshCentral's `config.json` with the new name as
  `cert` and its port as `aliasPort`; MeshCentral's start script restarts
  it (`docker/meshcentral/start.sh`), which ends open remote sessions (the
  page says so before the operator confirms) and reads `certUrl` as it
  starts. From then on MeshAgents on the old address are held, and each
  moves at its EasyRMM agent's next heartbeat: within a minute or two for
  computers that are on. A computer that is off moves when it comes back,
  before anyone could have reached it.
* **The edge follows MeshCentral's name**: MeshCentral's `certUrl` request
  from this host gets the certificate of MeshCentral's current name from
  whichever source serves it (today `internal` mode answers it with the
  authority's, which would hold every MeshAgent after a move to Let's
  Encrypt), and `certUrl`'s port follows MeshCentral's (4443 to 443 when an
  IP install moves to a name). An `EASYRMM_MESH_CERT_URL` set in `.env` is
  kept, and the page warns that it must reach the new name.
* **`allowedOrigin`**: whenever the MeshCentral hosts it serves to
  browsers change (a name added, step 2, step 5), EasyRMM writes all of
  them (the current name, IP access's addresses, an added or old name)
  into the domain's `allowedOrigin`, so that sessions launched on any of
  them pass `CheckWebServerOriginName`. The gateway passes the browser's
  `Origin` through unchanged (`server/internal/remote/gateway.go`), so
  today a session on a host other than `cert` (IP access in a DNS
  install, ADR-0055's added name before this move) may be refused. Slice 3
  checks that by opening one; if it is refused, slice 3 writes
  `allowedOrigin`, and the defect is recorded against ADR-0016 (and
  ADR-0055, if 5b has shipped).
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

### The EasyPatch agent follows its EasyRMM agent
* The EasyPatch agent's paths are served on every console origin
  ([ADR-0039](0039-agents-on-easyrmms-name.md)), so its address is
  EasyRMM's console name. After EasyRMM's agent changes its own address (a
  move, a fallback, by hand), it moves the EasyPatch agent when that agent
  is on the address it left: it runs the EasyPatch agent's new `set-server
  <url>` command, on Windows and Linux, which checks in with the engine at
  the new address with its own credential, then writes `ServerUrl` in its
  state and its bootstrap configuration and restarts its service. The
  authority it trusts is kept; the move's trust rule above already
  required that the new name is served by a certificate it accepts.
* The server sees the move in the inventory's report of the EasyPatch
  agent's address, as today. An EasyPatch agent from before the command
  stays on the old name and is listed as **update the EasyPatch agent**
  (the engine's automatic agent updates, or a policy change).
* EasyPatch agents on an imported EasyPatch's names
  ([ADR-0045](0045-importing-a-standalone-easypatch.md)) are not on
  EasyRMM's console name and are left there.

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
* **Authentik's blueprint** stays EasyRMM's
  ([ADR-0044](0044-authentik-when-chosen.md)) and lists a redirect URI per
  console name: the server writes the names into a directory of the data
  root mounted read-write into the server and read-only into Authentik's
  containers, as it writes MeshCentral's `config.json`, and the blueprint
  reads them with Authentik's `!File` tag (Authentik 2026.8.5,
  `authentik/blueprints/v1/common.py`). `!ParseJSON` parses only its own
  text, so one file per name: the primary and, during a move, the old one;
  the slice settles how an absent second name is left out (`!If`). A
  compromised server could name any host there, but it already holds the
  client secret those codes need; nothing else in Authentik is reachable
  through the files. Whether Authentik applies a blueprint again when only
  a file it reads changes was not checked; the test sign-in shows when it
  took effect, and the slice finds what triggers it.
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
  (a redirect would otherwise send people round between the two), and,
  for passkeys, for slice 7.

### Passkeys
An IP install has none (browsers refuse WebAuthn on addresses), so the
common case loses nothing. For a move between names:

* **A credential keeps the relying party ID it was registered under**:
  `user_webauthn_credentials` gains `rp_id`, filled with today's host by
  the migration. New keys are registered at the primary name, under its ID
  (amends [ADR-0032](0032-webauthn-passkeys.md)).
* **Old keys keep working at the new name** through Related Origin
  Requests: the old name serves `/.well-known/webauthn` listing the new
  console origin, and the old ID's configuration accepts that origin
  (go-webauthn v0.18.2, which `go.mod` pins, builds the document:
  `RelatedOrigins`, `protocol.WellKnownPathWebAuthn`). A browser asks for
  one relying party ID at a time, so the second-factor step asks for the
  person's keys under the new ID, then under the old one if those are all
  they have; passkey sign-in offers **Use a passkey from rmm.example.net**
  beside the usual button.
* **Browsers without Related Origin Requests** cannot use old keys at the
  new name. Those people use their authenticator app or a recovery code,
  or register a key again; which browsers support it is checked by hand
  and recorded, not assumed.
* **Everyone with keys only under the old ID is asked to add one** at the
  new name, on their account page and in a banner after sign-in. The page
  counts the keys left under the old ID and when each was last used.
* **The old name keeps serving `/.well-known/webauthn`** while any key is
  registered under it, also after step 5. Removing the name for good asks
  first to remove those keys, listing their owners; people left without a
  second factor are listed apart, for an administrator to reset theirs.

### Step 5: removing the old name
* **When**: at least 24 hours after step 1, and when no device seen in the
  last 30 days still has an EasyRMM agent, MeshAgent or EasyPatch agent on
  the old pair, and no agent waits for approval there. Otherwise the page
  lists them and **Remove anyway** asks for confirmation.
* **What it does**: the old pair is no longer served (421
  `name_retired`, with the command that moves a computer by hand),
  its certificate is no longer renewed unless passkeys still need its
  `/.well-known/webauthn` (above), and **Move back** is gone. The move is
  finished.
* ADR-0055's **Remove name** on a name that agents use, or that is the
  primary, is refused outside this step and gated the same way.
* **An old IP address** is not removed: IP access keeps serving it as it
  serves every address of the host (ADR-0016). Finishing a move from an IP
  install removes nothing IP access serves, so a computer that never moved
  keeps its EasyRMM agent. Its MeshAgent follows MeshCentral's name like
  every other, and connects only if that computer can reach the name.
* **Install commands already handed out** (scripts, Group Policy, Intune,
  packages' `install.conf` and transforms from feature 6) name the old
  address. The page says so at step 1 and again before step 5.

### Moving from an IP address to a name
The case the plan builds feature 5 around: `EASYRMM_PUBLIC_URL` is
`https://203.0.113.10`, MeshCentral is on `https://203.0.113.10:4443`, the
mode is `internal` and IP access is on. ADR-0055 added `rmm.example.com`
and `mesh.rmm.example.com` with Let's Encrypt; the console already works
there, with passkeys.

1. **Agents**: EasyRMM's agents trust their CA file and, for DNS names,
   the system's roots too (ADR-0055's build); each checks
   `https://rmm.example.com` against Let's Encrypt's chain and the job key,
   moves, and moves its EasyPatch agent, which trusts the system's store.
2. **Remote access**: MeshCentral's `cert` becomes `mesh.rmm.example.com`,
   its port 443, and `certUrl` follows; MeshAgents follow within a
   heartbeat. Remote sessions from the IP console still open on
   `https://203.0.113.10:4443`, now through `allowedOrigin`.
3. **Sign-in**: each provider confirmed at the name; Authentik's redirect
   URI added.
4. **Browsers**: nothing to redirect: the IP console is IP access.
5. **Finish**: nothing is removed; computers that never moved keep their
   EasyRMM agent on the address.

Nothing is lost: there were no passkeys, and old TOTP entries keep working.
A customer's firewall that allows the server's address still matches when
the name resolves to it; MeshAgent's port changes from 4443 to 443, which
the page says at step 2, with every address and port computers must reach.

### Names in `.env`
`EASYRMM_PUBLIC_URL` and `EASYRMM_MESH_PUBLIC_URL` stay in `.env` as the
pair an install starts with. The server records the pair `.env` gave at
each start, in `settings`.

* **A console move does not change `.env`**: the server cannot write the
  host's configuration, and the updater takes nothing from it but a
  version (ADR-0052). Once a move is finished the page shows the two lines
  to put in `.env`, and why: `setup.sh --upgrade` and the engine's
  `EasyPatch__PublicUrl` read them. Until then `.env` naming the old pair
  changes nothing.
* **`.env` changed by hand starts a move**: when `.env` names another pair
  than at the previous start, and that pair is not the primary, a move to
  it starts at step 1, recorded as started on the host. The pair `.env`
  named before stays served as an old name, and MeshCentral keeps its name
  until step 2, as in any move. Today that edit strands every agent; with
  this it moves them. The edit is root's on the host, so no trust check or
  step-up applies; each agent's own check still does. (Between slices 3
  and 4, a change of `EASYRMM_MESH_PUBLIC_URL` applies to MeshCentral at
  once, as today, and MeshAgents follow by the rule above.)
* **The engine's `EasyPatch__PublicUrl`** is no longer read by EasyRMM
  (step 1). What still reads it when slice 4 is built (today the links in
  the engine's alert messages, which F2's sender takes over) gets
  EasyRMM's primary name from EasyRMM instead, and the setting is removed
  once nothing reads it (ADR-0048's rule).
* **Moving to another IP address of this server** works the same way, when
  `EASYRMM_IP_ADDRESSES` lists both: an address the host has lost takes
  its agents with it unless they moved first.

### Rollback
* **Move back** (above), until step 5: every agent that moved follows the
  move back, by the same instruction and check; MeshAgents follow
  MeshCentral; nothing at providers changes.
* **A rollback by the updater** ([ADR-0052](0052-the-host-updater.md)) or a
  restore from a backup:
  | Backup taken | The restored server | Agents that moved |
  |---|---|---|
  | During the move | Has the move, serves both pairs | Keep working. MeshAgents follow MeshCentral's name in the backup |
  | Before step 1, after the new pair was added | Serves the new pair as an added name, primary the old | Keep working on the new name; MeshAgents follow MeshCentral's old name back |
  | Before the new pair was added | Does not serve the new name (421) | Fall back to the old address within an hour, with the check, and their EasyPatch agents with them; MeshAgents follow |

  When `.env` already names the new pair (the operator wrote the lines
  after the move), the restored server sees `.env` differ from the pair it
  recorded and starts a move to it (below), so agents on the new name keep
  working in every row once the edge serves its certificate.
* **The 24 hours before step 5 keep ADR-0052's rollback safe**: **Roll
  back** is offered for 24 hours after a confirmed upgrade and restores the
  backup taken just before it, and between that backup and the
  confirmation the server is held, so no step can be taken. A rollback
  after step 5, which came at least 24 hours after step 1, therefore
  restores a backup taken after step 1: one that serves both pairs. No
  check is added to the updater for it. Only a restore by hand from an
  older backup (`docs/operations/backup-restore.md`) can leave agents on a
  name the restored server does not know: add the name again (ADR-0055),
  or run `set-server` on each computer. The restore guide says so.
* **`tls reset`** (ADR-0055) also ends a move in progress, returning the
  primary to `.env`; agents on names it removes fall back within an hour.
  A finished move's names count as the install's own: `tls reset` keeps
  them.
* **A job key rotation** (ADR-0057) is independent: each device follows each
  by its own statements, and the move is signed with the key from the
  device's report. The guide advises finishing one before starting the
  other.

### Who
* **Super administrators** (`settings.manage`, platform-wide) see the page
  and take every step. Organization administrators see, under
  `device.view`, which of their devices are still on the old name.
* **Step-up authentication** for steps 1, 2, 4 and 5, **Move back** and
  removing passkeys: ADR-0055's check, which 5b builds and this reuses.
* **Every super administrator is told** when a step is taken, a move is
  moved back or finished, a move starts from `.env`, and when agents report
  a confirmation that does not verify: a notice in the console and an
  email through F2's sender.
* **On the host**: `.env` (above), `tls reset`, and `docker compose exec
  server easyrmm-server names status` to read the move's state. On the
  computer: `easyrmm-agent set-server`, as root or administrator.

### Console
* Settings → **Certificates** (ADR-0055): **Move here** on a trusted name
  opens the move's page: the five steps, each with what it changes and what
  it waits for; counts of devices moved, waiting (offline since when),
  unable to move (with the agent's version) and failed (with the reason),
  for each of the three agents; providers and their confirmation; keys
  left under the old relying party ID; **Move back**; **Try again** for
  failed devices.
* **Devices**: an *Address* column and filter (*Moved*, *Waiting*,
  *Cannot move*, *Check failed*); a device's page shows the address of each
  of its agents.
* A banner for super administrators while a move is in progress, and until
  `.env` names the primary.

### API
* `GET /api/v1/settings/names`: the names and their roles, the move in
  progress, each step's state and the counts.
* `POST /api/v1/settings/names/moves` (`to`), and on the move `POST
  …/steps/{remote-access|browsers|remove}`, `POST …/back`; step-up as
  above. `POST /api/v1/devices/{id}/move/retry`. Super administrators
  only, except the device's retry (`device.edit`).
* `GET /api/v1/auth/sso/{id}/start?test=1` at a name runs the test
  sign-in.
* Agents: `POST /api/agent/v1/address` (the check) and `POST
  /api/agent/v1/move` (reports), both signed with the device key.

### Audit records
| Action | When | Details |
|---|---|---|
| `name_move.start` | Step 1, from the console or `.env` | From and to; devices able, waiting and unable to move; console or host |
| `name_move.step` | Steps 2 to 5 | The step; for step 5, what was still on the old name and whether it was removed anyway |
| `name_move.back` | Moved back | The step it had reached |
| `name_move.keys_remove` | Keys under an old relying party ID removed | The name, how many, whose |
| `sso.provider_confirm` | A provider's sign-in first completes at a name | The provider and the name |
| `device.address_refuse` | An agent reports a confirmation that does not verify | The address and the agent's reason (recorded as the agent) |
| `device.address_set` | An agent reports a change made with `set-server` | From and to (recorded as the agent) |
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
* **The cut-off is removing the old name**, offered after 24 hours and
  gated on what is still there, not a date.
* **Passkeys**: the plan relied on Related Origin Requests alone. Keeping
  each key's relying party ID and asking people to register again lets the
  old name go eventually, and says what happens in browsers without them.
* **The engine's public URL is not moved**: EasyRMM stops depending on it.
* **Authentik's own name does not move**; only EasyRMM's redirect URI
  there.
* **Added**: the agent's fallback and `set-server`, a hand edit of `.env`
  that starts a move instead of stranding agents, and MeshAgents that
  follow MeshCentral's name whatever changed it.
* **Signed settings (ADR-0058) are not how agents learn an address**: a
  setting can be set per organization or site, and an address must not be;
  a move needs a check against the new address from each computer, which a
  setting has no place for. The move travels as an instruction, in the
  heartbeat answer and on the WebSocket channel once it carries
  instructions.

## Testing
* **Unit** (`internal/agentproto`, the agent; also on CI's Windows runner):
  the move instruction and the confirmation signed and verified, and each
  refusal (another device, expired, unknown fields, another address,
  another nonce, an untrusted key, a key from before a rotation's cut-over
  with ADR-0057's ring); the switch writing `agent.json` before the
  restart, `previousServer` kept; the fallback after an hour of failures,
  with a fake clock, and not during downtime of both; `set-server` and
  `status`; replacing only `MeshServer` in a `.msh`, with Windows line
  endings and the service name line kept, refused when `ServerID` or the
  address differ.
* **The EasyPatch agent** (`EasyPatch.Agent.Tests`, Linux and CI's Windows
  runner): `set-server` checks in at the new address before it writes,
  writes the state and the bootstrap configuration, keeps the authority,
  and refuses an address that does not answer.
* **Integration** (PostgreSQL, race detector): `name_moves` and the
  primary; the instruction offered only to devices on an old name with a
  build that can move, again after an hour; the confirmation signed only
  for served addresses and matching `Host`; step 1 refused while a device
  seen in 30 days cannot move; each step's gates; **Move back**; `.env`
  changes at start; `tls reset` during a move; link matching across names;
  WebAuthn credentials under two relying party IDs and the well-known
  document; a provider confirmed by a sign-in at a name (against the test
  OpenID provider already used, `ssotest`); permissions, step-up and the
  audit records; two servers on one database agreeing within seconds.
* **Console**: the move's page, the devices' column and filter, the
  re-registration prompt.
* **The bundle test, with real agents, every machine on the host's network
  only** (`--network host`, as `scripts/e2e/bundle.sh` runs its machine;
  never a bridge network). It starts from the IP install at
  `https://127.0.0.1` and uses ADR-0055's Pebble and BIND, on host
  networking, for `rmm.example.com` and `mesh.rmm.example.com`:
  1. machine 1, today's Debian machine with systemd, enrolled on the IP
     address, with its MeshAgent and EasyPatch agent; machine 2 enrolled,
     then its agent stopped; machine 3 with the last release's agent, by
     its tag, checked against that release's `SHA256SUMS`;
  2. the name added (ADR-0055), then step 1 through the API (through the
     console from slice 4's console work on): refused for machine 3 until
     the rollout updates it; machine 1's agent checks, moves, its
     EasyPatch agent follows, a script runs and a patch scan reaches the
     engine through the name;
  3. step 2: MeshCentral logs its new certificate, machine 1's MeshAgent
     reconnects on `mesh.rmm.example.com` and a remote session opens; one
     opens from the IP console too;
  4. machine 2 started: it moves, then its MeshAgent, within two
     heartbeats;
  5. a hijacked name: machine 2's `/etc/hosts` points the name at a server
     of the test's own in a network namespace joined by a veth pair (no
     bridge, as feature 7's webhook receiver), with a certificate machine 2
     trusts and another key: the check fails, the agent stays,
     `device.address_refuse` is audited;
  6. **Move back**: every agent and MeshAgent follows; then the move again,
     and step 5 after the 24 hours are moved back in the database (the
     test's only shortcut, recorded as such);
  7. `set-server` on a machine left on the removed name: it reaches the
     server again.

  The machines share the host's network; if two MeshAgents cannot share
  one network namespace, the slice that finds it says how it was solved,
  never with a bridge network (as ADR-0057's test).
* **Single sign-on and Authentik**: the Authentik bundle test
  (`scripts/e2e/authentik.sh`) gains a move: the blueprint's redirect URI
  for the new name, a sign-in through Authentik there.
* **Passkeys** with Chromium's virtual authenticator through Playwright
  (new to the suites): a key registered
  at the old name, used at the new one through the well-known document,
  and a new key registered there. Real browsers (Chrome, Edge, Safari,
  Firefox) with a real security key and a synced passkey are checked by
  hand and recorded in IMPLEMENTATION_STATUS.
* **Rollback**: ADR-0052's upgrade test gains a real agent: after a
  confirmed upgrade, a name added and step 1 taken, then **Roll back**:
  the agent keeps working on the new name and its MeshAgent follows
  MeshCentral back. The backup-restore drill (`scripts/drill/`) restores a
  backup from before the name was added: the agent falls back within the
  real hour; recorded in [drills.md](../../development/drills.md).
* **Then** the owner's next full instance with DNS: an IP install moved to
  its real name, with their Windows and Linux computers.

## Slices
Each merges, is verified on its own, and leaves nothing unused.

1. **The check, `set-server` and the fallback** (EasyRMM's agent and the
   server): the confirmation statement and `POST /api/agent/v1/address`,
   `previousServer`, `status`. Useful alone: a computer is moved by hand
   between two addresses the server serves. Verified in the bundle by
   moving machine 1 from `https://127.0.0.1` to the host's other address
   (IP access serves both, no DNS needed).
2. **The EasyPatch agent's `set-server`**, and EasyRMM's agent running it
   after its own change of address.
3. **MeshAgent follows MeshCentral's name** (the rule above, the edge's
   `certUrl` answer and port), and `allowedOrigin` if the check above finds
   sessions refused. Verified in the bundle by changing MeshCentral's
   address in `.env` and restarting the server: on the IP install only its
   port may change (`validate` requires the same address), so
   `EASYRMM_MESH_PUBLIC_URL` and `EASYRMM_IP_MESH_PORT` move from 4443 to
   another port. The MeshAgents follow, which today they cannot.
4. **The move of agents** (step 1 and **Move back**): `name_moves`, the
   primary, a DNS install adding a name, the signed instruction, the
   failure reports, `.env` changes at start, link matching and install
   instructions from EasyRMM's names, the engine's `PublicUrl` no longer
   read, step-up, notices, the page and the devices' column, audit.
5. **MeshCentral's move** (step 2), and the code-signing check above.
6. **Sign-in and browsers** (steps 3 and 4): redirect URIs per name,
   confirmation, Authentik's files, the redirect. Until slice 7, step 4 is
   refused while keys are registered under the old name.
7. **Passkeys on the new name**: `rp_id`, Related Origin Requests, the
   prompts, the count.
8. **Removing the old name** (step 5), the restore guide, the drill, and
   the guide's page on moving.

Slices 1 to 5 and 6 without passkeys complete the IP-to-name case.

## Consequences
* An install on an IP address gets agents, remote access, single sign-on
  and Authentik onto its name from the console, with no computer visited.
* A name can change without reinstalling anything; passkeys survive it in
  browsers that support Related Origin Requests, and everyone is asked to
  register again so the old name can go.
* No one can move agents to a server without the job key, and each
  computer checks the new address itself before it moves.
* MeshAgents follow MeshCentral's name whatever changes it; remote access
  to a computer is interrupted for about a heartbeat at step 2.
* A hand edit of the names in `.env` moves agents instead of stranding
  them.
* Install commands handed out before a move stop working when its old name
  is removed.
* The EasyPatch agent gains a command, and its older builds stay on the old
  name until updated.
* Old names stay served, and their certificates renewed, until someone
  removes them; one that passkeys still use keeps serving one file.

## Alternatives considered
* **Signed settings for the address** (ADR-0058): above.
* **Moving MeshAgents device by device**: MeshCentral holds whichever group
  sees the other certificate. Turning off its check (`ignoreAgentHashCheck`)
  would let a TLS-intercepting party read remote sessions.
* **One certificate naming both MeshCentral names during a move between
  names**: MeshAgents on either address would see the same certificate,
  so they could move one by one. It does not help the common case, since
  ADR-0055 keeps IP addresses on the internal authority; it would be a
  second mechanism beside the one that case needs, and it departs from
  ADR-0055's one certificate per name.
* **The server changing `.env` or Authentik through the updater**: the
  updater takes nothing but a version from the server (ADR-0052).
* **Serving old names for ever**: agents would never need to move, but a
  lapsed domain would stay an address every agent uses.
* **A second relying party ID only, without Related Origin Requests**: old
  keys would stop working at the new name at once.
* **Unsigned moves, trusting TLS**: TLS without a pinned key is what the
  job key exists not to rely on.
