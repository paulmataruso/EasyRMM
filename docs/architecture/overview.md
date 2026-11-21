# EasyRMM architecture

How EasyRMM is built and why. What works today is in
[`IMPLEMENTATION_STATUS.md`](../../IMPLEMENTATION_STATUS.md); each decision
has an ADR in [`adr/`](adr/).

## 1. System context

![EasyRMM architecture: technicians' browsers and managed computers reach one EasyRMM server over HTTPS on port 443; the server forwards remote sessions to MeshCentral and patching to the patching engine, which run with PostgreSQL on loopback on the same Docker host](../images/diagrams/architecture.svg)

Everything runs on one Linux host with Docker, every container with
`network_mode: host`. Only the EasyRMM server's TLS edge listens on public
interfaces (443; 4443 for IP access; 80 optionally, for ACME and redirects).
MeshCentral, the patching engine and PostgreSQL listen on `127.0.0.1` only,
on ports chosen to avoid common collisions. The console name
(`rmm.example.com`) serves the web console, the REST API and the agents'
API; the MeshCentral name (`mesh.rmm.example.com`) serves remote sessions
and MeshAgent through the remote-access gateway. Managed computers only
connect out, to 443. [network.md](network.md) has every port and name.

## 2. Components

| Component | Technology | Responsibility |
|---|---|---|
| `easyrmm-server` | Go modular monolith | TLS edge, web console hosting, REST API, agent gateway, MeshCentral gateway and control client, jobs, monitoring and alerts, reports, notifications, the patching engine's client (ADR-0038) |
| `web` | React, TypeScript and Vite, designed with Impeccable | The only user interface. Built into the server binary |
| `easyrmm-agent` | Go, one static binary per operating system and architecture | Enrollment, identity, inventory, metrics, scripts, software, MeshAgent and EasyPatch agent installation and supervision, self-update |
| MeshAgent | MeshCentral's agent, the version the running MeshCentral serves | Remote desktop, terminal, files and the RDP tunnel |
| MeshCentral | Upstream container, pinned version | Remote-session relay and MeshAgent management; never reachable directly. Keeps its own data in files |
| Patching engine | .NET (`easypatch/`), its API and worker on loopback | Patch state, policies, schedules and patch jobs (ADR-0046) |
| EasyPatch agent | .NET service, installed by the EasyRMM agent | Scans for and installs updates on the computer: Windows Update and winget on Windows, apt and dnf on Linux |
| PostgreSQL | 18 | `easyrmm` (with row-level security), `easypatch` (the patching engine's), and `authentik` when Authentik is installed |

### Server packages (`server/internal/…`)

| Package | What it does |
|---|---|
| `app` | Assembles the server: database, services, routes, the TLS edge, health and background maintenance |
| `config` | Reads and checks the configuration from environment variables and secret files |
| `database` | Connection pool, migrations and tenant-scoped transactions |
| `access`, `rbac` | Who is calling and what they may do |
| `auth`, `sso` | Passwords, second factors, sessions; OpenID Connect sign-in |
| `users`, `tenancy` | Accounts and role assignments; organizations, sites and device groups |
| `audit`, `auditfwd` | The hash-chained audit log; forwarding it to syslog |
| `agents`, `devices`, `inventory` | Enrollment and agents' signed requests; the device list; what agents report |
| `jobs` | The script library and jobs that run on devices |
| `monitoring`, `mailer` | Alert policies and alerts; email |
| `remote`, `meshcentral` | Remote access: MeshCentral's accounts, device groups, launch and gateway; its control client |
| `easypatch` | The patching engine's client: statements, organizations, agent installs |
| `reports` | Tables to read in the console and download as CSV |
| `pki`, `secrets`, `netguard` | The server's own certificate authority; sealing secrets; keeping outbound calls off internal addresses |
| `httpapi`, `apperr`, `webui` | Shared HTTP plumbing, errors, the embedded console |

Modules communicate through Go interfaces inside one process. There are no
internal network hops, message brokers or caches in the default deployment.

## 3. Data and tenancy

Hierarchy: **Organization → Site → Device group → Device**. Patching adds
tags, which organizations, sites and devices carry and which can hold a
patch policy.

Tenant isolation is enforced three times:

1. **RBAC** in handlers (`rbac.Principal.Can(permission, resource)`).
2. **Query scoping**: every query runs in a transaction opened with the
   caller's data scope.
3. **PostgreSQL row-level security**: policies read transaction-local
   settings (`easyrmm.scope_*`). With nothing set, nothing is visible. The
   server connects as `easyrmm_app`, which cannot alter tables or disable RLS;
   migrations run as `easyrmm_owner`.

See [database.md](database.md) and ADR-0002.

## 4. Identity and access

* Users authenticate with e-mail + password (Argon2id) and a second factor
  (TOTP, or security keys and passkeys, ADR-0032), required unless the
  operator sets `EASYRMM_REQUIRE_MFA=false`. Sessions are opaque 256-bit tokens in a
  `__Host-` cookie (`Secure`, `HttpOnly`, `SameSite=Strict`), stored hashed,
  with idle and absolute expiry, rotation on privilege change, and a
  per-session CSRF token. See ADR-0006.
* Roles: Super Administrator (platform), Organization Administrator, Site
  Administrator, Technician, Read-Only — each assignable at organization or
  site scope (super admin: platform only). Permissions are granular
  (`device.remote_desktop`, `script.run`, …). Privilege escalation is
  prevented by rank and scope checks (`rbac.CanAssign`). See
  [docs/security/rbac.md](../security/rbac.md).
* Every security-relevant action is written to a hash-chained, append-only
  audit log through a `SECURITY DEFINER` function; the runtime role cannot
  insert, update or delete audit rows directly. See ADR-0007.

## 5. MeshCentral integration

See ADR-0004, ADR-0005, ADR-0014 and ADR-0033.

![Opening a remote session: the console gets a one-minute launch token from the EasyRMM API; the access gateway redeems it for a grant cookie, passes the browser's tunnel request to MeshCentral only if the grant covers that device and session type, and lets the MeshAgent join only that recorded tunnel](../images/diagrams/remote-session.svg)

* MeshCentral runs on loopback with TLS offload; our edge serves it on a
  dedicated hostname (`mesh.<domain>`) to keep it in a separate browser
  origin. The edge forwards agent routes (`agent.ashx`, `meshrelay.ashx`,
  `meshagents`, `agenttransfer.ashx`, `devicefile.ashx`) without a grant, as
  MeshCentral's agent port serves them, and browser routes only for requests
  that carry a valid EasyRMM remote-session grant cookie. Relays and their
  tunnel requests are bound to the session's grants (ADR-0022, ADR-0033). MeshCentral's login page and `/meshsettings` are never
  reachable from the internet.
* One MeshCentral device group per EasyRMM **site**. One MeshCentral user per
  EasyRMM user who has any remote permission, with random credentials the user
  never sees. Group rights are derived from EasyRMM RBAC and pushed on change
  (event-driven), with periodic reconciliation.
* The server keeps one persistent `control.ashx` connection as a dedicated
  service administrator.
* Launching a session: the browser asks our API; the server checks
  `device.remote_desktop` (also for RDP, ADR-0026) / `device.terminal` /
  `device.files` for that device, records an audit event, issues a single-use grant, and returns an
  iframe URL on the mesh hostname. The edge exchanges the grant for a
  host-only cookie and redirects to MeshCentral with a one-minute,
  single-use GCM login token for the technician's MeshCentral user,
  `gotonode`, `viewmode` and `hide=63`.
* MeshCentral learns the edge's certificate from `certUrl`
  (`EASYRMM_MESH_CERT_URL`, by default `https://127.0.0.1:443`, where the
  edge answers with the MeshCentral name's certificate). It reads the
  certificate again when an agent reports a different one, at most every
  two minutes, so agents keep validating the server across renewals
  (ADR-0014; [Docker deployment](../deployment/docker.md)).

## 6. Endpoint: one installation

See ADR-0008, ADR-0015 (which replaced bundling MeshAgent) and ADR-0020
(Windows). The customer runs **one command**: a PowerShell line on Windows
or a shell line on Linux, copied from **Devices → Add devices**
([docs/deployment/agents.md](../deployment/agents.md)). MSI, DEB and RPM
packages are not built yet.

![Enrolling an EasyRMM agent: a deployment token creates the device at once; an approval token makes the agent wait with a device code until a super administrator approves it into a site; then the agent fetches MeshAgent through EasyRMM and starts its heartbeat](../images/diagrams/agent-enrollment.svg)

1. The install script downloads `easyrmm-agent` for the machine's
   architecture and checks it against the server's `SHA256SUMS`. When the
   server uses its own certificate authority (`internal` TLS, IP access),
   the command pins the server's key and the script hands the authority,
   fetched over that pinned connection, to the agent. With a public
   certificate, ordinary TLS checks apply.
2. `easyrmm-agent install` generates an Ed25519 device key, presents the
   token, and receives a device id. With an approval token (ADR-0024) it
   gets a device code instead and waits, as a service, until a super
   administrator approves it under **Devices → Waiting for approval**. It
   installs itself as a service (`EasyRMMAgent` on Windows, a systemd unit
   on Linux).
3. The agent downloads MeshAgent and its site's settings (`.msh`) from the
   EasyRMM server with signed requests. The server fetches them from the
   running MeshCentral, so MeshAgent always matches it. MeshAgent runs as a
   service of its own (`EasyRMMMeshAgent`, `easyrmm-meshagent.service`), or
   as a supervised child process where Linux has no systemd.
4. The agent reports MeshAgent's node id (`meshagent -nodeid`) in its
   heartbeat. The server links the node to the device, only within the
   device's own site.
5. The device appears in the console, online, with its inventory.

`easyrmm-agent uninstall` removes both agents, their services and state;
the device stays listed as offline.

The server rolls its agent build out a few devices at a time, with
instructions signed by its job key that name the build's SHA-256, and an
agent goes back to its previous build when the new one does not reach the
server (ADR-0027). MeshCentral updates MeshAgent itself.

## 7. Agent communication

See ADR-0009, ADR-0015 and ADR-0017. Outbound only, over HTTPS. Every request
after enrollment is signed with the device key over the method, path,
timestamp, nonce and body hash, with a ±5-minute window and single-use
nonces. The agent:
* sends a heartbeat with its facts and metrics every minute;
* uploads its inventory when the server's copy differs;
* holds a job long poll open (25 seconds at a time);
* backs off with jitter after any failure.

ADR-0009's WebSocket channel is not built; long polling delivers jobs within
a second or so. Jobs are durable server-side and delivered when the device
next polls. Every job is signed with the server's job key, which the agent
pinned at enrollment, so a TLS-intercepting middlebox cannot inject
commands. A compromised endpoint holds only its own device key: it can
report data about itself and receive its own jobs, nothing else.

## 8. Patching

See ADR-0046 and [patching-engine.md](patching-engine.md); using it is
described in [docs/operations/patching.md](../operations/patching.md).
The patching engine is EasyPatch's server, built from `easypatch/` of this
repository and released with EasyRMM from the same commit (ADR-0043). It
runs in every deployment, on loopback, with no console or accounts of its
own, and is the source of truth for patch state. EasyRMM calls it with a
signed statement per request naming the person, their role and the
organizations of that call (ADR-0038), keeps its organizations and sites in
step with EasyRMM's (ADR-0040), and shows patch state in its own console
behind its own roles.

On request, or for every device in an organization set to install
automatically, the EasyRMM agent downloads the EasyPatch agent from the
engine through EasyRMM's address, checks it and installs it with a
single-use token (ADR-0031, ADR-0039). The EasyPatch agent then talks to
the engine through EasyRMM's address too.

## 9. Deployment

* Docker Compose, host networking only, explicit bind mounts under a single
  data root (default `/srv/easyrmm`). See
  [docs/deployment/docker.md](../deployment/docker.md).
* TLS modes: `acme` (default, Let's Encrypt via TLS-ALPN-01 or HTTP-01),
  `manual` (certificate files), `offload` (behind an existing NGINX; the
  server listens on loopback HTTP and trusts `X-Forwarded-*` only from
  configured proxies).
