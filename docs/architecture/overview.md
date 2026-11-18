# EasyRMM Architecture

This document describes the target architecture. What is implemented today is
tracked in [`IMPLEMENTATION_STATUS.md`](../../IMPLEMENTATION_STATUS.md);
decisions are recorded as ADRs in [`adr/`](adr/).

## 1. System context

```
                         Internet / customer networks
   Technicians (browser)                     Managed endpoints (Windows, Linux)
          │ HTTPS 443                         │ outbound only: HTTPS/WSS 443
          ▼                                   ▼
 ┌──────────────────────────────── Linux host (Docker, host networking) ─────────────────────┐
 │                                                                                             │
 │  easyrmm-server  :443 (TLS edge)  :80 (optional ACME HTTP-01 + redirect)                    │
 │   ├─ rmm.example.com   → web UI, /api/v1 (users), /api/agent/v1 (companion agents)          │
 │   └─ mesh.example.com  → gated reverse proxy ──► meshcentral 127.0.0.1:14430 (HTTP)         │
 │                                                                                             │
 │  postgres 127.0.0.1:15432   databases: easyrmm (RLS), meshcentral                            │
 │                                                                                             │
 └─────────────────────────────────────────────────────────────────────────────────────────────┘
          │ HTTPS (optional, server-to-server)
          ▼
   EasyPatch server (separate host or IP, own TLS)
```

Every container uses `network_mode: host`. Only the edge listens on public
interfaces; every other service binds to `127.0.0.1` on ports chosen to avoid
common collisions. See [network.md](network.md) for the complete port table.

## 2. Components

| Component | Technology | Responsibility |
|---|---|---|
| `easyrmm-server` | Go modular monolith | TLS edge, web UI hosting, REST API, agent gateway, MeshCentral gateway and control client, job scheduler, monitoring engine, notification delivery, EasyPatch connector |
| `web` | React + TypeScript + Vite, designed with Impeccable | The only user interface. Embedded into the server binary at build time |
| `easyrmm-agent` | Go, single static binary per OS/arch | Enrolment, identity, inventory, telemetry, job and script execution, software management, MeshAgent and EasyPatch-agent supervision, self-update |
| MeshAgent | Upstream binary, pinned version | Remote desktop, terminal, file transfer and RDP tunnel transport |
| MeshCentral | Upstream container, pinned version | Remote-session relay and MeshAgent management; never exposed directly |
| PostgreSQL | 18 | EasyRMM database (row-level security) and MeshCentral's database |
| EasyPatch (optional) | .NET and React, in `easypatch/`; its own deployment, or any existing EasyPatch server | Patch state, policy and patch jobs |

### Server modules (`server/internal/…`)

`config`, `database` (pool, migrations, scoped transactions), `secrets`
(sealing), `auth` (sessions, MFA, passwords), `rbac`, `audit`, `tenancy`
(organizations, sites, device groups), `users`, `httpapi` (routing, middleware,
JSON), `edge` (TLS, certificates, host routing), `meshcentral` (control client,
login tokens, user/mesh sync, gateway), `enrollment` (deployment tokens),
`devices` (inventory, identity mapping), `agentgw` (agent protocol),
`jobs`, `scripts`, `monitoring`, `alerts`, `software`, `updates`,
`easypatch`, `reports`, `notify`.

Modules communicate through Go interfaces inside one process. There are no
internal network hops, message brokers or caches in the default deployment.

## 3. Data and tenancy

Hierarchy: **Organization → Site → Device group → Device**, plus free-form
tags and typed custom fields.

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

See ADR-0004 and ADR-0005. Summary:

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
* Certificate renewals are written to `meshcentral-data/proxy-cert.pem`, which
  MeshCentral reads through `certUrl: file:///…`, so agents keep validating
  the server across Let's Encrypt renewals.

## 6. Endpoint: one installation

See ADR-0008, ADR-0015 (which replaced bundling MeshAgent) and ADR-0020
(Windows). The customer runs **one command**: a PowerShell line on Windows
or a shell line on Linux, copied from **Devices → Add devices**
([docs/deployment/agents.md](../deployment/agents.md)). MSI, DEB and RPM
packages are not built yet.

1. The install script downloads `easyrmm-agent` for the machine's
   architecture and checks it against the server's `SHA256SUMS`. When the
   server uses its own certificate authority (`internal` TLS, IP access),
   the command pins the server's key and the script hands the authority,
   fetched over that pinned connection, to the agent. With a public
   certificate, ordinary TLS checks apply.
2. `easyrmm-agent install` generates an Ed25519 device key, presents the
   deployment token, and receives a device id. It installs itself as a
   service (`EasyRMMAgent` on Windows, a systemd unit on Linux).
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

## 8. EasyPatch

See ADR-0010 and [docs/integrations/easypatch.md](../integrations/easypatch.md).
EasyPatch is EasyRMM's patch management component. Its code is in
`easypatch/` of this repository, under its own licence
([LICENSING.md](../../LICENSING.md)), and it builds, releases and runs as its
own server ([monorepo.md](../development/monorepo.md)). It is the source of
truth for patch state, and EasyRMM can use any EasyPatch server.
EasyRMM talks to it server-to-server with an EasyPatch API token (ADR-0030)
and renders patch state natively behind EasyRMM's roles. On request, or for
every device in an organization set to install automatically, the EasyRMM
agent downloads the EasyPatch agent from the customer's EasyPatch server,
checks it and enrolls it (ADR-0031). EasyPatch is never redistributed with
EasyRMM.

## 9. Deployment

* Docker Compose, host networking only, explicit bind mounts under a single
  data root (default `/srv/easyrmm`). See
  [docs/deployment/docker.md](../deployment/docker.md).
* TLS modes: `acme` (default, Let's Encrypt via TLS-ALPN-01 or HTTP-01),
  `manual` (certificate files), `offload` (behind an existing NGINX; the
  server listens on loopback HTTP and trusts `X-Forwarded-*` only from
  configured proxies).
