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
| EasyPatch (optional) | Customer's existing deployment | Patch state, policy and patch jobs |

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

* Users authenticate with e-mail + password (Argon2id) and a mandatory second
  factor (TOTP; WebAuthn planned). Sessions are opaque 256-bit tokens in a
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
  `meshagents`, `agenttransfer.ashx`, `devicefile.ashx`) unconditionally, and
  browser routes only for requests that carry a valid EasyRMM remote-session
  grant cookie. MeshCentral's login page and `/meshsettings` are never
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

See ADR-0008. The customer installs **one package**; it contains:

* `easyrmm-agent` (our service), and
* the pinned upstream MeshAgent binary for that OS/architecture
  (hash-verified at build time; Apache-2.0 notices included).

Installation flow (identical across MSI, EXE, PowerShell, deb, rpm and
shell script):

1. Install files and the `easyrmm-agent` service.
2. `easyrmm-agent enroll --server <url> --token-file -` generates an Ed25519
   device key, presents the deployment token, and receives a device id,
   credentials and the MeshAgent `.msh` for its site.
3. The agent installs MeshAgent (`-fullinstall --copy-msh=1`), writes
   `MeshAgent.tag = easyrmm:<device-id>`, and waits for the NodeId.
4. It reports the NodeId; the server confirms it against the tag that
   MeshCentral reports, and links the two identities.
5. Health checks run; the device appears in the dashboard.

Uninstalling the package removes both agents, their services, credentials and
files, and notifies the server (best effort; the server also revokes on
request). The server rolls its agent build out a few devices at a time, with
instructions signed by its job key that name the build's SHA-256, and an
agent goes back to its previous build when the new one does not reach the
server (ADR-0027). MeshCentral updates MeshAgent itself.

## 7. Agent communication

See ADR-0009. Outbound only. Primary channel: a WebSocket to
`/api/agent/v1/connect` authenticated by a signature with the device key.
Fallback: signed HTTPS polling with exponential backoff and jitter. Jobs are
durable server-side and delivered when the device next connects; every job
payload is signed by the server so a TLS-intercepting middlebox cannot inject
commands. A compromised endpoint holds only its own device key: it can report
data about itself and receive its own jobs, nothing else.

## 8. EasyPatch

See ADR-0010 and [docs/integrations/easypatch.md](../integrations/easypatch.md).
EasyPatch remains its own product and its own source of truth for patch state.
EasyRMM talks to it server-to-server with an integration credential, renders
patch state natively, and installs the EasyPatch agent by downloading it from
the customer's EasyPatch server during enrolment, so it is not redistributed
inside our open-source installer.

## 9. Deployment

* Docker Compose, host networking only, explicit bind mounts under a single
  data root (default `/srv/easyrmm`). See
  [docs/deployment/docker.md](../deployment/docker.md).
* TLS modes: `acme` (default, Let's Encrypt via TLS-ALPN-01 or HTTP-01),
  `manual` (certificate files), `offload` (behind an existing NGINX; the
  server listens on loopback HTTP and trusts `X-Forwarded-*` only from
  configured proxies).
