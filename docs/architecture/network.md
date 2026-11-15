# Network architecture

All containers use `network_mode: host`. Defaults below are configurable.

| Port | Bind | Service | Exposed? | Why |
|---|---|---|---|---|
| 443/tcp | `0.0.0.0` | easyrmm-server | **Yes** | HTTPS for UI, API, agent gateway, MeshCentral hostname |
| 80/tcp | `0.0.0.0` | easyrmm-server | Optional | ACME HTTP-01 challenges and redirect to HTTPS. Not needed when TLS-ALPN-01 or manual certificates are used |
| 15432/tcp | `127.0.0.1` | PostgreSQL | No | Database (non-default port avoids clashing with a host PostgreSQL) |
| 14430/tcp | `127.0.0.1` | MeshCentral | No | MeshCentral HTTP with TLS offloaded to the edge |
| 18080/tcp | `127.0.0.1` | easyrmm-server | No | Only in `offload` mode, behind an upstream NGINX |
| 18081/tcp | `127.0.0.1` | easyrmm-server | No | Liveness (`/healthz`) and readiness (`/readyz`) probes used by the container health check |

Endpoints only make **outbound** connections to 443. No inbound endpoint
connectivity is ever required.

MeshCentral features that would open more ports are disabled: HTTP redirect
(:80), Intel AMT MPS (:4433), multicast scanning (UDP 16990), WebRTC and STUN.

## Host names

| Name | Purpose |
|---|---|
| `rmm.example.com` | Web UI, API, EasyRMM agent API (`/api/agent/`) and installers |
| `mesh.rmm.example.com` (configurable) | MeshCentral agents and embedded remote sessions (separate browser origin, ADR-0004) |

Both resolve to the same address. A wildcard record works too.

The two names must share a registrable domain (`rmm.example.com` and
`mesh.rmm.example.com`, not `rmm.example.com` and `remote.example.net`).
Remote sessions run in an iframe on the MeshCentral name, and the cookie that
admits them is `SameSite=Strict`, so browsers send it only when the console
and MeshCentral are the same site. Remote sessions also need HTTPS with a
certificate browsers trust.

The edge routes by `Host`: the console name goes to the application, the
MeshCentral name to the remote-access gateway, anything else gets HTTP 421.
MeshCentral itself listens on loopback only and never sees a request the
gateway has not checked.

The EasyRMM agent talks to the console name under `/api/agent/v1/`:
enrollment with a deployment token, signed heartbeats, MeshAgent and its
settings (fetched by the server from MeshCentral over loopback), the install
script and the agent downloads. These routes take no browser session or
CSRF token; enrollment is rate-limited per address and everything after it
is signed with the device's key (ADR-0015).

## Firewall

Allow inbound TCP 443 (and 80 if using HTTP-01). Deny everything else
inbound. Outbound: 443 to Let's Encrypt (ACME) and to the EasyPatch server if
integrated; SMTP to your relay if e-mail notifications are enabled; and 443
to `github.com` (GitHub releases) when MeshCentral first starts, to download
its agent binaries (about 120 MiB, kept in its data directory afterwards).
