# Network architecture

All containers use `network_mode: host`. Defaults below are configurable.

| Port | Bind | Service | Exposed? | Why |
|---|---|---|---|---|
| 443/tcp | `0.0.0.0` | easyrmm-server | **Yes** | HTTPS for UI, API, agent gateway, MeshCentral hostname |
| 80/tcp | `0.0.0.0` | easyrmm-server | Optional | ACME HTTP-01 challenges and redirect to HTTPS. Not needed when TLS-ALPN-01 or manual certificates are used |
| 15432/tcp | `127.0.0.1` | PostgreSQL | No | Database (non-default port avoids clashing with a host PostgreSQL) |
| 14430/tcp | `127.0.0.1` | MeshCentral | No | MeshCentral HTTP with TLS offloaded to the edge |
| 18080/tcp | `127.0.0.1` | easyrmm-server | No | Only in `offload` mode, behind an upstream NGINX |

Endpoints only make **outbound** connections to 443. No inbound endpoint
connectivity is ever required.

MeshCentral features that would open more ports are disabled: HTTP redirect
(:80), Intel AMT MPS (:4433), multicast scanning (UDP 16990), WebRTC and STUN.

## Host names

| Name | Purpose |
|---|---|
| `rmm.example.com` | Web UI, API, companion-agent gateway |
| `mesh.rmm.example.com` (configurable) | MeshCentral agents and embedded remote sessions (separate browser origin, ADR-0004) |

Both resolve to the same address. A wildcard record works too.

## Firewall

Allow inbound TCP 443 (and 80 if using HTTP-01). Deny everything else
inbound. Outbound: 443 to Let's Encrypt (ACME) and to the EasyPatch server if
integrated; SMTP to your relay if e-mail notifications are enabled.
