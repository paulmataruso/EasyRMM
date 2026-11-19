# Network architecture

All containers use `network_mode: host`. Defaults below are configurable.

| Port | Bind | Service | Exposed? | Why |
|---|---|---|---|---|
| 443/tcp | `0.0.0.0` | easyrmm-server | **Yes** | HTTPS for UI, API, agent gateway, MeshCentral hostname |
| 4443/tcp | `0.0.0.0` | easyrmm-server | With IP access | Remote sessions and MeshAgent on an IP address (`https://<address>:4443`, ADR-0016). Not opened with `EASYRMM_IP_ACCESS=false` or in offload mode |
| 80/tcp | `0.0.0.0` | easyrmm-server | Optional | ACME HTTP-01 challenges and redirect to HTTPS. Not needed when TLS-ALPN-01 or manual certificates are used |
| 15432/tcp | `127.0.0.1` | PostgreSQL | No | Database (non-default port avoids clashing with a host PostgreSQL) |
| 14430/tcp | `127.0.0.1` | MeshCentral | No | MeshCentral HTTP with TLS offloaded to the edge |
| 18080/tcp | `127.0.0.1` | easyrmm-server | No | Only in `offload` mode, behind an upstream NGINX |
| 18081/tcp | `127.0.0.1` | easyrmm-server | No | Liveness (`/healthz`) and readiness (`/readyz`) probes used by the container health check |
| 19443/tcp, 19080/tcp | `127.0.0.1` | EasyPatch's Caddy | No | Only when EasyPatch shares the server: EasyRMM's edge passes EasyPatch's name through to them (ADR-0035, [easypatch-cohost.md](../deployment/easypatch-cohost.md)) |

Endpoints only make **outbound** connections to 443. No inbound endpoint
connectivity is ever required.

MeshCentral features that would open more ports are disabled: HTTP redirect
(:80), Intel AMT MPS (:4433), multicast scanning (UDP 16990), WebRTC and STUN.

## Host names

| Name | Purpose |
|---|---|
| `rmm.example.com` | Web UI, API, EasyRMM agent API (`/api/agent/`) and installers |
| `mesh.rmm.example.com` (configurable) | MeshCentral agents and embedded remote sessions (separate browser origin, ADR-0004) |
| `patch.example.com` (optional) | EasyPatch on the same server (`EASYRMM_EASYPATCH_HOSTNAME`): passed through by SNI, still encrypted, to EasyPatch's own Caddy (ADR-0035) |
| An imported EasyPatch's names (optional) | `EASYRMM_PATCHING_AGENT_HOSTNAMES`: its agents keep the address they enrolled with. EasyRMM's edge serves them with TLS like its own names, sends the EasyPatch agents' paths to the patching engine, and sends anything else to the console's patching pages |

All resolve to the same address. A wildcard record works too.

The two names must share a registrable domain (`rmm.example.com` and
`mesh.rmm.example.com`, not `rmm.example.com` and `remote.example.net`).
Remote sessions run in an iframe on the MeshCentral name, and the cookie that
admits them is `SameSite=Strict`, so browsers send it only when the console
and MeshCentral are the same site. Remote sessions also need HTTPS with a
certificate browsers trust.

The edge routes by `Host`, host and port: the console name goes to the
application, the MeshCentral name to the remote-access gateway, an imported
EasyPatch's names to the patching engine's agent paths, anything else gets
HTTP 421. A co-hosted EasyPatch's name is taken out earlier, by the TLS
server name, before the edge does any TLS of its own.
MeshCentral itself listens on loopback only and never sees a request the
gateway has not checked.

The EasyRMM agent talks to the console name under `/api/agent/v1/`:
enrollment with a deployment token, signed heartbeats, MeshAgent and its
settings (fetched by the server from MeshCentral over loopback), the install
script and the agent downloads. These routes take no browser session or
CSRF token; enrollment is rate-limited per address and everything after it
is signed with the device's key (ADR-0015).

## IP addresses

DNS is the recommended setup, but the server also answers on its IP
addresses (ADR-0016), so you can get in when DNS is not working, or run
without DNS at all:

| Address | Purpose |
|---|---|
| `https://203.0.113.10` | Web UI, API, agent API and installers |
| `https://203.0.113.10:4443` | MeshCentral: embedded remote sessions (and MeshAgent in an IP-only deployment) |

The two differ only in port, which makes them different browser origins of
the same site. Because browsers share cookies across ports, the gateway
removes EasyRMM's cookies before anything reaches MeshCentral and drops any
cookie MeshCentral tries to set under an EasyRMM name.

No public certificate authority certifies these addresses, so the server
uses its own (`EASYRMM_TLS_MODE=internal`, or automatically for the IP
addresses beside a DNS name). Browsers warn until you install the authority;
the console shows its fingerprint and a download under **Devices → Add
devices**. Agents installed through an IP address pin the server's key in
the install command and trust the authority afterwards.

| Setting | Default | Meaning |
|---|---|---|
| `EASYRMM_IP_ACCESS` | `true` | Answer on the IP addresses beside the public URL. `false` serves the public URL only |
| `EASYRMM_IP_ADDRESSES` | detected | Comma-separated addresses. Detected: the source addresses of the default routes. Behind NAT, list the public address |
| `EASYRMM_IP_MESH_PORT` | `4443` | MeshCentral's port on an IP address |

For an IP-only deployment set `EASYRMM_PUBLIC_URL=https://203.0.113.10`; the
MeshCentral URL becomes `https://203.0.113.10:4443` and TLS uses the internal
authority.

In a DNS deployment, MeshAgent keeps connecting to the MeshCentral *name*,
since MeshCentral writes that into its settings: a device enrolled by IP
address needs DNS for remote sessions, although its EasyRMM agent works over
the address.

## Firewall

Allow inbound TCP 443 (and 80 if using HTTP-01, and 4443 for IP access).
Deny everything else inbound. Outbound: 443 to Let's Encrypt (ACME) and to the EasyPatch server if
integrated; SMTP to your relay if e-mail notifications are enabled; and 443
to `github.com` (GitHub releases) when MeshCentral first starts, to download
its agent binaries (about 120 MiB, kept in its data directory afterwards).
