# ADR-0003: Go TLS edge, host networking and the port plan

* Status: Accepted (2026-11-15)

## Context
The deployment must use Docker host networking exclusively, expose as few
ports as possible, work without a mandatory internal NGINX, and also work
behind a customer's existing NGINX.

## Options
1. Caddy container as TLS edge in front of the server and MeshCentral.
2. NGINX container (rejected: the requirement says it must not be mandatory).
3. **The Go server itself terminates TLS** (`autocert`/manual certificates)
   and routes by host to its own handlers and to MeshCentral.

## Decision
Option 3. The server listens on `:443` (and optionally `:80` for ACME HTTP-01
and redirects). It owns routing to MeshCentral, which lets it gate every
browser request to MeshCentral on an EasyRMM authorization (ADR-0004), write
the certificate file MeshCentral needs for agent channel binding, and keep
the deployment to three containers. In `offload` mode it listens on loopback
HTTP for an upstream proxy and trusts `X-Forwarded-*` only from configured
addresses.

Port plan (all configurable):

| Listener | Bind | Purpose |
|---|---|---|
| 443/tcp | public | HTTPS: UI, API, agent gateway, MeshCentral hostname |
| 80/tcp | public, optional | ACME HTTP-01 and redirect to HTTPS |
| 15432/tcp | 127.0.0.1 | PostgreSQL |
| 14430/tcp | 127.0.0.1 | MeshCentral (HTTP, TLS offloaded) |
| 18080/tcp | 127.0.0.1 | Server in `offload` mode only |

MeshCentral listeners that would otherwise open on all interfaces (redirect
:80, Intel AMT MPS :4433, UDP multicast scanning, WebRTC/STUN) are disabled.

## Consequences
* Binding 443 requires `CAP_NET_BIND_SERVICE`; the container runs as a
  non-root user with only that capability.
* ACME state lives in the bind-mounted data directory.
* The edge must handle long-lived upgraded connections correctly (soak-tested).
