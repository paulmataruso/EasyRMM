# ADR-0035: EasyPatch on the same server, behind EasyRMM's edge

* Status: Accepted (2026-11-17).
* Refines: ADR-0003 (the Go edge on host networking), ADR-0010 and ADR-0030
  (the EasyPatch integration).

## Context
MSPs want EasyRMM and EasyPatch on one server. Both want ports 80 and 443:

* EasyRMM's edge is its own Go server (ADR-0003). It terminates TLS for the
  console and MeshCentral names, obtains their certificates, and routes by
  host name. It runs on host networking.
* EasyPatch runs Caddy in a container on Docker bridge networks. Caddy
  publishes 80 and 443, obtains EasyPatch's certificates with ACME (HTTP-01
  and TLS-ALPN-01), and sets EasyPatch's security headers.

Only one of them can own the ports, and EasyRMM owns them. Whatever sits in
front of EasyPatch must keep these properties:

* **Agents.** EasyPatch agents poll over HTTPS and sign each request with
  ECDSA over the method, exact path and query, timestamp, nonce and body
  hash. They follow no redirects and trust the operating system's
  certificate store, with no pinning. Any proxy must pass requests through
  byte for byte, with no redirects, and present a publicly trusted
  certificate for EasyPatch's name.
* **Client addresses.** EasyPatch rate-limits by client address and records
  the address of check-ins and audit entries. It trusts `X-Forwarded-For`
  only from its edge network, which Caddy sets from the connection's source.
  If another proxy simply connected to Caddy, every client would look like
  that proxy, sharing one rate limit, and the audit log would lose who acted.
* **Certificates and headers.** EasyPatch's certificates, HSTS, CSP and
  cookies (`__Host-easypatch-session`) are EasyPatch's. They should stay its
  own concern.
* **People** must still reach EasyPatch's own console by its URL. EasyPatch
  sends `frame-ancestors 'none'`, so EasyRMM cannot embed it.

## Decision
* **TLS passthrough by server name.** On the main HTTPS listener, the edge
  reads each connection's TLS ClientHello before doing any TLS itself. When
  the server name is `EASYRMM_EASYPATCH_HOSTNAME` (case-insensitive), it
  connects to `EASYRMM_EASYPATCH_TLS_UPSTREAM` (EasyPatch's Caddy on loopback,
  `127.0.0.1:19443` by default). It replays the bytes it read and relays both
  ways, still encrypted. Every other connection, including those with no
  server name or that are not TLS at all, goes to EasyRMM's own HTTPS server
  exactly as before. EasyRMM never holds EasyPatch's keys or sees its
  traffic. TLS-ALPN-01 challenges for EasyPatch's name pass through like
  any other connection.
* **PROXY protocol v2.** Each passed-through connection starts with a PROXY
  protocol v2 header naming the client (`EASYRMM_EASYPATCH_PROXY_PROTOCOL`,
  on by default). Caddy's `proxy_protocol` listener wrapper reads it, but
  only from EasyPatch's edge network. Docker's port publishing makes
  EasyRMM's connections arrive from that network's gateway. Caddy then sets
  `X-Forwarded-For` to the real client, as it does today. A client cannot
  forge a header itself:
  * the edge only passes through connections whose first bytes are a TLS
    ClientHello, and puts its own header in front;
  * Caddy's ports are published on loopback only.
* **Port 80.** For EasyPatch's name, `/.well-known/acme-challenge/` is
  reverse-proxied to `EASYRMM_EASYPATCH_HTTP_UPSTREAM` (`127.0.0.1:19080`)
  for HTTP-01. Everything else is redirected (308) to
  `https://<name><path>`. An empty upstream leaves TLS-ALPN-01 as Caddy's
  only challenge type.
* **EasyRMM never requests a certificate for EasyPatch's name.** Its ACME
  host list stays the console and MeshCentral names.
* **The connector takes the short way.** When EasyRMM's EasyPatch
  connection is `https://<EasyPatch name>` on port 443, the connector dials
  the TLS upstream directly. Over PROXY protocol it names its own loopback
  address as the client. The certificate is still checked against
  EasyPatch's name. A server behind NAT that cannot reach its own public
  address (no hairpin NAT) still works, and the traffic never leaves the
  host.
* **Configuration.** `EASYRMM_EASYPATCH_HOSTNAME` turns this on. It must be a
  DNS name different from EasyRMM's own names. Both upstreams must be
  loopback addresses. It is refused in `offload` mode, where a reverse proxy
  in front owns 443 and should route EasyPatch's name itself.
* **EasyPatch's side is configuration, not code.**
  `deploy/easypatch/docker-compose.easyrmm.yml` (a Compose override) and
  `Caddyfile.easyrmm` go into EasyPatch's install directory. The override:
  * publishes Caddy on `127.0.0.1:19080` and `127.0.0.1:19443` instead of
    80 and 443 (`ports: !override`);
  * runs Caddy with `Caddyfile.easyrmm`, which is EasyPatch's own Caddyfile
    plus the `proxy_protocol` and `tls` listener wrappers on `:443`.

  It works with the published `easypatch-proxy` 1.9.0 image as it is.
* **Opening EasyPatch.** The Patching page and Settings → EasyPatch link to
  EasyPatch's own console (its public URL, `https://` only) in a new tab.

## Consequences
* One server, one pair of public ports, two independent products. Each keeps
  its own certificates, headers, cookies and upgrades. EasyPatch's agents
  and browsers see exactly what they saw with Caddy on 443.
* EasyPatch depends on EasyRMM's edge being up. Restarting EasyRMM drops
  open EasyPatch connections. Agents retry at their next poll, and browsers
  reconnect.
* SNI is required for EasyPatch: a client that sends no server name reaches
  EasyRMM. Every agent and browser EasyPatch supports sends one.
* Anything on the host that can connect to `127.0.0.1:19443` can send a
  PROXY header Caddy believes. That is only local processes, which could
  already reach EasyPatch's containers.
* With PROXY protocol off, EasyPatch sees every client as Docker's gateway.
  Rate limits then apply to everyone together. The option exists for an
  EasyPatch without the listener wrapper, not for production.
* EasyPatch's own release could ship `Caddyfile.easyrmm`, so the override
  needs no mounted file. That is EasyPatch's choice to make; nothing here
  depends on it.

## Verification
* Unit and integration tests (`internal/app/passthrough_test.go`) use a real
  TLS upstream that parses PROXY headers as the specification describes.
  They cover:
  * the client's address and the certificate EasyPatch presents;
  * EasyRMM's own names, connections without a server name, and plain HTTP
    on 443, all unchanged;
  * port 80 challenges and redirects;
  * EasyPatch down, slow clients, and shutdown with connections open.
* `internal/proxyproto` checks headers against bytes written out from the
  specification.
* Checked end to end, outside CI, on the preview server:
  * EasyPatch's real `easypatch-proxy:1.9.0` image ran with the two files
    above, behind a full EasyRMM server.
  * Pebble, Let's Encrypt's test CA, issued EasyPatch's certificate through
    EasyRMM's edge, once by HTTP-01 and once by TLS-ALPN-01.
  * Requests through the edge reached EasyPatch's API with the real client
    address in `X-Forwarded-For`, along with Caddy's HSTS and CSP headers.
  * A client sending its own PROXY header through the edge never reached
    Caddy.
