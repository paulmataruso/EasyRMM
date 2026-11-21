# ADR-0016: Reaching the server by IP address

* Status: Accepted (2026-11-15). Refines ADR-0003 (TLS edge) and ADR-0004
  (MeshCentral origin). Amended (2026-11-21): MeshCentral's `allowedOrigin`
  lists every MeshCentral origin.

## Context
ADR-0003 provides TLS from ACME, the operator's files, or a proxy, and
ADR-0004 puts MeshCentral on a hostname of its own. Both assume DNS. An MSP
technician must still be able to get in when DNS is not working (a customer
network with a broken resolver, an expired domain, a DNS outage), and some
deployments have no DNS at all (a lab, a closed network). DNS remains the
recommended setup; the IP address must work alongside it, and on its own.

An IP address changes four things browsers and agents rely on:

* **Certificates.** Public CAs do not certify private addresses, and
  certifying a public one needs the address reachable from the CA and
  frequent renewal. Browsers send no server name (SNI) for an IP address.
* **One host for the console and MeshCentral.** An address has no
  subdomains, so the two can only differ by port. Different ports are
  different origins, so the browser keeps scripts apart. They are still the
  same site, so embedded sessions work.
* **Cookies are not isolated by port.** A cookie set by
  `https://203.0.113.10` is also sent to `https://203.0.113.10:4443`, and the
  other way round.
* **The server cannot know its own public address** behind NAT.

## Decision
* **Origins.** The server answers on its public URL, which may be a DNS name
  or an IP address. With **IP access** on (`EASYRMM_IP_ACCESS`, default
  `true`) it also answers on each of its IP addresses:
  * the console and the agent API on `https://<address>`, at the public URL's
    port;
  * MeshCentral on `https://<address>:4443` (`EASYRMM_IP_MESH_PORT`).

  The addresses are `EASYRMM_IP_ADDRESSES`. If that is empty, the server
  detects the source addresses of its default routes: it connects a UDP
  socket, which sends nothing. Behind NAT the operator lists the public
  address. With `EASYRMM_IP_ACCESS=false` only the public URL is served.
* **IP-only deployments.** `EASYRMM_PUBLIC_URL=https://203.0.113.10`. The
  MeshCentral URL then defaults to `https://203.0.113.10:4443` and the TLS
  mode to `internal`. ACME is refused for an IP address with an explanation.
  `manual` works when the operator's certificate names the address. The
  public and MeshCentral URLs must differ in host or port, and must remain
  same-site.
* **Routing by host and port.** A request goes to the console, or to the
  MeshCentral gateway, by its `Host` header compared as host and port, with
  443 assumed when no port is given. A host that only one kind of route uses
  also matches on any port. This keeps proxies that change the port, and the
  development server, working. A host shared by both needs the right port.
  In direct TLS modes the server also listens on each MeshCentral port that
  differs from the console's.
* **The internal certificate authority** (`server/internal/pki`):
  * The authority's certificate is ECDSA P-256 and lasts ten years. Its path
    length is 0, so it can certify only servers, not other authorities.
  * It is created on first use and stored sealed in `settings`
    (`tls.internal_ca`) under the secret key. When two servers start at
    once, the first one stored wins.
  * The server certificate (the leaf) lasts one year and is renewed 30 days
    before it expires. It always uses the same server key, so the pin in an
    install command stays valid.
  * The leaf is stored in `settings` (`tls.internal_cert`, not sealed: it
    is public) and served again after a restart while it names the same
    addresses and is not due for renewal; servers starting together serve
    the first one stored. A restart must not change it: MeshAgent pins the
    exact certificate, and MeshCentral re-reads it at most every two
    minutes (ADR-0014). Until 2026-11-17 every start issued a new leaf, and
    two restarts within two minutes left every MeshAgent held by
    MeshCentral until MeshCentral restarted.
  * The leaf names every origin served by the internal authority: its IP
    addresses, and its DNS names in `internal` mode.
  * Which certificate a connection gets:
    * a server name: the configured source (ACME or files);
    * no server name: the internal authority;
    * MeshCentral reading its own certificate from the same host
      (`EASYRMM_MESH_CERT_URL`): the MeshCentral origin's. Without this, ACME
      would refuse that connection for lack of a server name.
  * Behind an offloading proxy, the proxy terminates TLS, so IP access needs
    explicit addresses there and the proxy's own certificate.
* **Trust.**
  * *Browsers* warn until the authority is installed. The console shows its
    SHA-256 fingerprint and offers it for download (Devices → Add devices).
    Browsers do not apply HSTS to IP addresses, so a warning can be clicked
    through.
  * A browser cannot show a certificate warning inside a frame, and some
    browsers (Firefox) keep exceptions per port. The launch response
    therefore says when a session's origin uses the internal authority, and
    the session page offers help: open the MeshCentral origin once and
    accept its warning, or install the authority.
  * *Agents* installed through an internal address get an install command
    that pins the server's key:
    `curl -fsSL --insecure --pinnedpubkey 'sha256//…'`. `--insecure` skips
    only the CA check; curl still refuses a different key. A test against
    curl itself shows a wrong pin is refused.
  * The install script then needs curl, because wget cannot pin. It fetches
    the authority's certificate (`/api/agent/v1/ca.pem`) over the pinned
    connection and enrolls the agent with `--ca-file`. From then on the agent
    trusts only that authority, and checks that the certificate names the
    address it connects to.
* **Remote sessions from an IP console.**
  * A session started from a console origin launches on that origin's
    MeshCentral origin.
  * MeshCentral's `allowedFramingOrigins` lists every console origin.
  * MeshCentral's `allowedOrigin` lists the host of every MeshCentral
    origin. MeshCentral checks the `Origin` of a session's control
    connection against that list, and without one accepts only its own
    name (`cert`). It is never `true`, which accepts any origin.
    *Amended 2026-11-21:* until then it was not set, so MeshCentral closed
    every session started from any other MeshCentral origin
    (`invalidorigin`): the addresses of a DNS deployment, and an IP-only
    deployment's addresses other than the public URL's. The list is
    written from the origins the server serves on every start, so origins
    added later are allowed with them; when it changes, MeshCentral's start
    script restarts MeshCentral.
  * The console's CSP `frame-src` lists every MeshCentral origin.
  * The CSRF origin check accepts every console origin.
* **Cookies across ports.**
  * The gateway removes every EasyRMM cookie (`__Host-easyrmm*`,
    `easyrmm*`) from requests it forwards, so MeshCentral never sees the
    console's session.
  * It also drops any `Set-Cookie` from MeshCentral that uses an EasyRMM
    cookie name.

## Consequences
* The console, enrollment and remote sessions work without DNS, either as
  the whole deployment or as a way in when DNS fails. Agents installed by IP
  address keep using that address. (Remote sessions from an address other
  than MeshCentral's own name work since the 2026-11-21 amendment above.)
* **MeshAgent always uses the primary MeshCentral origin.** That origin is
  written into MeshAgent's settings by MeshCentral, and MeshCentral checks
  that agents see the certificate it reads from `EASYRMM_MESH_CERT_URL`, a
  single certificate.
  * In a DNS deployment, a device enrolled by IP address therefore runs the
    EasyRMM agent over the IP address, but needs DNS for remote sessions.
  * An IP-only deployment has no such gap.
* **Sharing a host is weaker isolation than ADR-0004's separate hostnames.**
  Script running on the MeshCentral port could still set cookies that the
  console receives. The gateway filters MeshCentral's `Set-Cookie` headers,
  but cannot filter cookies set by script. The console's cookies are
  `HttpOnly`, and its CSRF token is bound to the session. DNS stays the
  recommended deployment, and the documentation says so.
* A certificate warning teaches people to click through warnings. The
  console therefore explains how to install the authority and verify its
  fingerprint.
* IP access opens port 4443 by default (host networking); the deployment
  guide names it for firewalls. `EASYRMM_IP_ACCESS=false` closes it.
* The internal authority renews the server certificate with the same key,
  so what MeshCentral reads from `EASYRMM_MESH_CERT_URL` keeps its key
  across renewals.
* **The authority has no name constraints** (the security review before the first release). A
  computer that trusts it would accept a certificate for any site signed
  with its key, not only for EasyRMM. Constraining it to the server's
  names and addresses was considered and rejected:
  * Agents trust the authority's certificate itself, stored at install.
    Go checks name constraints against every name in the server's
    certificate.
  * The authority must outlive address changes; that is the point of a
    ten-year authority. Once the server gained a name or address outside
    the constraints, every agent would stop connecting.
  * A constrained certificate cannot be swapped in later without
    reinstalling every agent.

  The key is sealed under the server's secret key, in the database. Anyone
  who can open it already controls the server, and through it every
  managed device. The documentation therefore asks for the authority to be
  installed only on the computers technicians administer EasyRMM from. It
  recommends a DNS name with a public certificate wherever browsers reach
  the console. For agents the trust is narrow already: only the agent
  uses its copy.

## Alternatives considered
* **Wildcard DNS services such as sslip.io.** They depend on outside DNS,
  which is the very thing that may be failing.
* **Public CA certificates for IP addresses.** They need a public address
  reachable from the CA and renewal every few days, and they cannot cover
  private addresses.
* **A new self-signed certificate on every start.** The pin would change,
  and any trust already placed in the certificate would be lost.
* **MeshCentral under a path of the console origin.** MeshCentral's pages
  would then share the console's origin, which breaks ADR-0004's isolation
  completely rather than only for cookies.
