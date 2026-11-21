# ADR-0055: Let's Encrypt in one step

* Status: Proposed (2026-11-21). Not implemented. Revised after an
  independent review the same day.
* Builds on: [ADR-0003](0003-go-edge-host-networking.md) (the TLS edge),
  [ADR-0004](0004-meshcentral-dedicated-origin.md) and
  [ADR-0014](0014-remote-access-gateway-and-device-discovery.md)
  (MeshCentral's name, and how it reads the certificate its agents see),
  [ADR-0016](0016-ip-address-access.md) (IP access and the internal
  certificate authority), [ADR-0009](0009-agent-protocol.md) (protocol
  levels, as amended by pull request #52),
  [ADR-0027](0027-agent-updates.md) (signed
  instructions in the heartbeat, probation and rollback),
  [ADR-0031](0031-easypatch-agent-install.md) and
  [ADR-0042](0042-agents-trust-easyrmms-authority.md) (EasyPatch agents
  and that authority), [ADR-0034](0034-oidc-single-sign-on.md) (providers
  trusted to enforce MFA), [ADR-0044](0044-authentik-when-chosen.md)
  (Authentik's name), [ADR-0052](0052-the-host-updater.md) (`hold`,
  backups and rollback), and the notification sender of ADR-0053
  (proposed).
* Part of [the feature plan](../feature-plan.md): feature 5, slices 5a and
  5b (5b1 to 5b4). Slice 5c, moving agents and the console to a new name,
  needs the job key's rotation (F0) and gets an ADR of its own; this one
  says where it begins.

## Context
The owner asked for "a super easy way to setup letencrypt certs for
everything, it should be dead simple, and renew automaticlyty for the
user".

### What exists
* **Four TLS modes**, chosen in `.env` (`EASYRMM_TLS_MODE`) and read at
  start (`server/internal/config/config.go`, `TLSMode`): `acme`, `manual`
  (`EASYRMM_TLS_CERT_FILE`, `EASYRMM_TLS_KEY_FILE`), `internal` (the
  server's own authority, `server/internal/pki`) and `offload` (a proxy in
  front). A DNS name defaults to `acme`, an IP address to `internal`
  (`LoadFrom`), and `acme` is refused for an IP address (`validate`;
  `deploy/scripts/setup.sh` refuses it too).
* **`acme` mode is `autocert`** (`edge.run` in
  `server/internal/app/edge.go`): a `HostWhitelist` of the names
  `acmeHosts` lists (the DNS origins' console and MeshCentral names and
  `config.ExtraHostnames`: Authentik's name and an imported EasyPatch's
  names), HTTP-01 on port 80 (`m.HTTPHandler`) and TLS-ALPN-01 on every
  TLS listener (`acme.ALPNProto`), its account and certificates in
  `<data dir>/acme` (`autocert.DirCache`). A certificate is ordered at the
  first handshake that asks for the name. `autocert` uses no ACME Renewal
  Information; it renews at the lesser of 30 days or a third of the
  lifetime before expiry (`RenewBefore` in `golang.org/x/crypto`'s
  `acme/autocert`). `EASYRMM_ACME_EMAIL` is required (`validate`), and
  `setup.sh --with-authentik` fills it with the administrator's address
  when none is given (`authentik_ask`). `EASYRMM_ACME_DIRECTORY` exists;
  the root to trust for another directory's own HTTPS does not. The
  server's environment is an explicit list in `deploy/docker-compose.yml`,
  so a variable that is not on it never reaches the server.
* **Which certificate a connection gets** (`edge.certificates`). In
  `internal` mode, the authority's, for every connection. Otherwise a DNS
  server name gets the mode's source; a connection without one (an IP
  address) gets the internal authority, except MeshCentral reading its
  own certificate from this host (`fromThisHost`), which gets the
  MeshCentral name's. In `manual` mode the file must also cover
  Authentik's and the imported names (`covers`).
* **One authority certificate for every internal origin.** The authority
  issues a single certificate for the names and addresses of the origins
  marked internal (`internalAddresses` in
  `server/internal/app/origins.go`; `Authority.SetAddresses` in
  `server/internal/pki/pki.go`) and issues it again whenever that set
  changes, which every MeshAgent on an IP address then sees.
* **Names are fixed at start.** The router (which answers `421` for any
  other host), the console origins that the CSRF check accepts, the CSP's
  `frame-src`, MeshCentral's `allowedFramingOrigins`, the install scripts
  and the authenticator issuer are all built once from `.env` (`Build`,
  `Handler` and `MeshServerConfig` in `server/internal/app/app.go`;
  `agentapi.New` renders one script per origin).
* **What trusts what:**
  * *EasyRMM's agent* trusts the system's roots, or, when installed with
    `--ca-file`, only that file (`client.New` in `agent/client/client.go`
    replaces `RootCAs`; the path is kept in `state.Config`). Install
    commands pin and hand over the internal authority for every origin
    the authority serves (`origins` in `server/internal/app/origins.go`;
    `install.sh.tmpl` and `install.ps1.tmpl` in
    `server/internal/httpapi/agentapi`), and `--ca-file` is also the
    documented way to trust a private CA in `manual` mode. So an agent
    installed through a DNS name in `internal` mode trusts the authority
    and nothing else, and one installed under a public certificate trusts
    the system's roots and nothing else.
  * *The EasyPatch agent* trusts the system's store and, when its install
    instruction carried one, the server's authority as well
    (`AgentHttpClientFactory` in
    `easypatch/agent/EasyPatch.Agent/Platform`). Instructions carry the
    authority only in `internal` mode (ADR-0042; `CACert` in
    `internal/agentproto/easypatch.go`). It reaches the engine at
    `EASYRMM_PUBLIC_URL` (`EasyPatch__PublicUrl` in
    `deploy/docker-compose.yml`).
  * *MeshAgent* pins MeshCentral's agent certificate (`ServerID` in its
    `.msh` is that certificate's key hash: `webserver.js` of MeshCentral
    1.3.1, the version `deploy/docker-compose.yml` pins), not the TLS
    certificate, and checks no TLS chain. At each connection it reports
    the hash of the TLS certificate it saw; MeshCentral compares it with
    the one it read from `certUrl` and, when they differ, holds the agent
    and reads `certUrl` again, at most once every two minutes, then
    disconnects the held agents so they reconnect, but only if the hash
    it read changed (`meshagent.js` and `updateProxyCertificates` in
    `meshcentral.js`). EasyRMM sets `certUrl` to its own listener without
    a server name (`EASYRMM_MESH_CERT_URL`, `defaultCertURL`) and rewrites
    MeshCentral's `config.json` only when it changes; MeshCentral's start
    script restarts it then (`docker/meshcentral/start.sh`). A second
    change within those two minutes leaves agents held until MeshCentral
    restarts (ADR-0014; `docs/deployment/docker.md`).
  * *The server itself* reaches Authentik's name through its own edge,
    trusting the system's roots and, in `internal` mode, its authority
    (`authentikClient` in `server/internal/app/authentik.go`).
* **MeshCentral checks the browser's origin.** Its `control.ashx`
  WebSocket, which its pages open in every remote session, is closed with
  `invalidorigin` unless the `Origin` header's host name is MeshCentral's
  own name (`settings.cert`) or is listed in the domain's `allowedOrigin`
  (`CheckWebServerOriginName` in `webserver.js` of MeshCentral 1.3.1).
  EasyRMM writes `cert` (the MeshCentral name of `EASYRMM_MESH_PUBLIC_URL`)
  and `allowedFramingOrigins`, but no `allowedOrigin` (`Render` in
  `server/internal/meshcentral/config.go`, `MeshServerConfig` in
  `server/internal/app/app.go`), and the remote gateway passes the header
  through unchanged (`server/internal/remote/gateway.go`). So a session
  launched from another MeshCentral origin, such as an IP-access origin
  of a DNS install (ADR-0016), is refused today: running MeshCentral
  1.3.1's own `CheckWebServerOriginName` in the pinned image refused an
  IP-access origin and accepted it once an `allowedOrigin` list included
  it. **This is fixed separately**, before this ADR's slices, on branch
  `fix/mesh-allowed-origin`: `Render` writes `allowedOrigin` with the host
  name of every MeshCentral origin. IPv6 addresses are written in
  brackets, because MeshCentral compares the list with Node's
  `URL.hostname`, which returns `[2001:db8::1]` for one.
* **Signed instructions.** The heartbeat's answer carries instructions
  signed with the job key, each under a context of its own, for one
  device, with a short validity (`HeartbeatResponse` in
  `internal/agentproto/agentproto.go`: updates, EasyPatch installs,
  uninstalls). An update that has not reached the server is undone by the
  agent; its first heartbeat that gets through confirms it and removes
  the previous build (ADR-0027).
* **Confirming a person.** `reauthenticate` asks for the password
  (`server/internal/auth/service.go`); accounts created through a
  provider have none. A session's `AuthenticatedAt` is set when it
  becomes active, not when a factor was last asked for, and recovery
  codes count as a second factor at sign-in. Requests to providers carry
  neither `prompt` nor `max_age` (`server/internal/sso`). WebAuthn is
  available only on a DNS name (`configureWebAuthn` in
  `server/internal/auth/webauthn.go`). `EASYRMM_REQUIRE_MFA=false` lets
  an account have no second factor.
* **The host updater's hold** (ADR-0052; the file `hold` in
  `/run/easyrmm-updater`, `EASYRMM_UPDATER_STATUS_DIR`, from pull request
  #51, open): while it exists the server answers only its health check.
* **Storage and backup.** The internal authority is sealed in `settings`
  and sealed again with the current key when read at start (`pki.Load`).
  The ACME cache is a directory, which the backup guide lists as its own
  part (`docs/operations/backup-restore.md`).
* **One server.** Several servers are not supported (ADR-0001); some
  choices below are groundwork for them and are labelled so.

### Let's Encrypt, November 2026
* **Lifetimes.** The default `classic` profile issues 90-day
  certificates today, 64-day ones from 10 February 2027 and 45-day ones
  from 16 February 2028; authorization reuse falls to 10 days and then
  7 hours. `tlsserver` (45 days) and `shortlived` (160 hours) are opt-in
  profiles. ([profiles](https://letsencrypt.org/docs/profiles/),
  [from 90 to 45](https://letsencrypt.org/2025/12/02/from-90-to-45),
  [64-day certificates](https://letsencrypt.org/2026/10/07/64-day-certs))
* **IP addresses** can be certified since 15 January 2026, only with the
  `shortlived` profile (160 hours) and only through HTTP-01 or
  TLS-ALPN-01, IPv4 and IPv6.
  ([general availability](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability),
  [challenge types](https://letsencrypt.org/docs/challenge-types/))
* **Renewal.** ACME Renewal Information is RFC 9773 (June 2025). Let's
  Encrypt asks clients to check it at least twice a day, to renew at a
  third of the lifetime left without it, and to back off after failures
  (1, 10 and 100 minutes, then at most once a day), never treating a
  failure as fatal. ([RFC 9773](https://www.rfc-editor.org/info/rfc9773),
  [integration guide](https://letsencrypt.org/docs/integration-guide/))
* **Rate limits.** 50 new certificates per registered domain (or IPv4
  address, or IPv6 /64) per 7 days; 5 per exact set of names per 7 days,
  without overrides; 5 failed authorizations per name per account per
  hour; 300 orders per account per 3 hours; 10 accounts per IP address per
  3 hours. A renewal through ARI is exempt from all of them. A name that
  keeps failing is paused for the account, and only Let's Encrypt's
  self-service page lifts the pause.
  ([rate limits](https://letsencrypt.org/docs/rate-limits/))
* **Staging**, `https://acme-staging-v02.api.letsencrypt.org/directory`,
  has far higher limits, accounts of its own, and roots no store trusts.
  ([staging](https://letsencrypt.org/docs/staging-environment/))
* **No expiry emails, no OCSP.** Expiry emails ended on 4 June 2025; an
  address given through ACME is no longer stored but forwarded to ISRG's
  general mailing list. OCSP URLs left certificates on 7 May 2025.
  ([notification service ended](https://letsencrypt.org/2025/06/26/expiration-notification-service-has-ended),
  [upcoming features](https://letsencrypt.org/upcoming-features/))
* **Validation** comes from several places on the Internet, from addresses
  Let's Encrypt does not publish. It connects over IPv6 first when a name
  has an `AAAA` record, and retries over IPv4 only after a timeout, so an
  `AAAA` record that points elsewhere fails validation even when the `A`
  record is right. CAA (`letsencrypt.org`, with `accounturi` and
  `validationmethods`) is checked up the tree.
  ([integration guide](https://letsencrypt.org/docs/integration-guide/),
  [IPv6](https://letsencrypt.org/docs/ipv6-support/),
  [CAA](https://letsencrypt.org/docs/caa/))
* **DNS-PERSIST-01**, one standing TXT record instead of DNS credentials,
  was announced for 2026; the last statement we found (25 June 2026) says
  it will not be deployed in production until an open question in the
  draft is settled.
  ([announcement](https://letsencrypt.org/2026/02/18/dns-persist-01),
  [status thread](https://community.letsencrypt.org/t/dns-persist-01-deployment-status-and-timeline/246468))
* **Chains.** ECDSA certificates are issued by the intermediates YE1 and
  YE2 (RSA by YR1 and YR2), and served by default as leaf ← YE1 or YE2 ←
  Root YE ← ISRG Root X2 ← ISRG Root X1: Root YE is cross-signed by X2,
  and X2 by X1. Roots YE and YR are submitted to trust stores but not yet
  widely trusted, so a store without X1 or X2 cannot verify the chain.
  ([chain of trust](https://letsencrypt.org/certificates/))

### CertMagic v0.25.6
CertMagic (Apache 2.0, `github.com/caddyserver/certmagic`, v0.25.6 of 30
September 2026) is the library this ADR uses. As read in its source:

* `ManageAsync` and `ObtainCertAsync` retry a failed order on a fixed
  schedule (1, 2, 2, 5, 10 minutes … then every 6 hours, for 30 days),
  held in memory and lost at a restart (`retryIntervals` in `async.go`).
  Every retry after the first asks the `TestCA` first, which is Let's
  Encrypt's staging service when the CA is Let's Encrypt's, and production
  only once staging succeeds (`ACMEIssuer.Issue` in `acmeissuer.go`).
* Renewals by its maintenance loop make one attempt per check, every
  `RenewCheckInterval` (10 minutes by default, `maintain.go`), with a
  backoff held in memory. ARI is refreshed only in that loop and when a
  name is first managed (`manageOne`).
* `ObtainCertSync` and `RenewCertSync` make one attempt, without the
  retry loop; with no attempt count in their context they never use
  `TestCA`.
* Every attempt, whoever starts it, first emits `cert_obtaining` to
  `OnEvent`, under the name's storage lock; an error from the handler
  cancels the attempt (`config.go`). Nothing in it knows of a hold.
* Those two calls are its only exported one-attempt calls, and both are
  interactive: they reach `ACMEIssuer.setEmail` with prompts allowed
  (`PreCheck` in `acmeissuer.go`). With an empty email, `setEmail` takes
  the address of the most recently written account stored under that
  CA's account keys (`mostRecentAccountEmail` in `account.go`); when
  there is none, it prints a prompt, reads standard input, and on end of
  input silently sets the package-wide `DefaultACME.Agreed` to true.
  `AccountKeyPEM` names the account to use for the order itself.
* DNS-01's propagation check asks the resolvers in `resolv.conf` and,
  when it has none, Google's and Cloudflare's public resolvers; it waits
  at most 2 minutes by default (`dnsutil.go`, `solvers.go`).

## Decision

### What "everything" is
| Name | Where it comes from | Certificate |
|---|---|---|
| The console's name | `EASYRMM_PUBLIC_URL` when it is a DNS name | Let's Encrypt |
| MeshCentral's name | `EASYRMM_MESH_PUBLIC_URL` (by default `mesh.` and the console's name) | Let's Encrypt |
| Authentik's name | `EASYRMM_AUTHENTIK_HOSTNAME` | Let's Encrypt |
| An imported EasyPatch's names | `EASYRMM_PATCHING_AGENT_HOSTNAMES` | Let's Encrypt |
| A name pair added to an IP install (5b3) | The console | Let's Encrypt; the authority's second certificate for agents when it is not trusted |
| The server's IP addresses, and IP-only installs | IP access (ADR-0016) | Always the internal authority |
| Anything, in `offload` mode | The proxy | The proxy's |

* **One certificate per name**, not one for all names: a name that fails
  validation holds back no other, adding Authentik's name does not change
  MeshCentral's certificate (which would make MeshCentral hold its
  agents), and a renewal touches one name.
* **No wildcard certificates.** They need DNS-01 for the whole zone, and
  a wildcard key on this server would also be valid for every other host
  in the zone. A wildcard DNS *record* still works, as the guide says.
* **No Let's Encrypt certificates for IP addresses.** Agents installed
  through an IP address trust only the internal authority (above), so a
  public certificate there would cut every one of them off; it could not
  be told apart from a browser at the handshake, since neither sends a
  server name for an address. A 160-hour certificate also leaves days, not
  weeks, to notice a failing renewal, and private addresses cannot be
  validated at all. An IP-only install gets browser trust by getting a
  name (5b3).

### Certificates through CertMagic (5a)
CertMagic replaces `autocert` for the names above:

* **A managed list, issued at start**, not at the first handshake;
  on-demand issuance is never on. Every order and renewal is started and
  paced by EasyRMM (next section).
* **Renewed by ACME Renewal Information**, which CertMagic checks at
  least twice a day; where a CA offers none, at a third of the lifetime
  left (`RenewalWindowRatio`). No profile is requested: the CA's default,
  so the move to 64 and 45 days needs no change. Nothing assumes 90 days:
  every threshold below is a fraction of the certificate's own lifetime.
* **No OCSP stapling** (`OCSPConfig.DisableStapling`): Let's Encrypt has
  no OCSP, and the server then makes no OCSP requests for a private CA's
  certificates either.
* **Keys**: ECDSA P-256, a new key at each renewal.
* **Challenges**: HTTP-01 on port 80 when `EASYRMM_LISTEN_HTTP` is set,
  and TLS-ALPN-01 on 443, as today. They are answered only for names on
  the managed list or with an order pending, from storage, and nothing
  else under `/.well-known/acme-challenge/` is answered or passed on.
* **No email by default, and the account chosen explicitly.**
  `EASYRMM_ACME_EMAIL` becomes optional, and empty means no contact
  address: Let's Encrypt sends nothing to it any more, and would only pass
  it to ISRG's mailing list. Expiry is watched by EasyRMM (below).
  `setup.sh` stops requiring `--acme-email` and stops copying
  `--admin-email` into it; an address already in `.env` is kept.
* **The account is chosen explicitly, and standard input is never
  read.** The account EasyRMM registered or imported is named for each
  order (`AccountKeyPEM`), with its own address or none. Since the calls
  EasyRMM uses are interactive (above), a precondition holds before any
  of them runs: that account (its registration and key) is saved under
  CertMagic's account keys for the CA in use (`acme/<CA>/users/<address
  or "default">/`, in `tls_storage`), and it is the only account stored
  for that CA, so `mostRecentAccountEmail` finds it and the prompt is
  never reached. The staging configuration of the trial order keeps its
  own account the same way. Registration, the import and the start of the
  certificate service establish it, and the service refuses to make an
  attempt when it does not hold. A test proves standard input is never
  read and `DefaultACME.Agreed` never changes.
* **The Subscriber Agreement** is accepted by the operator: at install by
  choosing `acme` (setup.sh prints the link), in the console by **Agree
  and get certificates** (5b2).
* **Another ACME CA is supported**: `EASYRMM_ACME_DIRECTORY` (exists) and
  a new `EASYRMM_ACME_CA_FILE`, a PEM file under `EASYRMM_TLS_DIR` holding
  the roots to trust for that directory's own HTTPS (CertMagic's
  `TrustedRoots`) and for the server's own connections to its names
  (`authentikClient`). Both are on the compose file's environment list.
  Devices must already trust that CA (an enterprise PKI); install commands
  do not carry it. The tests use it for Pebble.
* **A name that does not resolve here** is shown as "waiting for DNS
  since …" and checked again every minute; it is ordered once it
  resolves, or at once when a super administrator presses **Order
  anyway** (split-horizon resolvers, where the server cannot see the
  public answer). Either way it alerts after an hour without a
  certificate (below).
* **The upgrade issues nothing, and registers no account.** At the first
  start of 5a, under the storage lock, `autocert`'s account key
  (`acme_account+key`) and the ECDSA certificate of every name still
  valid (the entries named after the name alone; `+rsa` and `+token`
  entries are skipped) are imported, and that account is named from then
  on. The directory is left in place, so a rollback (ADR-0052) still finds
  it. The import stays until a release states that upgrades must pass
  through 5a.
* **Several servers (groundwork, since ADR-0001 supports one)**: the
  storage is PostgreSQL (below), so instances share one set. The one that
  obtains a certificate sends `NOTIFY`; the others load it, and, since a
  notification is lost while a connection is down, each also compares
  the serials in storage with those it serves every minute and after
  every reconnection.

### Every attempt is EasyRMM's (5a)
CertMagic's own retries would go to staging, forget everything at a
restart (a server in a crash loop would make about 60 production attempts
an hour and get its name paused), and ignore a hold. So EasyRMM decides
every attempt and CertMagic carries it out:

* **`tls_certificates` holds, per name**, the next attempt allowed, the
  failed validations in the last hour, the time it started failing, the
  last error, the certificate's serial, validity and ARI window, and, for
  MeshCentral's name, the time of MeshCentral's last read of `certUrl`
  (below).
* **The scheduler** runs every minute in one server at a time (an
  advisory lock), takes the names that need a certificate or a renewal
  (CertMagic answers whether one is needed: ARI's window, or a third of
  the lifetime left) and whose next attempt has come, and makes one
  attempt for each: `ObtainCertSync` for a name without a certificate
  (then `CacheManagedCertificate`, which puts it under the maintenance
  loop), `RenewCertSync` for a renewal. `ManageAsync`'s retry loop is not
  used, and `TestCA` is set to the CA itself as a second guard, so that
  nothing ever goes to staging but the trial order.
* **CertMagic's maintenance loop keeps running**: it is where ARI is
  refreshed, and where a certificate another server renewed is loaded.
  Its own renewal attempts are cancelled by the gate below, and each
  cancellation is logged and recorded as a failure in its in-memory
  backoff (`maintain.go`). That is noise in the log, and harmless, since
  EasyRMM decides when attempts happen.
* **Every attempt passes one gate**: the `cert_obtaining` handler, under
  the name's storage lock, cancels any attempt the scheduler did not
  start (CertMagic's maintenance loop among them), any attempt whose time
  has not come, any while the hold file exists, and any the failure
  budget forbids; it writes the attempt to `tls_certificates` before
  letting it go. State lives in the database, so a restart repeats
  nothing.
* **Retries** follow Let's Encrypt's guide, after 1, 10 and 100 minutes,
  then once a day, each wait capped at a tenth of the renewal window (so
  that a short-lived certificate still gets several attempts). At one a
  day a name is never paused.
* **The failure budget**: automatic attempts stop after 3 failed
  validations of a name within an hour. **Retry now** on the Certificates
  page makes one attempt at once, and is refused, saying when it can run,
  once 4 have failed within the hour: Let's Encrypt allows 5.
* **During a hold** (the file `hold` in `/run/easyrmm-updater`, pull
  request #51) no attempt is made; attempts that come due wait for its end.
  The hold answers port 80 and 443 with `503` anyway, so an attempt would
  only fail.

### Where keys and certificates live
* **`tls_storage`**, a key/value table implementing CertMagic's `Storage`
  and `Locker`: account keys, certificate keys and certificates. Every
  value is sealed with `EASYRMM_SECRET_KEY`, with its key as associated
  data so that a value copied to another row does not open (as ADR-0047
  binds tokens). Values sealed with a previous key are sealed again with
  the current one when read at start, as `pki.Load` does, since account
  keys and DNS credentials are otherwise never written again.
* **Locks** are PostgreSQL advisory locks held on a connection of their
  own. A server that dies releases them; a server whose lock connection
  drops treats the lock as lost and abandons what it was doing under it.
* **`tls_certificates`**, above. The console reads this, not CertMagic's
  cache.
* 5b adds **`device_tls_trust`** (5b1: each device's verification of each
  chain it was asked to check), **`tls_names`** (5b2: per-name sources
  and moves; 5b3: added names and their reachability) and
  **`tls_dns_providers`** (5b4: sealed DNS credentials).
* The `tls_` tables are platform tables like `settings`, outside
  row-level security, reached only through the certificate service, which
  requires `settings.manage`. `device_tls_trust` follows `devices`.
  `database.md` lists them with their migrations.
* **Backup** is the database's: `pg_dump` (and the updater's copy of the
  data root) carries them, and `.env` holds the key that opens them, as
  for every sealed value. A restored install serves the same certificates
  and orders nothing, which keeps clear of the 5-per-week duplicate
  limit. `backup-restore.md` drops the ACME directory from what it backs
  up.

### When a certificate is missing or failing
Thresholds are fractions of each certificate's own lifetime, so that they
hold for 90, 64 and 45 days and for a ten-minute test certificate alike.
*W*, the renewal window, runs from the moment renewal became due (the
start of ARI's window, or two thirds of the lifetime) to expiry.

* **States** on the page: valid; renewing; "waiting for DNS since …";
  "failing since …" with the CA's error and its fix; expired.
* **A warning** when a name has had no certificate for an hour (waiting
  for DNS or failing; `.env` names and added names alike), when a renewal
  has failed for a quarter of *W* or 24 hours, whichever comes first, and
  when an added name's reachability fails (5b3).
* **Critical** when less than a quarter of *W* is left (about 7 days of a
  90-day certificate, 4 of a 45-day one), or a renewal fails after the CA
  moved its ARI window earlier, as it does before revoking.
* **Resolved** at the next success.
* **It reaches people two ways**, through one interface the certificate
  service calls, `Publish(ctx, Event)`, with a stable key per name
  (`tls:<name>`), opened or resolved, a severity, a summary, the last
  error and a link to Settings → **Certificates**:
  * the console, for super administrators: a banner across every console
    origin, the IP console included (when the DNS name's certificate is
    missing, the IP console is often the only way in), and on the page
    (and on the Alerts page and dashboard, as ADR-0053 shows a failing
    channel, once it is built);
  * *EasyRMM* events, which platform rules of the notification sender of
    ADR-0053 (proposed) can send to their channels. Until that sender
    exists, the interface has only the console behind it, so 5a does not
    wait for it.
* **At expiry**, a name whose Let's Encrypt certificate was chosen in the
  console (5b2) goes back to the source `.env` gives it (the authority or
  the operator's files), which every device using it has verified
  (5b1); an added name keeps only its agent route (5b3). In `acme` mode
  there is nothing to go back to: the server keeps trying, and with IP
  access on the IP addresses remain a way in.

### MeshCentral's name
MeshAgents follow the certificate EasyRMM serves for MeshCentral's name
only through MeshCentral's reads of `certUrl`, so:

* **The read gets exactly what agents get.** A connection from this host
  without a server name gets the certificate the edge serves for
  MeshCentral's name at that moment, in every mode, `internal` included
  (today `internal` mode answers it with the authority before looking).
  One function chooses a name's certificate, the loopback rule calls it
  with MeshCentral's name, and both change in the same atomic swap.
* **A swap waits until 3 minutes after MeshCentral's last read.**
  MeshCentral throttles its reads, not EasyRMM's swaps: a read within
  2 minutes of the previous one returns at once, and a held agent is
  released only by a read that finds a changed certificate
  (`updateProxyCertificates` in `meshcentral.js`, `meshagent.js`). A swap
  shortly after a read would leave agents that reconnect held until
  another mismatched agent happens to connect after the throttle ends,
  which in a small fleet can take hours. So the edge records each of
  MeshCentral's reads (the loopback handshake without a server name that
  `fromThisHost` identifies), stores its time in `tls_certificates` so a
  restart does not forget it, and applies a new certificate for that name
  only once 3 minutes have passed since the last read, whatever causes
  the change: a renewal, a move, the fallback at expiry, **Retry now**,
  `tls reset`, another server's `NOTIFY`. The first agent that sees the
  new certificate then makes MeshCentral read it at once. The wait never
  serves a certificate past its expiry. The console also refuses a second
  move of that name within 10 minutes.
* **An IP-only install's MeshAgents** use the IP address, whose
  certificate 5b never changes (5b3).
* **An added remote-access name joins `allowedOrigin`** (5b3): the
  list the separate fix writes (above) gains the name while it is
  trusted and loses it when it stops being trusted, rewritten with
  `allowedFramingOrigins`.

### Checks (5a for `.env` names; 5b for names from the console)
The same checks run on the Certificates page and in `easyrmm-server tls
check`. `setup.sh` runs the command once the server has started in `acme`
mode and prints the result; a failure does not stop the install, since
DNS may follow. Each check is a tick, a warning or a failure, with its
fix:

* each name resolves here (a warning: split-horizon resolvers; the page
  offers **Order anyway**);
* its `A` and `AAAA` records point at this server's addresses (from IP
  access's list, which the operator corrects behind NAT): a mismatch is a
  warning, except an `AAAA` record that points elsewhere, which fails,
  since Let's Encrypt tries IPv6 first;
* a name looked up before its record existed may stay "not found" for
  the zone's negative-caching time (its SOA minimum), here and at the
  resolvers on the way; the page says so whenever a name was missing;
* CAA, walked up the tree, allows `letsencrypt.org`, with any
  `validationmethods` naming a challenge on offer, and any `accounturi`
  naming this server's account (once it has one, below). A lookup that
  fails gets Let's Encrypt's advice, DNSSEC first;
* ports 80 and 443 answer at the resolved addresses with a token this
  server serves, under a path of its own and only for a name being
  checked (a warning: routers often do not loop a host's own address
  back).

**The checks connect out, so they are held to an address policy** (the
plan's, F2): an address is dialled only if it is one of this server's own
or public unicast, checked on the address actually dialled, so DNS cannot
point the check elsewhere between lookup and connection. Loopback,
link-local, multicast, reserved ranges and every cloud metadata address
(including `fd00:ec2::254` and `100.100.100.200`) are refused. No
redirects are followed, the result is pass or fail with a fixed reason
(never what the other side said), each connection times out after 5
seconds, and a person may run them for a name at most once every 10
seconds.

### Agent trust (5b1)
5b1 ships first and changes nothing by itself: it gives EasyRMM a way to
learn what each device really trusts and to widen that trust, per device,
only when a move asks for it.

* **A trust instruction** in the heartbeat's answer, signed with the job
  key under a context of its own (`EASYRMM-TRUST-SIG-V1`), as ADR-0027's
  update instruction is: the device, the origin, the certificates to add
  to the agent's trust (the authority's, when the move needs it), and
  each chain to verify (the exact chain a source will serve, leaf
  included, with its purpose: the move's target, or the name's fallback),
  an ID and a 10-minute validity. It may also name a host the device's
  EasyPatch agent uses (the host of its `ServerURL`, which need not be the
  EasyRMM agent's origin) with chains to verify for that host against the
  system's roots alone. The agent refuses an instruction for another
  device, an expired one, one with unknown fields or a bad signature.
* **The agent verifies each chain** for the origin's host name with the
  trust it would have: the system's roots, through the platform's own
  verifier on Windows (so a root update turned off by Group Policy shows)
  and the distribution's bundle on Linux, plus its CA file and the
  instruction's certificates. It verifies the chains named for the
  EasyPatch agent's host against the system's roots alone, which is what
  that agent trusts besides any authority its install carried. It
  reports pass or fail per chain, with the error, in its next heartbeat.
* **For the EasyPatch agent this is a stand-in, flagged as one on
  Linux.** On Windows both agents use the system's store. On Linux, Go
  reads the distribution's bundle file, while .NET reads OpenSSL's
  certificate directory; they usually hold the same roots but need not.
  The page marks a Linux device's EasyPatch result as checked by the
  EasyRMM agent, and the bundle test checks the EasyPatch agent itself
  after each move.
* **It widens its trust only when the target chain verifies**: from then
  on it trusts the system's roots and its CA file together for that
  origin, kept in its state (`state.Config`), which later builds read.
  Nothing changes for any other device.
* **Rollbacks cannot lose it.** The instruction is applied only through
  a heartbeat that got through, and that heartbeat confirms the running
  build and removes the previous one (ADR-0027), so a later probation
  rollback returns to a build that already held it. A rollback of the
  deployment (ADR-0052) restores the database with the release, so the
  restored server serves what its agents trusted at that time.
* **Checked again whenever it could change**: when a name's served or
  fallback chain changes (a renewal, another intermediate, the authority
  issuing again), when a device's build changes (an update or a
  rollback, which the heartbeat reports), and at a device's first
  heartbeat on a name whose source is not `.env`'s (a new install), the
  device is asked to verify both the chain served and the fallback's.
  The page and each device's page show the results; a device that fails
  the fallback's is shown as **unprotected**: it would be cut off if the
  name fell back at expiry or by `tls reset`, and the expiry alert lists
  it.
* **New installs through a name whose source is not `.env`'s** (a moved
  name, an added name) trust the name's current source and its fallback
  from the start:
  * fallback to the authority (`internal` mode, added names): the
    system's roots and the authority, one private authority owned by
    this server, added only where the name falls back to it;
  * fallback to the operator's files (`manual` mode): the system's roots
    and the files' issuing root when the file holds it (a self-signed
    certificate at the end of its chain). When it does not and the chain
    does not verify against public roots, such devices show as
    unprotected, on the page and in the alert, until the operator adds
    the root to the file or the computers trust it.
* **Older agents** report nothing, which counts as "not verified".
* **Protocol** (ADR-0009, as amended by pull request #52, open; 5b1
  depends on it). The agent reports in its heartbeat that it understands
  trust instructions, and the server sends `trust` only to an agent that
  reported it, as ADR-0009 requires of every new instruction. The
  per-chain results are a request field added after level 2, which the
  agent sends only to a server of level 2 or higher. Nothing goes in the
  answer's feature list: the agent behaves the same whichever server it
  talks to.
* **A device cut off anyway** (one that failed and was not seen within
  the 30 days, or whose computer's roots changed) is offered
  **Reinstall through a remote session** on its page: a terminal through
  MeshAgent, which checks no TLS chain and stays connected, with the
  install command and, from the reported error, the fix (update the
  computer's root certificates, or install with `--ca-file`).

### Moving between sources (5b2)
`EASYRMM_TLS_MODE` stays in `.env`, as the plan says: it is the source a
name starts with and falls back to. The console records, per DNS name,
that it uses Let's Encrypt instead (`tls_names`). In `internal` and
`manual` modes the edge therefore answers HTTP-01 on port 80 and
TLS-ALPN-01 on 443 too (today only `acme` does), only for names with an
order pending or managed, and in `manual` mode the files need cover only
the names still served from them (`covers`).

A move, to Let's Encrypt or back, needs step-up authentication (below)
and goes:

1. **Agree and get certificates** (to Let's Encrypt): the production
   account is registered, unless the deployment has one; the CAA check
   runs again against that account's URI; a **trial order against
   staging** proves validation from Let's Encrypt's own vantage points
   without spending production's limits, unless CAA names an account
   (`accounturi`), which no staging account can match, so the trial is
   skipped and the page says why; then the real order. A CAA record that
   names an account this server does not hold fails with the record to
   add. Afterwards the page offers, as optional hardening, a CAA record
   naming this account and the challenge used.
2. **The certificate is held, not served**, and every device that uses
   the name gets a trust instruction with the target chain: devices whose
   EasyRMM agent's origin (that of its signed requests) is the name, and
   devices whose EasyPatch agent's `ServerURL` host is the name (the
   engine's public URL, `EASYRMM_PUBLIC_URL`: `install.go` in
   `server/internal/easypatch`, `EasyPatch__PublicUrl` in the compose
   file; or an imported EasyPatch's names). A name whose patching agents
   EasyRMM cannot ask is refused: an imported EasyPatch's name while the
   engine lists agents on it, seen in the last 30 days, that are not
   linked to a device with an EasyRMM agent (`links.go`, ADR-0045).
3. **The move waits** until every device seen in the last 30 days has
   verified it, for EasyRMM's agent and, when the device has one, for
   its EasyPatch agent (below). The page lists, per device, passed,
   failed with the error, or not reported, and offers **Update these
   agents** (ADR-0027) for agents too old to report. Devices not seen for
   30 days do not block; they are listed. The operator can cancel.
4. **Then the edge swaps the name's source atomically**, with no restart:
   connections already open keep going, new handshakes get the new
   certificate (for MeshCentral's name, once 3 minutes have passed since
   MeshCentral's last read, above).

**Moving back** is the same, with the fallback source's chain as the
target. For the operator's own files signed by a private CA, agents
installed under Let's Encrypt without `--ca-file` cannot verify it, so
the move back is refused until they are reinstalled with it; for the
authority, the instruction adds the authority's certificate.

**EasyPatch agents** trust the system's store plus any authority they
were given. The EasyRMM agent on the same computer verifies for them
against the system's roots alone (above, with Linux flagged), and the
bundle test checks the EasyPatch agent itself. ADR-0042 is widened:
install instructions carry the internal authority whenever the
deployment has one, not only in `internal` mode,
and EasyRMM records per device whether the instruction it sent carried
it. A move to the authority is refused while a device seen in the last 30
days has an EasyPatch agent whose instruction did not carry it (devices
installed before the record existed count as without). The remedy is
**Reinstall patching agents**, which sends ADR-0031's install
instruction again, now with the authority; a device whose EasyRMM agent
is cut off gets it through a remote session.

**MeshAgent** is not affected by its pin, which is MeshCentral's agent
certificate. A move of MeshCentral's name is one certificate change:
MeshAgents that reconnect wait for MeshCentral's next read of `certUrl`,
at most two minutes, and then reconnect.

### A name for an install on an IP address (5b3)
The case the feature is built around, and the owner's "one step".

* **One name pair** (the console's and its remote-access name) can be
  added when `EASYRMM_PUBLIC_URL` is an IP address. The remote-access
  name must be on the same site as the console's, as `.env` names must
  be (`validateMesh`). Installs that have a DNS name already change names
  in 5c. If `.env` later names an added name, `.env` wins: at start the
  name stops being an added one and is served as `.env` says, and this is
  audited.
* **What the operator does:**
  1. Types the name, such as `rmm.example.com`. The remote-access name is
     filled in as `mesh.rmm.example.com` and can be changed. No email, no
     account, nothing else.
  2. Creates the records the page shows with this server's public
     address: an `A` (and `AAAA`) record for each name, and, when CAA
     forbids Let's Encrypt, the `CAA` record to add.
  3. Reads the checks (above).
  4. Presses **Agree and get certificates** (as in a move, above). The
     names are served from their certificates once they are in hand;
     until then nothing changes.
  5. Confirms the change of origins, which restarts MeshCentral to accept
     the console's name as a framing origin and the remote-access name as
     an allowed origin, and so ends open remote sessions; the page says so
     first.
  6. Reads "**Renews automatically; next renewal on** …".
* **Added origins are never internal.** They never enter
  `internalAddresses` or `SetAddresses`, so the certificate every
  MeshAgent on the IP address sees never changes. The authority issues a
  second certificate, for added names only, which the edge serves for an
  added name whenever its Let's Encrypt certificate is not trusted or
  not valid; agents enrolled through the name trust it (5b1).
* **It is trusted** once this server holds a Let's Encrypt certificate
  for both names and has reached itself through them: obtained by HTTP-01
  or TLS-ALPN-01, or, for DNS-01, once a token served here was fetched
  through the name, by the server through the host's resolver or, on
  split-horizon networks, by the operator's browser from the page.
* **Reachability is checked every day**, the same fetch again, and
  every console page loaded through the name by a signed-in person counts
  as a browser confirmation; the page shows the age of each. A recent
  browser confirmation counts as success: on networks where the server
  cannot reach its own public address (no hairpin NAT, split horizon),
  the server's fetch always fails, and browsers are the only proof.
  * The name is **reachable** while the server's fetch or a browser
    confirmation succeeded within the last 7 days, the grace period.
  * When the day's fetch fails and no browser confirmed it that day, a
    warning opens, naming both.
  * Only when both have failed for the whole grace period is the name
    dropped from install commands and email links, and it stops being
    trusted.
* **Once trusted**, each component is told as follows:

| Component | What changes | How it is told |
|---|---|---|
| Routing and certificates (`newRouter`, `edge.certificates`) | The pair becomes an origin, not internal | Rebuilt and swapped atomically |
| CSRF origin check (`httpapi.NewSessions`) and the CSP's `frame-src` | The pair is accepted | Read from the current origins |
| MeshCentral's `allowedFramingOrigins` and `allowedOrigin` (`MeshServerConfig`) | The console name is added to the first, the remote-access name to the second | `config.json` rewritten once; MeshCentral restarts, ending open remote sessions |
| Remote sessions | Launched from the name, they open on its remote-access name, whose `control.ashx` MeshCentral now accepts | As for every origin (ADR-0016), with `allowedOrigin` above |
| Install commands (`agentapi.New`, `enrollapi`) | The name's command comes first, for new devices, while the name is reachable (above) | Rendered again |
| Links in email (`auth.Config.PublicURL`) | The name while it is trusted and reachable; otherwise `EASYRMM_PUBLIC_URL` | Chosen when each email is sent |
| Authenticator issuer (`auth.Config.Issuer`) | `EasyRMM (<name>)` for new enrolments; existing entries keep their label and keep working | Read when enrolling |
| WebAuthn's relying party (`configureWebAuthn`) | The name: security keys and passkeys become available there. An IP install has none registered, so none is lost | Reconfigured |
| The IP console | Links browsers to the name, as it links to the public URL for security keys today | Read from the current origins |

* **What stays on the IP address until 5c**, because it is registered
  outside the server or is an address agents hold: single sign-on's
  redirect URI (registered at each provider, and for Authentik built from
  `.env` by its blueprint, `docker/authentik/blueprints/easyrmm.yaml`),
  so sign-in through a provider still happens at the IP console; the
  patching engine's public URL (`EasyPatch__PublicUrl`, which EasyPatch
  agents enroll with and `links.go` matches them against); MeshCentral's
  own name (MeshAgents' address and `certUrl`); the audit forwarder's
  host name; and every agent already installed.
* **When a name stops being trusted** (its certificate expires with
  renewal failing, reachability's grace ends, **Remove name**, `tls
  reset`), the console, links, framing and allowed origins (a
  MeshCentral restart again) and WebAuthn go back to the IP address,
  but the name keeps routing the agent API, served with the authority's
  second certificate, so that agents enrolled through it keep working.
* **Remove name** is refused while a device seen in the last 30 days
  uses the name. Before it, and in the warnings of expiry and
  reachability, the page lists the people whose only second factor is a
  security key or passkey registered for the name: on the IP address they
  could not use it, so each must add an authenticator app first, or a
  super administrator resets their second factor.

### DNS-01 (5b4)
For servers Let's Encrypt cannot reach on port 80 or 443 (internal
networks, a VPN):

* **Providers**: RFC 2136 dynamic update with a TSIG key using
  HMAC-SHA256 or stronger (HMAC-MD5 and HMAC-SHA1 are refused; BIND,
  Knot, PowerDNS; Windows DNS signs updates with GSS-TSIG, which this does
  not cover), and Cloudflare with an API token, through CertMagic's libdns
  providers (`libdns/rfc2136`, `libdns/cloudflare`, both MIT). Others
  when asked for.
* **The zone that holds the challenge must answer the Internet**, since
  Let's Encrypt asks from there. For a zone only reachable inside,
  **delegation** is the setup, and the page shows it first:
  `_acme-challenge.rmm.example.com CNAME` to a name in a public zone used
  only for challenges, which EasyRMM then writes (CertMagic's
  `OverrideDomain`; the check follows the CNAME and fills it in). For RFC
  2136 the guide gives an update policy that allows only that TXT record.
  A Cloudflare token can only be scoped to a zone, so without delegation
  EasyRMM holds write access to the whole zone, and the page says so.
* **Propagation is checked against the zone's own servers**, not the
  host's resolver: for RFC 2136 the server the update went to, for
  Cloudflare the zone's name servers. EasyRMM sets CertMagic's
  `Resolvers` so, never falling back to public resolvers, and waits up to
  5 minutes, which the page shows while it waits.
* **The RFC 2136 server's address** is typed by a super administrator,
  so the plan's rule for the platform's own destinations applies:
  private addresses and loopback are allowed, cloud metadata never.
  `libdns/rfc2136` dials the server it is given itself, with no hook for
  checking the address dialled, so EasyRMM resolves a name once, checks
  the address, and hands the library that address, pinned, on port 53
  only. Errors from saving and testing are fixed reasons (refused, timed
  out, not authorized, zone not found), never the library's text, so the
  test cannot be used to probe ports or hosts.
* **Credentials** are sealed with `EASYRMM_SECRET_KEY`, bound to their
  row, tested when saved (a TXT record created and removed), never shown
  again, and replaced or removed; the audit log names the provider and
  zone, never a secret.
* **DNS-01 proves control of DNS, not that the name reaches this
  server**, hence the reachability fetch above for a name obtained that
  way, and every day after.
* **DNS-PERSIST-01** would remove the credentials altogether (the page
  would show one TXT record). It is revisited when Let's Encrypt offers it
  in production and CertMagic supports it.

### Who
* **Super administrators** (`settings.manage`, platform-wide) see the
  page, and may retry and order anyway.
* **Step-up authentication** (below) is required for adding or removing
  a name, moving a name between sources, **Order anyway** for a name
  added in the console, and DNS credentials.
* **Every super administrator is told** when a name is added, removed or
  moved: a notice in the console and, once ADR-0053's sender exists, an
  email.

### Step-up authentication
This is the one definition: ADR-0057 and ADR-0061 cite it, and 5c reuses
it. 5b2 builds it.

* **A second factor confirmed within the last 5 minutes.** A second
  factor is an authenticator app's code (TOTP) or a security key or
  passkey (WebAuthn). WebAuthn works only on a DNS name, so on the IP
  console only a code can be used.
* **Recorded on the session with its own time**, `stepped_up_at`, set
  only by a step-up and checked by the server on every action that
  requires one. `AuthenticatedAt`, which is set when the session becomes
  active, is not used.
* **Never a recovery code**, and never a password alone.
* **Refused when no factor is enrolled** (possible with
  `EASYRMM_REQUIRE_MFA=false`): the person is told to set one up first.
* **An account signed in through a provider trusted to enforce MFA**
  (ADR-0034), which may have no factor of its own and no password (an
  administrator Authentik created): a fresh sign-in at the provider,
  requested with `prompt=login` and `max_age=0`, whose ID token's
  `auth_time` must be later than the start of the step-up. The sign-in
  is bound to the account and to this step-up, so that a stolen session
  and the attacker's own account at the same provider do not pass:
  * the ID token's issuer and subject (`iss` and `sub`) must be the
    provider identity linked to the session's user;
  * its `state` and `nonce` are created for this step-up and this
    session, and accepted once;
  * the provider must still be marked as trusted to enforce MFA when the
    token arrives;
  * any mismatch is a failed step-up, audited and counted as below.

  An account signed in through a provider not so trusted has a factor of
  its own, as sign-in requires, and uses it.
* **Audited**: each step-up and each failed one (`auth.step_up`, with
  the method). Failures count against the session as a wrong password
  does in `reauthenticate`, which ends it after `MaxMFAFailures`.

### Audit
All under `tls.`, with the name, issuer, serial and validity in the
details, never a key or a credential:

* by the system (`ActorSystem`): `tls.certificate_obtain`,
  `tls.certificate_renew`, `tls.certificate_fail` (each failed attempt;
  the schedule and the budget bound them), `tls.import` (5a's import),
  `tls.name_trust` and `tls.name_untrust` (with the reason),
  `tls.reachability_fail`, `tls.source_fallback` (at expiry),
  `tls.name_superseded` (`.env` now names an added name);
* by a person: `tls.retry`, `tls.order_anyway`, `tls.trial_order`,
  `tls.account_register`, `tls.name_add`, `tls.name_remove`,
  `tls.source_change` (from and to, requested, completed or cancelled),
  `tls.easypatch_reinstall`, `tls.dns_provider_save`,
  `tls.dns_provider_remove`;
* per device, by the agent: `device.tls_trust` (an instruction applied,
  with each chain's result);
* on the host: `tls.reset` (below).

### Recovery (5b2)
`docker compose exec server easyrmm-server tls reset` returns every name
to the source `.env` gives it, cancels pending moves and stops trusting
names added in the console, keeping stored certificates and the account;
names that devices seen in the last 30 days use keep their agent route
(5b3). Then `docker compose restart server` (an unchanged container is
not recreated by `up -d`). The wait after MeshCentral's last read holds
across the restart, since that read's time is stored. It
is for the case where a choice made in the console locks the operator out
of it, and comes with 5b2, which makes the first such choice; the guide
describes it. TLS never stops the server from starting.

### Slices
* **5a. CertMagic, status and alerts.** For the names in `.env`:
  CertMagic with ARI and the managed list, EasyRMM's scheduler and gate
  with the hold, PostgreSQL storage, `autocert`'s import, optional email
  and the named account, `EASYRMM_ACME_CA_FILE`, the checks and `tls
  check`, **Order anyway** and **Retry now**, MeshCentral's name rules,
  the Certificates page, alerts through the interface, and the system's
  audit records. Mergeable alone: no name or source changes, and an
  install upgraded to it serves the same certificates.
* **5b1. Agent trust**, released first: the trust instruction, the
  agent's verification and widening, `device_tls_trust`, the re-checks,
  and **Reinstall through a remote session**. It changes no name. It
  needs ADR-0009's protocol levels (pull request #52).
* **5b2. Sources and moves**: per-name sources, challenges in `internal`
  and `manual` modes, account registration and the staging trial, the
  move and its waiting on devices, moving back, ADR-0042's widening and
  **Reinstall patching agents**, step-up authentication, `tls reset`.
* **5b3. An IP install's name**: the added pair, the authority's second
  certificate, reachability, the components' table (the remote-access
  name added to `allowedOrigin` among them, which needs the separate fix
  merged), **Remove name**.
* **5b4. DNS-01**: the providers, delegation, propagation, credentials.
  It adds a challenge to 5b2's moves and 5b3's names, so either can ship
  first.
* **5c begins** where 5b stops: moving agents (EasyRMM's agent,
  MeshAgent's `.msh`, the EasyPatch agent's `ServerUrl`) to the name,
  changing a DNS install's console name, and moving single sign-on's
  redirect URIs, Authentik's address and the engine's public URL with it.
  It needs F0 and its own ADR.

### Where this differs from the plan
* **Single sign-on, Authentik's address and the engine's address** stay
  with 5c, not 5b: each is registered outside the server or held by
  agents, and moving them is moving a name.
* **A per-name source in the console**, beside the TLS mode in `.env`,
  is what lets a name move to Let's Encrypt and back without a restart.
* **Agents' trust, verified on each device and widened per device**, and
  ADR-0042's condition changed: without that, a move would cut agents
  off.
* **5b is four slices**, agent trust first.
* **Step-up authentication is defined here** for 5b, ADR-0057 and
  ADR-0061.
* **`tls reset`** comes with 5b2, which makes the choices it undoes.
* **Alerts** open on failures lasting a fraction of the renewal window
  (at most 24 hours), not at the first one, which the retries usually
  fix; a critical level is added near expiry; a name with no certificate
  alerts after an hour.
* **New**: `autocert`'s import, `setup.sh` no longer sending the
  administrator's address to Let's Encrypt, and `tls check`.

## Testing
Pebble, Let's Encrypt's test CA (with ARI and configurable profiles), and
BIND run in containers on **host networking only**, never on a bridge:

* **Pebble** listens on loopback ports of its own (ACME on 14000,
  management on 15000), with `httpPort: 80` and `tlsPort: 443` so that it
  validates against the edge's real ports, `PEBBLE_VA_NOSLEEP=1`,
  `PEBBLE_WFE_NONCEREJECT=0`, a profile whose `validityPeriod` is 600
  seconds for the renewal tests, and `-dnsserver 127.0.0.1:53`. Its root
  is generated again at each start, so one Pebble runs for a whole job.
* **BIND** listens on `127.0.0.1:53` (systemd-resolved's stub is on
  `127.0.0.53`) and is authoritative for the test zone, `example.com`,
  with one answer for every name: the runner's own primary address,
  at which the edge listens and which the checks accept as this server's
  own. Views per source cannot work here: every container runs on the
  host's network (`--network host` in `scripts/e2e/bundle.sh`, the Linux
  machine included) and asks through the stub, so BIND sees every query
  come from `127.0.0.1`.
* **The host's resolver** sends the test zone to BIND: a dummy link with
  `resolvectl dns` set to `127.0.0.1` and `resolvectl domain` set to
  `~example.com`; Pebble asks BIND directly. The job's first assertions
  are that the server's container and the Linux machine resolve
  `rmm.example.com` to BIND's answer, so that a resolver that bypassed
  the stub fails at once instead of reaching the real `example.com`.

The tests:

* **Unit**: the seal's binding and the re-seal at start; certificate
  choice per source in each of the four modes, the loopback rule
  included; MeshCentral's read rule (a read at T makes a swap at T + 1
  minute wait until T + 3 minutes, whatever its cause, across a restart,
  never past expiry); thresholds computed from the lifetime;
  the scheduler, the gate (an attempt not due, during a hold, over the
  budget, not started by the scheduler) and **Retry now**'s refusal; an
  order and a renewal with no email, with standard input a pipe the test
  holds open, use the named account, read nothing from the pipe and
  leave `DefaultACME.Agreed` unchanged, and with no account stored for
  the CA the attempt is refused before CertMagic is called; the step-up
  through a provider refused for another subject, a reused `state` or
  `nonce`, an old `auth_time`, or a provider no longer trusted for MFA;
  RFC 2136's address pinned and its errors fixed; CAA
  tree walking with `accounturi` and `validationmethods`; the checks'
  address policy, redirects refused; the trust rules that keep a move
  waiting (devices chosen by their agent's origin and by their EasyPatch
  agent's `ServerURL` host; an imported name with unlinked patching
  agents refused; a `manual` fallback without its root showing devices
  unprotected); the step-up cases.
* **Agent**: a trust instruction forged, for another device, expired or
  with unknown fields is refused; a chain that does not verify leaves the
  trust unchanged; one that verifies widens it, and the widening survives
  an update and a probation rollback; chains named for the EasyPatch
  agent's host are checked against the system's roots alone; the
  capability is reported, and the results are sent only to a server of
  level 2 or higher.
* **PostgreSQL integration**: the storage against CertMagic's contract;
  two servers on one database order once and both serve the result,
  including after one missed the `NOTIFY` (groundwork); a lock is lost
  when its connection dies; a server restarted ten times within a minute
  while its name fails makes the scheduled attempts and no more.
* **A challenge test** (the edge against Pebble): HTTP-01 alone,
  TLS-ALPN-01 alone (port 80 off), a challenge for an unmanaged name
  unanswered, and DNS-01 through RFC 2136 against BIND with an
  HMAC-SHA256 key allowed only `_acme-challenge`, directly and through a
  CNAME delegation, with an HMAC-MD5 key refused.
* **The bundle test** gains a parallel job with Pebble, on the release
  bundle and real agents:
  * 5a: an install by name in `acme` mode issues at start; the Linux
    machine (Pebble's root in its store) enrolls through the name, its
    MeshAgent connects and a remote session opens.
  * **Renewal with a short-lived certificate**: 600-second certificates,
    with CertMagic's `RenewCheckInterval` and the scheduler's interval
    set to 10 seconds by test-only settings. A new serial is served for
    every name; MeshCentral logs that it loaded the new certificate, each
    swap of its name at least 3 minutes after its last read (the edge's
    log); MeshAgent reconnects and a session opens again.
  * **The failure alert**: validation of the console's name made to fail
    (BIND answers another address). The warning opens a quarter of the
    renewal window after the first failure, with "failing" as its reason;
    automatic attempts stop at the budget; the alert turns critical with
    less than a quarter of the window left; once validation works again,
    **Retry now** renews and the alert resolves.
  * **The upgrade**: the previous release, with `autocert`, against
    Pebble. That release has no setting for Pebble's root, so a test-only
    override compose file puts Pebble's root under `EASYRMM_TLS_DIR` and
    `SSL_CERT_FILE`, pointing at it, in the server's environment. After
    `setup.sh --upgrade` the new release, with `EASYRMM_ACME_CA_FILE` set,
    serves the same serials, places no order, and registers no account
    (Pebble's log shows no new one).
  * 5b2: an `internal`-mode DNS install with an agent of the previous
    release: a move to Let's Encrypt waits ("not reported") until that
    agent is updated, then completes; MeshCentral's name moved from the
    authority to Let's Encrypt and back, with a remote session opened
    after each move; a move of the console's name waits on the device's
    check for its EasyPatch agent's host, and the EasyPatch agent keeps
    working after each move; a move back refused for an EasyPatch agent
    installed without the authority goes through after **Reinstall
    patching agents**; an agent installed after a move reports the
    fallback's chain at its first heartbeat; `tls reset`.
  * 5b3: the IP install at `https://127.0.0.1` adds a name; the agent on
    the IP address keeps working and the IP's certificate is unchanged; a
    remote session opens from the name, on its remote-access name; a
    new agent enrolls through the name; the name untrusted, that agent
    keeps working on the authority's second certificate; **Remove name**
    refused while it is used.
  * 5b4: DNS-01 through RFC 2136 for an added name.
* **Windows**: the agent's verification through the platform's verifier,
  the trust instruction and `install.ps1` with both trusts run on the
  Windows CI machine; until that machine runs them, IMPLEMENTATION_STATUS
  marks them unverified.
* **ADR-0042's change**: the EasyPatch agent's own tests (or a contract
  test against it) show an install instruction carrying the authority in
  `manual` and `acme` modes accepted and that authority trusted.
* **Coverage**: the certificate service's package gets a floor in
  `scripts/ci/check-coverage.sh` (90%), as every new package does.
* **Stand-ins, flagged as such**: in CI a second Pebble plays Let's
  Encrypt's staging for the trial order. Cloudflare cannot be validated
  by Pebble through BIND, since the record lives in Cloudflare's real
  zone: it runs against Let's Encrypt's staging with a real zone, on
  `main` only, or is marked unverified.
* **By hand**, recorded in IMPLEMENTATION_STATUS: a real Let's Encrypt
  staging run on a real host and name (the checks, the trial, issuance,
  a forced renewal, MeshAgents reconnecting), then production on the
  owner's next full instance with DNS.

## Consequences
* An install by name gets certificates at start and renews them without
  anyone; an install on an IP address gets a trusted name from one page,
  with nothing typed but the name.
* A missing or failing certificate is never silent: it alerts within an
  hour, or within a fraction of its renewal window, on every console
  origin.
* Nothing is sent to Let's Encrypt but what issuance needs: no email
  unless the operator sets one. PRIVACY.md says so.
* Certificates and the account move into the database and its backup;
  the ACME directory leaves the backup guide.
* An agent's trust widens only on its own device, only for a move, and
  only after it verified the chain itself. New installs through a moved
  or added name trust the system's roots and the name's fallback (the
  authority, or the files' root when the file holds it); a device that
  cannot verify the fallback is shown as unprotected.
* A move waits on every device that uses the name, through either of its
  agents; a name whose patching agents EasyRMM cannot ask is not moved.
* An added name stays trusted while the server or a browser reaches it;
  on networks without hairpin NAT, browsers are the proof.
* EasyPatch install instructions carry the authority whenever there is
  one, amending ADR-0042's condition.
* MeshCentral restarts when an added name is trusted or stops being
  trusted, ending open remote sessions; certificate changes alone never
  restart it, and they wait until MeshCentral can read them at once.
* A move can wait on devices that have not reported; the page shows
  which, and the operator can update, reinstall or cancel.
* Single sign-on and the engine's address stay on an IP install's address
  until 5c.

## Alternatives considered
* **Keep `autocert`.** No ARI, ordering at the first handshake, a
  directory per server, no events for alerts.
* **CertMagic's own retries** (`ManageAsync`). Retries in memory that a
  restart forgets, retries through staging, and no hold; above.
* **Let's Encrypt's IP certificates.** They would cut off every agent
  installed by IP address, and last 160 hours.
* **One certificate for all names, or a wildcard.** Above.
* **Widening every DNS-name agent's trust** to the system's roots and
  the authority. Simpler, but every agent that trusts one private
  authority today would trust every public CA without need; per device,
  only for a move, keeps that to the devices that need it.
* **Trusting what the agent reports** (`system`, `ca-file`) instead of a
  chain it verified. A computer's roots can be old or reduced by policy;
  only verifying the chain on the computer shows it.
* **A second CA as a fallback** (CertMagic can hold several issuers):
  another party for every install, and ZeroSSL needs an account;
  certificates keep weeks of validity through a Let's Encrypt outage, and
  the alert covers it.
* **TLS mode from the console.** `offload` and trusted proxies belong to
  the host's setup; a per-name choice gives the same result without the
  server rewriting its own configuration.
