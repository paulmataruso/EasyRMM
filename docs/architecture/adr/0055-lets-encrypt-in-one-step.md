# ADR-0055: Let's Encrypt in one step

* Status: Proposed (2026-11-21). Not implemented.
* Builds on: [ADR-0003](0003-go-edge-host-networking.md) (the TLS edge),
  [ADR-0004](0004-meshcentral-dedicated-origin.md) and
  [ADR-0014](0014-remote-access-gateway-and-device-discovery.md)
  (MeshCentral's name, and how it reads the certificate its agents see),
  [ADR-0016](0016-ip-address-access.md) (IP access and the internal
  certificate authority), [ADR-0042](0042-agents-trust-easyrmms-authority.md)
  (EasyPatch agents and that authority),
  [ADR-0044](0044-authentik-when-chosen.md) (Authentik's name),
  [ADR-0052](0052-the-host-updater.md) (`hold` and backups), and the
  notification sender of ADR-0053 (proposed).
* Part of [the feature plan](../feature-plan.md): feature 5, slices 5a and
  5b. Slice 5c, moving agents and the console to a new name, needs the job
  key's rotation (F0) and gets an ADR of its own; this one says where it
  begins.

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
  the root to trust for another directory's own HTTPS does not.
* **Which certificate a connection gets** (`edge.certificates`): a DNS
  server name gets the mode's source; no server name (an IP address) gets
  the internal authority; MeshCentral reading its own certificate from
  this host gets the MeshCentral name's (`fromThisHost`). In `manual`
  mode the file must also cover Authentik's and the imported names
  (`covers`).
* **Names are fixed at start.** The router, the console origins that the
  CSRF check accepts, the CSP's `frame-src`, MeshCentral's
  `allowedFramingOrigins`, the install scripts and the authenticator
  issuer are all built once from `.env` (`Build`, `Handler` and
  `MeshServerConfig` in `server/internal/app/app.go`; `agentapi.New`
  renders one script per origin).
* **What trusts what:**
  * *EasyRMM's agent* trusts the system's roots, or, when installed with
    `--ca-file`, only that file (`client.New` in `agent/client/client.go`
    replaces `RootCAs`). Install commands pin and hand over the internal
    authority for every origin the authority serves (`origins` in
    `server/internal/app/origins.go`; `install.sh.tmpl` and
    `install.ps1.tmpl` in `server/internal/httpapi/agentapi`). So an agent
    installed through a DNS name in `internal` mode trusts the authority
    and nothing else, and one installed under a public certificate trusts
    the system's roots and nothing else.
  * *The EasyPatch agent* trusts the system's store and, when its install
    instruction carried one, the server's authority as well
    (`AgentHttpClientFactory` in
    `easypatch/agent/EasyPatch.Agent/Platform`). Instructions carry the
    authority only in `internal` mode (ADR-0042).
  * *MeshAgent* pins MeshCentral's agent certificate (`ServerID` in its
    `.msh` is that certificate's key hash: `webserver.js` of MeshCentral
    1.3.1, the version `deploy/docker-compose.yml` pins), not the TLS
    certificate. At each connection it reports the hash of the TLS
    certificate it saw; MeshCentral compares it with the one it read from
    `certUrl` and, when they differ, holds the agent and reads `certUrl`
    again, at most once every two minutes, then disconnects the held
    agents so they reconnect (`meshagent.js` and `updateProxyCertificates`
    in `meshcentral.js`). EasyRMM sets `certUrl` to its own listener
    (`EASYRMM_MESH_CERT_URL`, `defaultCertURL`) and rewrites MeshCentral's
    `config.json` only when it changes; MeshCentral's start script
    restarts it then (`docker/meshcentral/start.sh`). A second change
    within those two minutes leaves agents held until MeshCentral restarts
    (ADR-0014; `docs/deployment/docker.md`).
  * *The server itself* reaches Authentik's name through its own edge,
    trusting the system's roots and, in `internal` mode, its authority
    (`authentikClient` in `server/internal/app/authentik.go`).
* **Storage and backup.** The internal authority is sealed in `settings`
  (`server/internal/pki`). The ACME cache is a directory, which the backup
  guide lists as its own part (`docs/operations/backup-restore.md`).

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
  3 hours. A renewal through ARI is exempt from all of them.
  ([rate limits](https://letsencrypt.org/docs/rate-limits/))
* **Staging**, `https://acme-staging-v02.api.letsencrypt.org/directory`,
  has far higher limits and roots no store trusts.
  ([staging](https://letsencrypt.org/docs/staging-environment/))
* **No expiry emails, no OCSP.** Expiry emails ended on 4 June 2025; an
  address given through ACME is no longer stored but forwarded to ISRG's
  general mailing list. OCSP URLs left certificates on 7 May 2025.
  ([notification service ended](https://letsencrypt.org/2025/06/26/expiration-notification-service-has-ended),
  [upcoming features](https://letsencrypt.org/upcoming-features/))
* **Validation** comes from several places on the Internet, from addresses
  Let's Encrypt does not publish; CAA (`letsencrypt.org`, with
  `accounturi` and `validationmethods`) is checked up the tree.
  ([integration guide](https://letsencrypt.org/docs/integration-guide/),
  [CAA](https://letsencrypt.org/docs/caa/))
* **DNS-PERSIST-01**, one standing TXT record instead of DNS credentials,
  was announced for 2026; the last statement we found (25 June 2026) says
  it will not be deployed in production until an open question in the
  draft is settled.
  ([announcement](https://letsencrypt.org/2026/02/18/dns-persist-01),
  [status thread](https://community.letsencrypt.org/t/dns-persist-01-deployment-status-and-timeline/246468))
* **Chains** now run through the new `YE` and `YR` intermediates up to
  ISRG Root X1 (and X2); the new roots `YE` and `YR` are not yet widely
  trusted. ([chain of trust](https://letsencrypt.org/certificates/))

## Decision

### What "everything" is
| Name | Where it comes from | Certificate |
|---|---|---|
| The console's name | `EASYRMM_PUBLIC_URL` when it is a DNS name; or added in the console (5b) | Let's Encrypt |
| MeshCentral's name | `EASYRMM_MESH_PUBLIC_URL` (by default `mesh.` and the console's name); for an added name, `mesh.` and that name | Let's Encrypt |
| Authentik's name | `EASYRMM_AUTHENTIK_HOSTNAME` | Let's Encrypt |
| An imported EasyPatch's names | `EASYRMM_PATCHING_AGENT_HOSTNAMES` | Let's Encrypt |
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
  name (5b).

### Certificates through CertMagic (5a)
CertMagic (Apache 2.0, `github.com/caddyserver/certmagic`) replaces
`autocert`, for the names above:

* **Issued at start**, not at the first handshake (`ManageAsync`, which
  never holds up the start), from a **managed list**; on-demand issuance
  is never on. A name with no certificate yet is ordered only once it
  resolves (checked locally every 10 minutes), so an install whose DNS is
  not ready burns no failed validations.
* **Renewed by ACME Renewal Information**, checked at least twice a day;
  where a CA offers none, at a third of the lifetime left (CertMagic's
  `RenewalWindowRatio`). No profile is requested: the CA's default, so the
  move to 64 and 45 days needs no change. Nothing assumes 90 days.
* **No OCSP stapling** (`OCSPConfig.DisableStapling`): Let's Encrypt has
  no OCSP, and the server then makes no OCSP requests for a private CA's
  certificates either.
* **Keys**: ECDSA P-256 (CertMagic's default key type), a new key at each
  renewal.
* **Challenges**: HTTP-01 on port 80 when `EASYRMM_LISTEN_HTTP` is set,
  and TLS-ALPN-01 on 443, as today; CertMagic chooses among those
  enabled.
* **No email by default.** `EASYRMM_ACME_EMAIL` becomes optional, and
  empty means no contact address: Let's Encrypt sends nothing to it any
  more, and would only pass it to ISRG's mailing list. Expiry is watched
  by EasyRMM (below). `setup.sh` stops requiring `--acme-email` and stops
  copying `--admin-email` into it; an address already in `.env` is kept.
* **The Subscriber Agreement** is accepted by the operator: at install by
  choosing `acme` (setup.sh prints the link), in the console by **Agree
  and get certificates** (5b).
* **Another ACME CA is supported**: `EASYRMM_ACME_DIRECTORY` (exists) and
  a new `EASYRMM_ACME_CA_FILE`, a PEM file under `EASYRMM_TLS_DIR` holding
  the roots to trust for that directory's own HTTPS (CertMagic's
  `TrustedRoots`) and for the server's own connections to its names
  (`authentikClient`). Devices must already trust that CA (an enterprise
  PKI); install commands do not carry it. The tests use it for Pebble.
* **Several servers share one set**: CertMagic's storage is PostgreSQL
  (below), so the instances form one cluster; one orders, the others load
  the result. The one that obtains a certificate sends `NOTIFY`, and the
  others serve it within seconds; each also looks in the shared storage
  before it orders anything.
* **The upgrade issues nothing.** At the first start of 5a, under the
  storage lock, `autocert`'s account key and every certificate in
  `<data dir>/acme` still valid are imported. The directory is left in
  place, so a rollback (ADR-0052) still finds it. The import stays until a
  release states that upgrades must pass through 5a.
* **While the server is held** (ADR-0052's `hold`) it places no orders.

### Where keys and certificates live
* **`tls_storage`**, a key/value table implementing CertMagic's `Storage`
  and `Locker`: account keys, certificate keys and certificates. Every
  value is sealed with `EASYRMM_SECRET_KEY`, with its key as associated
  data so that a value copied to another row does not open (as ADR-0047
  binds tokens). Locks are PostgreSQL advisory locks held on a connection
  of their own, so a server that dies releases them.
* **`tls_certificates`**, one row per name: its source, issuer, serial,
  validity, ARI window, next attempt, the time it started failing and the
  last error. The console reads this, not CertMagic's cache.
* 5b adds **`tls_names`** (names added in the console, and per-name
  sources) and **`tls_dns_providers`** (sealed DNS credentials).
* All are platform tables like `settings`, outside row-level security,
  reached only through the certificate service, which requires
  `settings.manage`. `database.md` lists them with their migrations.
* **Backup** is the database's: `pg_dump` (and the updater's copy of the
  data root) carries them, and `.env` holds the key that opens them, as
  for every sealed value. A restored install serves the same certificates
  and orders nothing, which keeps clear of the 5-per-week duplicate
  limit. `backup-restore.md` drops the ACME directory from what it backs
  up. After an encryption key rotation, values sealed with a previous key
  stay readable while it is listed and are sealed again at their next
  write, which every renewal is.

### When renewal fails
* **Retries** follow Let's Encrypt's guide: after 1, 10 and 100 minutes,
  then once a day. That stays under 5 failures per hour, and at one a day
  an account is never paused. **Retry now** on the page tries at once.
* **An alert** is raised when a renewal has failed for 24 hours or fewer
  than 14 days are left (warning); when fewer than 7 days are left, or a
  renewal fails after the CA moved its ARI window forward, as it does
  before revoking (critical); and resolved at the next success.
* **It reaches people two ways**, through one interface the certificate
  service calls, `Publish(ctx, Event)`, with a stable key per name
  (`tls:<name>`), opened or resolved, a severity, a summary, the last
  error and a link to Settings → **Certificates**:
  * the console, for super administrators: a banner across the console
    and on the page (and on the Alerts page and dashboard, as ADR-0053
    shows a failing channel, once it is built);
  * *EasyRMM* events, which platform rules of the notification sender of
    ADR-0053 (proposed) can send to their channels. Until that sender
    exists, the interface has only the console behind it, so 5a does not
    wait for it.
* **At expiry**, a name whose Let's Encrypt certificate was chosen in the
  console (5b) goes back to the source `.env` gives it (the authority or
  the operator's files), so agents that trust that source keep working;
  it breaks nothing the expired certificate had not broken already.
  In `acme` mode there is nothing to go back to: the server keeps trying,
  and with IP access on the IP addresses remain a way in.

### The Certificates page (5a)
Settings → **Certificates**, for super administrators: each name, what it
is for (console, remote access, sign-in, patching agents), issuer, expiry,
next renewal, and the last error with its fix. The IP addresses show the
internal authority and its fingerprint. In `offload` mode the page says
the proxy owns TLS.

### The one step (5b)
The page is built around the install that needs it: one on an IP address
getting a name. It also moves a DNS name served by the authority or the
operator's files to Let's Encrypt, and back.

1. **What the operator types:** the name, such as `rmm.example.com`. The
   remote-access name is filled in as `mesh.rmm.example.com` and can be
   changed. No email, no account, nothing else. Moving an existing name
   needs nothing typed.
2. **The records to create**, shown with this server's public address
   (from IP access's addresses, which the operator corrects behind NAT):
   an `A` (and `AAAA`) record for each name, and, when the checks find a
   CAA record set that forbids Let's Encrypt, the `CAA` record to add.
3. **Checks**, each a tick or a failure with its fix:
   * each name resolves (failure);
   * it resolves to one of this server's addresses (a warning, not a
     failure: cloud and NAT hosts see only their private address);
   * CAA, walked up the tree, allows `letsencrypt.org`, and any
     `accounturi` or `validationmethods` it sets match this account and a
     challenge on offer (failure; a lookup that fails gets Let's Encrypt's
     advice, DNSSEC first);
   * ports 80 and 443 answer at the resolved address with a token this
     server serves (a warning: routers often do not loop a host's own
     address back);
   * **a trial order against Let's Encrypt's staging service**, the real
     test, from Let's Encrypt's own vantage points, for every name; its
     failure shows the CA's message and the fix, so a mistake does not use
     up the real service's limits.
4. **Agree and get certificates**: one order per name against the real
   service. A name changes source only once its certificate is in hand;
   until then the old source keeps serving. Nothing restarts.
5. "**Renews automatically; next renewal on** …".

### DNS-01 (5b)
For servers Let's Encrypt cannot reach on port 80 or 443 (internal
networks, a VPN):

* **Providers**: RFC 2136 dynamic update with a TSIG key (BIND, Knot,
  PowerDNS; Windows DNS signs updates with GSS-TSIG, which this does not
  cover), and Cloudflare with an API token, through CertMagic's libdns
  providers (`libdns/rfc2136`, `libdns/cloudflare`, both MIT). Others when
  asked for.
* **Delegation is the recommended setup**, and the page shows it first:
  `_acme-challenge.rmm.example.com CNAME` to a name in a zone used only
  for challenges, which EasyRMM then writes (CertMagic's `OverrideDomain`;
  the check follows the CNAME and fills it in). For RFC 2136 the guide
  gives an update policy that allows only that TXT record. A Cloudflare
  token can only be scoped to a zone, so without delegation EasyRMM holds
  write access to the whole zone, and the page says so.
* **Credentials** are sealed with `EASYRMM_SECRET_KEY`, bound to their
  row, tested when saved (a TXT record created and removed), never shown
  again, and replaced or removed; the audit log names the provider and
  zone, never a secret.
* **DNS-01 proves control of DNS, not that the name reaches this server.**
  Such a name is trusted (below) only once a token served here has been
  fetched through it: by the server through the host's resolver, or, on
  split-horizon networks where the server cannot resolve its own name, by
  the operator's browser from the page.
* **DNS-PERSIST-01** would remove the credentials altogether (the page
  would show one TXT record). It is revisited when Let's Encrypt offers it
  in production and CertMagic supports it.

### Moving between sources (5b)
`EASYRMM_TLS_MODE` stays in `.env`, as the plan says: it is the source a
name starts with and falls back to. The console records, per DNS name,
that it uses Let's Encrypt instead (`tls_names`). Moving a name means
obtaining its certificate first and then switching the source the edge
picks for it, atomically, with no restart: browsers and agents connected
keep their connections, new handshakes get the new certificate. In
`internal` and `manual` modes the edge therefore answers HTTP-01 on port
80 and TLS-ALPN-01 on 443 as well (today only `acme` does), for the names
that move and for trial orders, and in `manual` mode the files need cover
only the names still served from them (`covers`).

**EasyRMM's agents.** As they are today, an agent installed through a DNS
name in `internal` mode would refuse Let's Encrypt, and one installed
under Let's Encrypt would refuse the authority. So 5b changes the agent
and the install commands:

* For a server addressed by a DNS name, the agent trusts the system's
  roots *and* its CA file when it has one; for an IP address, only its CA
  file, as now. Install commands for a DNS name hand over the internal
  authority too, whenever the deployment has one, fetched over the
  connection already verified.
* The heartbeat reports what the agent trusts (`system`, `ca-file`), and
  the server records the origin each device's agent uses (from its signed
  requests' route). Older agents report nothing: one that uses an origin
  served by the authority is taken to trust only its CA file, one that
  uses any other origin only the system's roots.
* **A move is refused while a device seen in the last 30 days would lose
  trust**: to Let's Encrypt, a device that trusts only its CA file; back
  to the authority, one that trusts only the system's roots. The page
  lists them and offers **Update these agents** (ADR-0027's rollout,
  which moves them to a build that trusts both). Devices not seen for 30
  days do not block; they are listed as needing a new install if they
  return.
* Back to the operator's own files: when the files' chain verifies
  against the server image's system roots, nothing can break. When it
  does not (a private CA), the page warns that agents installed under
  Let's Encrypt trust it only if their computers do.

**EasyPatch agents** trust the system's store plus any authority they
were given (above), so a move to Let's Encrypt cannot break them. ADR-0042
is widened: install instructions carry the internal authority whenever the
deployment has one, not only in `internal` mode, and EasyRMM records per
device whether the instruction it sent carried it. Moving the public
URL's name back to the authority is refused while a device's EasyPatch
agent was installed without it (devices installed before the record
existed count as without).

**MeshAgent** is not affected by its pin, which is MeshCentral's agent
certificate. A move of MeshCentral's agent-facing name is one certificate
change: MeshAgents that reconnect wait for MeshCentral's next read of
`certUrl`, at most two minutes, and then reconnect. Two changes within two
minutes are the one thing to avoid, so the console refuses a second move
of that name within 10 minutes, and the cluster's `NOTIFY` keeps several
servers from serving different certificates for it. An IP-only install's
MeshAgents use the IP address, which keeps the authority (above), so 5b's
added name never changes their certificate.

### A name for an install on an IP address (5b)
* **One name pair** (the console's and its remote-access name) can be
  added when `EASYRMM_PUBLIC_URL` is an IP address. Installs that have a
  DNS name already change names in 5c.
* **It is trusted** only once this server holds a Let's Encrypt
  certificate for both names obtained through HTTP-01 or TLS-ALPN-01
  (proof that they reach this server) or, for DNS-01, once the fetch above
  succeeded. Adding it needs step-up authentication (below).
* **Once trusted**, each component is told as follows:

| Component | What changes | How it is told |
|---|---|---|
| Routing and certificates (`newRouter`, `edge.certificates`) | The pair becomes an origin, like an IP-access origin | Rebuilt and swapped atomically |
| CSRF origin check (`httpapi.NewSessions`) and the CSP's `frame-src` | The pair is accepted | Read from the current origins |
| MeshCentral's `allowedFramingOrigins` (`MeshServerConfig`) | The console name is added | `config.json` rewritten; MeshCentral restarts, ending open remote sessions, which the page says before the operator confirms |
| Remote sessions | Launched from the name, they open on its remote-access name | As for every origin (ADR-0016) |
| Install commands (`agentapi.New`, `enrollapi`) | The name's command comes first, for new devices | Rendered again |
| Links in email (`auth.Config.PublicURL`) | Point at the name | Read from the current browser name |
| Authenticator issuer (`auth.Config.Issuer`) | `EasyRMM (<name>)` for new enrolments; existing entries keep their label and keep working | Read when enrolling |
| WebAuthn's relying party (`configureWebAuthn`) | The name: security keys and passkeys become available. An IP install has none registered, so none is lost | Reconfigured |
| The IP console | Links browsers to the name, as it links to the public URL for security keys today | Read from the current browser name |

* **What stays on the IP address until 5c**, because it is registered
  outside the server or is an address agents hold: single sign-on's
  redirect URI (registered at each provider, and for Authentik built from
  `.env` by its blueprint, `docker/authentik/blueprints/easyrmm.yaml`),
  so sign-in through a provider still happens at the IP console; the
  patching engine's public URL (`EasyPatch__PublicUrl` in
  `deploy/docker-compose.yml`, which EasyPatch agents enroll with and
  `links.go` matches them against); MeshCentral's own name (MeshAgents'
  address and `certUrl`); the audit forwarder's host name; and every
  agent already installed.
* **A name whose renewal keeps failing** is flagged, and stops being
  trusted when its certificate expires: the components above go back to
  the IP address. **Remove name** (step-up) does the same at once.

### Who
* **Super administrators** (`settings.manage`, platform-wide) see the
  page and may retry.
* **Step-up authentication** for adding or removing a name, moving a
  name between sources, and DNS credentials: the session's second factor
  confirmed within the last 5 minutes (a code or a key, asked for again),
  or, for an account whose provider is trusted to enforce MFA (ADR-0034),
  a fresh sign-in there. Sessions already record how and when they signed
  in for this (`AMR`, `AuthenticatedAt` in `server/internal/auth`); 5b
  builds the check, and 5c reuses it.
* **Every super administrator is told** when a name is added, removed or
  moved: a notice in the console and, once ADR-0053's sender exists, an
  email.

### Audit
All under `tls.`, with the name, issuer, serial and validity in the
details, never a key or a credential:

* by the system (`ActorSystem`): `tls.certificate_obtain`,
  `tls.certificate_renew`, `tls.certificate_fail` (each failed attempt;
  the retry schedule bounds them), `tls.import` (5a's import),
  `tls.name_trust` and `tls.name_untrust`, `tls.source_fallback` (at
  expiry);
* by a person: `tls.retry`, `tls.trial_order`, `tls.name_add`,
  `tls.name_remove`, `tls.source_change` (from and to),
  `tls.dns_provider_save`, `tls.dns_provider_remove`;
* on the host: `tls.reset` (below).

### Recovery (5b)
`docker compose run --rm server tls reset` returns every name to the
source `.env` gives it and removes names added in the console, keeping
stored certificates and the account; then `docker compose up -d server`.
It is for the case where a choice made in the console locks the
operator out of it. The guide describes it. 5a makes no choice in the
console, and TLS never stops the server from starting, so the command
comes with 5b.

### Slices
* **5a. CertMagic, status and alerts.** Everything above for the names in
  `.env`: CertMagic with ARI and the managed list, PostgreSQL storage,
  `autocert`'s import, optional email, `EASYRMM_ACME_CA_FILE`, the
  Certificates page, alerts through the interface, the audit records of
  the system and `tls.retry`. Mergeable without 5b: no name or source
  changes, and an install upgraded to it serves the same certificates.
* **5b. Names and sources from the console.** The checks and the staging
  trial, moving between sources with the agent and instruction changes
  above, DNS-01, an IP install's name, step-up authentication, `tls
  reset`.
* **5c begins** where 5b stops: moving agents (EasyRMM's agent, MeshAgent's
  `.msh`, the EasyPatch agent's `ServerUrl`) to the name, changing a DNS
  install's console name, and moving single sign-on's redirect URIs,
  Authentik's address and the engine's public URL with it. It needs F0 and
  its own ADR.

### Where this differs from the plan
* **Single sign-on, Authentik's address and the engine's address** stay
  with 5c, not 5b: each is registered outside the server or held by
  agents, and moving them is moving a name.
* **A per-name source in the console**, beside the TLS mode in `.env`,
  is what lets a name move to Let's Encrypt and back without a restart.
* **The agent's trust and ADR-0042's condition change**: without that, a
  move would cut agents off.
* **`tls reset`** comes with 5b, which makes the choices it undoes.
* **Alerts** open after 24 hours of failure, not at the first one, which
  the retries usually fix; a critical level is added at 7 days.
* **New**: `autocert`'s import, and `setup.sh` no longer sending the
  administrator's address to Let's Encrypt.

## Testing
Pebble, Let's Encrypt's test CA (with ARI and configurable profiles), runs
in containers on **host networking only**, never on a bridge, on loopback
ports of its own, with BIND on host networking as the DNS that Pebble
(`-dnsserver`) and the server resolve the test names with.

* **Unit**: the seal's binding in `tls_storage`, certificate selection per
  source, the retry schedule, the alert thresholds, CAA tree walking and
  its parameters, the trust rules that refuse a move.
* **PostgreSQL integration**: the storage against CertMagic's contract;
  two CertMagic instances on one database order once and both serve the
  result; a lock released when its connection dies.
* **A challenge test** (integration, the edge against Pebble): HTTP-01
  alone, TLS-ALPN-01 alone (port 80 off), and DNS-01 through RFC 2136
  against BIND with a key allowed only `_acme-challenge`, directly and
  through a CNAME delegation.
* **The bundle test** gains a parallel job with Pebble, on the release
  bundle and real agents: an install by name in `acme` mode issues at
  start; the Linux machine (Pebble's root in its store) enrolls through
  the name, its MeshAgent connects and a remote session opens; **renewal
  with a short-lived certificate** (Pebble's profile set to minutes): a
  new serial is served, MeshCentral logs that it loaded the new
  certificate, MeshAgent reconnects and a session opens again; Pebble's
  validation made to fail: the alert opens, and resolves once it works
  again. The upgrade: the previous release with `autocert` against
  Pebble (trusting it through `SSL_CERT_FILE`, which Go reads, since that
  release has no setting for it), upgraded with `setup.sh --upgrade`,
  serves the same serial and places no order.
* **5b in the bundle test**: the IP install at `https://127.0.0.1` adds a
  name; the agent on the IP address keeps working, a new one enrolls
  through the name; an internal-mode name with an agent from the previous
  release is refused a move until that agent is updated, then moves, and
  moves back; `tls reset`.
* **Stand-ins, flagged as such**: in CI a second Pebble plays Let's
  Encrypt's staging for the trial order. Cloudflare runs against a real
  account on `main` only, or is marked unverified.
* **By hand**, recorded in IMPLEMENTATION_STATUS: a real Let's Encrypt
  staging run on a real host and name (the checks, the trial, issuance,
  a forced renewal, MeshAgents reconnecting), then production on the
  owner's next full instance with DNS.

## Consequences
* An install by name gets certificates at start and renews them without
  anyone; an install on an IP address gets a trusted name from one page,
  with nothing typed but the name.
* Nothing is sent to Let's Encrypt but what issuance needs: no email
  unless the operator sets one. PRIVACY.md says so.
* Certificates and the account move into the database and its backup;
  the ACME directory leaves the backup guide.
* The agent gains a wider trust for DNS names (system roots plus the
  authority), which every agent under a public certificate already has
  for its roots; IP addresses keep the authority only.
* EasyPatch install instructions carry the authority whenever there is
  one, amending ADR-0042's condition.
* MeshCentral restarts when an added name changes its framing origins,
  ending open remote sessions; certificate changes alone never restart
  it.
* Single sign-on and the engine's address stay on an IP install's address
  until 5c.

## Alternatives considered
* **Keep `autocert`.** No ARI, ordering at the first handshake, a
  directory per server, no events for alerts.
* **Let's Encrypt's IP certificates.** They would cut off every agent
  installed by IP address, and last 160 hours.
* **One certificate for all names, or a wildcard.** Above.
* **A second CA as a fallback** (CertMagic can hold several issuers):
  another party for every install, and ZeroSSL needs an account;
  certificates keep weeks of validity through a Let's Encrypt outage, and
  the alert covers it.
* **TLS mode from the console.** `offload` and trusted proxies belong to
  the host's setup; a per-name choice gives the same result without the
  server rewriting its own configuration.
