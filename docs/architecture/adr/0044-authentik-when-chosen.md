# ADR-0044: Authentik, when chosen

* Status: Accepted (2026-11-19)
* Plan: [one product](../one-product-plan.md), phase A.
* Adds to: [ADR-0034](0034-oidc-single-sign-on.md) (single sign-on with
  OpenID Connect). Uses the further names of the edge from phase S0.

## Context
Some MSPs want one sign-in for their people, with a second factor they
control, without running an identity provider of their own. Authentik
(MIT, self-hosted) can be that provider, but setting it up by hand is a day
of work: a database, a reverse proxy, an OpenID provider, flows, a second
factor, an invitation, and EasyRMM's side of it. The owner's rule: Authentik
can be a flag, but with the flag set, setup must be dead simple.

That is: `setup.sh --with-authentik`, two questions, `docker compose up -d`,
open the printed link.

## Decision

### Set-up
* `setup.sh --with-authentik` asks for Authentik's **sign-in name** (such as
  `auth.example.com`) and the **administrator's email**, or takes them from
  `--authentik-hostname` and `--admin-email`. It needs root, and refuses TLS
  offload: EasyRMM's own edge serves Authentik's name. Without
  `--acme-email`, ACME's account address is the administrator's.
* It writes `EASYRMM_AUTHENTIK_HOSTNAME`, `EASYRMM_AUTHENTIK_ADMIN_EMAIL`,
  and three secrets to `.env` (EasyRMM's client secret, Authentik's secret
  key and its database password), and adds `authentik` to
  `COMPOSE_PROFILES`.
* It makes `authentik/{data,secrets,invitations}` under the data root, owned
  by Authentik's user (uid 1000), mode 0700. `akadmin`, Authentik's own
  break-glass account, gets a random password in
  `authentik/secrets/akadmin-password` (0600), made once.
  `docker/authentik/start.sh` hands it to Authentik as
  `AUTHENTIK_BOOTSTRAP_PASSWORD` from the file, so it is never in `.env`.
* It prints the administrator's **invitation link** and what to do next.

### Authentik's services
Four services under the `authentik` profile, all on host networking, all
read-only with every capability dropped and `no-new-privileges`:

* `authentik-db-init` (the PostgreSQL image) creates or updates the
  `authentik` role and database in EasyRMM's PostgreSQL, idempotently, also
  on an existing install.
* `authentik-server` and `authentik-worker` run Authentik 2026.8.5,
  pinned by digest. The server listens on `127.0.0.1:18280` (HTTP) and
  `127.0.0.1:18243` (HTTPS), the worker on `127.0.0.1:18281`; metrics are
  off. Update checks, startup analytics and error reports are off. Only
  loopback is a trusted proxy. Outpost discovery and the embedded outpost
  are off. Their health checks allow 15 minutes for the first start, which
  migrates Authentik's database: the image's own 2 minutes were too short on
  a busy machine, and the worker was marked unhealthy before it was ready.
* `authentik-setup` runs once after each start, when the worker is healthy
  (`docker/authentik/setup.py`, through `ak shell`). It waits for EasyRMM's
  blueprint, then sets what blueprints cannot: people may not change their
  email address or username, and avatars are initials, so no browser asks
  Gravatar about anyone. Then it creates the pending invitation, if any.

### EasyRMM's edge serves Authentik's name
`EASYRMM_AUTHENTIK_HOSTNAME` is one of the edge's further names
(`config.ExtraHostnames`). It is covered by ACME, by the manual certificate
(checked at start), or by EasyRMM's own authority in internal mode. The
edge reverse-proxies it to `EASYRMM_AUTHENTIK_UPSTREAM` (fixed in the
compose file at `127.0.0.1:18280`; only loopback is accepted). The proxy:

* keeps the `Host`;
* sets `X-Forwarded-For` to the client the edge saw, and
  `X-Forwarded-Proto` and `X-Forwarded-Host`, replacing whatever the client
  sent;
* drops `Forwarded`;
* passes WebSocket upgrades;
* adds HSTS when Authentik sends none;
* answers 502 "Sign-in is not answering. Try again in a minute." with
  `Retry-After` when Authentik is down.

Authentik gets its own name because its sub-path mode has open bugs in
2026.8.5.

### The blueprint
`docker/authentik/blueprints/easyrmm.yaml` is applied by the worker at the
first start and whenever it changes. It makes:

* **EasyRMM's OpenID provider and application** (slug `easyrmm`):
  * confidential client `easyrmm`, with the secret from `.env`, for the
    authorization code grant only (2026.8 refuses any grant a provider does
    not list);
  * one strict redirect URI, `<EASYRMM_PUBLIC_URL>/api/v1/auth/sso/callback`;
  * the openid, email and profile scopes;
  * a hashed user id as subject, and an issuer per provider;
  * implicit consent.
* **A second factor in the authentication flow**, TOTP or WebAuthn, set up
  on the spot when missing.
* **No self-registration and no self-service recovery** from the sign-in
  page.
* **The enrollment flow `easyrmm-enrollment`**, steps in order:
  1. an invitation is required;
  2. name, password and password again (the email shown is the
     invitation's);
  3. the user is written and signed in;
  4. a second factor is set up;
  5. a redirect to EasyRMM's sign-in through this provider
     (`/api/v1/auth/sso/<id>/start`), which completes without asking again.

### The invitation
Blueprints are applied again, so a single-use invitation in one would come
back after use. And `setup.sh` runs before Authentik exists. So `setup.sh`
only *decides* the invitation: a random id, the administrator's email, and
an expiry 7 days out. It writes them to `authentik/invitations/pending` and
prints the link `https://<sign-in name>/if/flow/easyrmm-enrollment/?itoken=<id>`.

At the next start, `authentik-setup` creates the invitation:

* single-use, for the enrollment flow only;
* with the email and username fixed to the administrator's;
* replacing any earlier unused invitation of `setup.sh`'s.

It then removes the pending file, so an invitation Authentik deleted on use
never comes back. `setup.sh --new-invitation` decides another; it works
after the next `docker compose up -d`.

Authentik uses an invitation up when its link is **opened**, not when the
sign-up finishes. A sign-up left half-way can be finished in the same
browser; otherwise `--new-invitation`.

### EasyRMM's side
* **A deployment-managed provider.** When `EASYRMM_AUTHENTIK_HOSTNAME` is
  set, the server makes or updates, at each start, the provider with the
  fixed id `b2927669-72ce-48a1-a83d-8215013be7ab`, named "Authentik":
  * issuer `https://<name>/application/o/easyrmm/`;
  * client `easyrmm` with the secret from `.env`;
  * the administrator's email domain as its one allowed domain;
  * trusting the provider's email and second factor.

  It is marked `managed` (migration 00021). The API refuses to change or
  delete it (409 `provider_managed`), and Settings → Single sign-on shows it
  locked. Changes are audited as made by "deployment". If the setting is
  removed, the provider is disabled and no longer managed, and its links
  stay for the audit log. If its name is taken, it becomes
  "Authentik (deployment)".
* **Email and second factor are trusted.** Authentik's email scope sends
  `email_verified: false` by default, but here the email is fixed by the
  invitation and cannot be changed. Authentik's flow requires a second
  factor on every sign-in, so EasyRMM counts it done (session `amr`
  `fed`, `mfa`). Other providers are unchanged (ADR-0034).
* **The first super administrator.** When the database has no users, the
  server creates the administrator's account at start: their email, no
  password, the global super administrator role, audited as
  `setup.complete` by "deployment". ADR-0034's rule links it to the
  Authentik account at the first sign-in, by the email. There is no setup
  token and no first-run page.
* **No group mapping.** Authentik's groups are in its profile scope, and
  EasyRMM never reads them. Mapping them would make anyone who can edit a
  group in Authentik a super administrator of every managed computer.
  Roles are granted in EasyRMM only. Later people are invited in EasyRMM as
  before, and need an Authentik account with the same email.
* **Hairpin.** For this provider, discovery, keys and token calls use an
  HTTP client that:
  * dials only Authentik's name, and dials it at EasyRMM's own HTTPS
    listener on loopback (`127.0.0.1:443` for `:443`);
  * verifies TLS for the public name against the system's roots, plus
    EasyRMM's authority in internal mode;
  * follows no redirects and times out after 15 seconds.

  Many routers do not loop a server's public address back to itself, and
  the server need not resolve its own names. Discovery is not run at start,
  when the edge is not yet listening.
* **Break-glass.** `easyrmm-server recover [--email <address>]`, run on the
  server (`docker compose exec server easyrmm-server recover`), prints a
  one-time link to `<public URL>/recover#token=<token>`. The link:
  * is for an active super administrator (with several, `--email`
    chooses);
  * is valid for 15 minutes and works once;
  * is stored only as a hash (`recovery_links`).

  The page sends the token (in the fragment, never in a request line or a
  log) and the server signs in with method `recovery_link`, second factor
  counted done: shell access to the server is the trust root anyway, and no
  standing password exists. Issuing is audited (`auth.recovery_link`, by
  "recover command"); so is each use or failed attempt (`auth.login`).
  Attempts are rate-limited per address, disabled accounts are refused, and
  expired links are deleted a day later.

## Consequences
* Turning Authentik on is one flag, two answers and one link. Its three
  secrets, akadmin's password and the database are made by `setup.sh` and
  `authentik-db-init`.
* Authentik adds two long-running containers (about 500 MiB of memory
  between them during the first start; steady use was not measured) and a
  first start of several minutes while it migrates its database (about 6
  on the test machine, with other work running).
* Authentik's authenticator-app entries are named "authentik"; 2026.8.5 does
  not let the issuer be set per stage.
* akadmin keeps Authentik's default address (`root@example.com`); it is
  Authentik's own account, not a person's, and has no EasyRMM account.
* TLS offload is not supported with Authentik: the edge must hold the name.
* The image includes Authentik's `enterprise/` directory under its own
  licence. This deployment sets no enterprise licence, so that code is never
  activated; everything used is MIT.
* Taking Authentik out (empty `EASYRMM_AUTHENTIK_HOSTNAME`, no `authentik`
  profile) leaves its provider disabled in EasyRMM. Super administrators
  then sign in with `easyrmm-server recover` until they set a password or
  another provider.

## Verification
`make e2e-authentik` (CI's *Authentik end to end*; `scripts/e2e/authentik.sh`)
builds EasyRMM's and the engine's images from the commit. It sets up the
release's deployment tree with
`setup.sh --with-authentik` for `https://127.0.0.1`
(internal authority) and `auth.easyrmm.test`. That name resolves nowhere:
Chromium maps it to 127.0.0.1, and EasyRMM reaches it over loopback. The
test brings the tree up on host networking and checks that only the edge
listens beyond loopback, that Authentik listens on its three loopback ports
with no metrics port, and that its discovery document through the edge
names the right issuer. Then Playwright:

1. finds no first-run page, only *Sign in with Authentik*;
2. opens the printed invitation, makes the account with an authenticator
   app, and lands on the dashboard as super administrator;
3. makes an organization, reads the engine's empty fleet for it, and adds
   an alert rule for it in the engine;
4. finds the invitation refused; `setup.sh --new-invitation` and
   `docker compose up -d` give a link that opens the sign-up for the
   administrator;
5. gives Authentik a second user with an authenticator, in the same domain,
   and is refused by EasyRMM (`no_account`), with no account added;
6. signs in again in a new browser, and is asked for the second factor;
7. stops Authentik, gets the edge's 502, then signs in with
   `easyrmm-server recover`'s link, once.

It passed all seven steps locally on 2026-11-19 (the browser story in about
2 minutes); it has not run on GitHub yet. It goes through Authentik's pages
a stage at a time, and reloads when Chromium drops a request because the
host's network interfaces changed, which other containers on a shared
machine cause.

Go integration tests cover the provider (Dex, with a client that counts its
requests), the hairpin client and proxy (the internal authority, a stand-in
edge), the first administrator, recovery links, the command, and the HTTP
API; the web tests cover the recovery page and the locked provider.

Not verified: ACME for Authentik's name and the hairpin over a real public
address (the test uses the internal authority), WebAuthn as Authentik's
second factor (the test uses TOTP), and upgrading Authentik in place.
