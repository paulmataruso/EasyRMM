# ADR-0036: EasyRMM is EasyPatch's sign-in provider

* Status: Superseded by [ADR-0046](0046-what-one-product-retires.md)
  (2026-11-19). Accepted 2026-11-17, built on both sides (P4a to P4c) and
  tested end to end in a browser (P4d). Removed in one-product phase R: the
  patching engine runs in the deployment and takes EasyRMM's statements
  (ADR-0038), so nobody signs in to EasyPatch any more.
* Refines: ADR-0006 (sessions and mandatory MFA), ADR-0030 (the EasyPatch
  connector), ADR-0034 (single sign-on).
* Plan: [EasyPatch integration plan](../easypatch-integration-plan.md),
  sections 6.3 and 6.4.

## Context
EasyRMM owns EasyPatch. People move between the two consoles with the product
switch (P3), and each switch landed on a second sign-in page. Access was
also kept twice: an organization administrator in EasyRMM had to be given an
EasyPatch account by hand, and taking EasyRMM access away left the EasyPatch
account in place.

EasyPatch already has an OpenID Connect client (authorization code, PKCE,
`state`, `nonce`; `OidcService.cs`). Three ways to sign in once were weighed
(plan 6.3): both trusting the MSP's own identity provider, EasyRMM as an
OpenID provider, and a custom signed hand-off. A provider reuses EasyPatch's
client and a standard protocol, with one identity: EasyRMM's.

What must not happen:

* **Account takeover by email.** EasyPatch links provider sign-ins to
  existing accounts by verified email. If EasyRMM's sign-in did that, an
  EasyRMM user could take over an EasyPatch account with the same address.
* **Over-granting.** A grant on one EasyRMM site must not open a whole
  EasyPatch organization, and EasyPatch's own empty-list-means-all rule
  (fixed in P1) must not be reachable.
* **A weaker second factor.** EasyPatch's administrators may expect a
  second factor; EasyRMM can run with `EASYRMM_REQUIRE_MFA=false`.
* **Cross-site cookies.** EasyRMM's session cookie is SameSite=Strict, so
  it does not arrive on EasyPatch's cross-site redirect.

## Decision

**A deliberately small provider** (`server/internal/idp`,
`server/internal/httpapi/idpapi`).

* The authorization code flow only, with PKCE (S256), `state`, `nonce` and
  the `openid` scope all required. No implicit or hybrid flow, no refresh
  tokens, no userinfo endpoint, no consent screen, no dynamic registration,
  no `request` objects. Discovery says so.
* **One client: EasyPatch.** A super administrator creates it under
  **Settings → EasyPatch → Sign-in**, only when EasyPatch is connected and
  lists the `easyrmm-sign-in` capability. The client ID is random
  (`easypatch-…`); the secret is 256 random bits, shown once and kept as a
  SHA-256 hash. Replacing it stops the old one at once. Removing the client
  turns the provider off: every provider route answers 404, and codes not
  yet redeemed are deleted with it.
* **The redirect URI** is exactly EasyPatch's public address plus
  `/api/v1/auth/sso/callback`, fixed when the client is created. A request
  naming another client or redirect URI is answered on EasyRMM with a plain
  error page and never redirected (RFC 6749, 4.1.2.1). When EasyPatch's
  address changes, the settings page says to set sign-in up again.
* **Routes.** `/.well-known/openid-configuration`, `/oauth2/jwks`,
  `/oauth2/authorize` (GET and POST) and `/oauth2/token`, with the issuer
  `EASYRMM_PUBLIC_URL`. They sit outside the console's CSRF layer, like the
  agent API: EasyPatch's server calls the token endpoint itself.
  `authorize` reads the session (the session layer runs, and never rejects);
  `token` authenticates the client itself, with `client_secret_basic` or
  `client_secret_post` (one, not both). Both are rate-limited per address.
* **Codes** are 256-bit, single use (the first redemption marks them, whatever
  follows), valid 60 seconds and stored as SHA-256 hashes. Each is bound to
  the client, the redirect URI, the session, the user, the `nonce` and the
  PKCE challenge. The token endpoint checks all of them, then checks again
  that the session is still active and the user still has access: roles can
  change in that minute.
* **ID tokens** are signed with ES256. The key is made on first use, sealed
  under the secret key (additional data: its key id) in
  `idp_signing_keys`, and published at `/oauth2/jwks`. They live 5 minutes.
  Claims: `iss`, `aud`, `sub` (the EasyRMM user id), `exp`, `iat`,
  `auth_time`, `nonce`, `name`, `email` with **`email_verified: false`**,
  `amr`, and `easypatch` (below). `email_verified` is false on purpose: it
  stops any EasyPatch provider setting from linking accounts by email.
  `amr` is the session's methods with `mfa` always added: only multi-factor
  sessions get a token, and `mfa` is the one value EasyPatch needs to
  understand (it cannot know that `rc` is a second factor).
* The token response carries an `access_token`, because OAuth requires one.
  It is random, not stored, and opens nothing.

**Who may sign in.**

* **Sessions record how they signed in** (`sessions.amr`, RFC 8176 values):
  `pwd`, `fed` (single sign-on), `otp`, `hwk`, `rc` (a recovery code, EasyRMM's
  own value), and `mfa`. A passkey sign-in records `hwk` and `mfa`: it requires
  user verification. Single sign-on from a provider an administrator marked
  as enforcing MFA records `fed` and `mfa`. `authenticated_at` is when the
  session became active.
* **A second factor is required**, even with `EASYRMM_REQUIRE_MFA=false`:
  `pwd` or `fed` with `otp`, `hwk` or `rc`, or `mfa`. Sessions from before
  this change have no `amr` and are refused until their person signs in
  again; the refusal says so.
* **Access comes from one function**, `easyPatchAccess` (P3,
  `server/internal/easypatch/access.go`): a super administrator is a
  SuperAdmin; otherwise only organization-wide grants on linked
  organizations count, Admin where the person has `patch.configure`, else
  ReadOnly where they have `patch.view`. No access, no sign-in. The result is
  the `easypatch` claim: `{"role": "...", "organizations": [EasyPatch ids]}`.

**Refusals** go back to EasyPatch's callback as `error=access_denied` (or
`login_required`, `invalid_request`, `invalid_scope`,
`unsupported_response_type`) with `state` and `iss` (RFC 9207). EasyPatch shows
its own error page, so there is no EasyRMM page for Back to bounce off.

**No session yet: one bounce.** A cross-site redirect arrives without the
SameSite=Strict cookie. `authorize` then sends the browser to EasyRMM's
`/login?returnTo=/oauth2/authorize?…&bounced=1`. The console checks the
session with its own same-origin request, which the cookie accompanies, and,
signed in or once signed in, leaves for the `returnTo` with a full page load
(the `/oauth2/*` route). That load is same-site, so the cookie comes. A second
arrival without a session (`bounced=1`) returns `login_required` instead of
looping. `prompt` is not supported: `prompt=none` would need the console to
stay invisible, and EasyPatch does not send it.

**Links from EasyPatch** use the same idea. `/go/from-easypatch/{endpoints,
organizations,jobs}/:id` is a console route: the console asks
`GET /api/v1/patching/from-easypatch/{kind}/{id}` with its own request and
opens the device's Patches tab, the organization, or the Patching job dialog.
What the person may not see, or EasyRMM does not link, opens Patching with a
notice. The notice comes from the server in router state, never from the
URL, so a crafted link cannot put words on the page.

**Audit.** `idp.authorize` on success and on each refusal after the client
is known, with the reason, role and organization count;
`idp.client_create`, `idp.client_rotate` and `idp.client_delete`.

**EasyPatch's side** (P4b, P4c; plan 6.4) adds a provider kind "EasyRMM":
accounts matched by issuer and subject only and never by email; role and
organizations taken from the `easypatch` claim at every sign-in; SuperAdmin
accepted only from this kind; the second factor counted only when `amr`
contains `mfa`; sessions of at most one hour, renewed silently.

## Consequences
* One identity: removing someone's EasyRMM access ends their EasyPatch
  sign-ins, and their EasyPatch role follows their EasyRMM roles (within an
  EasyPatch session's lifetime).
* EasyRMM gains an authorization server. Its surface is kept small and off
  until a super administrator sets it up; it is tested end to end with a
  standard client (go-oidc and x/oauth2) against the real server,
  including single use, PKCE, expiry, revoked sessions, access removed
  between authorize and token, and secret rotation.
* People signed in before this change must sign in once more before they
  can use EasyPatch through EasyRMM.
* The provider lives at the public URL. Like passkeys and single sign-on
  (ADR-0032, ADR-0034), it does not work at EasyRMM's IP addresses.
* EasyPatch's server must reach EasyRMM's public URL over HTTPS for
  discovery, keys and tokens. On the same server (ADR-0035) that is
  EasyRMM's own edge; the co-hosting guide covers it (P4d).
