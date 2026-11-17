# ADR-0034: Single sign-on with OpenID Connect

* Status: Accepted (2026-11-17).
* Refines: ADR-0006 (sessions and mandatory MFA), ADR-0032 (passkeys).

## Context
MSPs keep their technicians in an identity provider: Microsoft Entra ID,
Google Workspace, Okta, Keycloak, Authentik. They want technicians to sign in
to EasyRMM with that account. When someone leaves, disabling them there should
also close EasyRMM. OpenID Connect (OIDC) is the protocol all of them speak.

An RMM account reaches every managed machine, so sign-in through a third
party must not open a new way in:

* **Account takeover through email.** If EasyRMM matched accounts by email,
  anyone who could make a provider assert an email address could take over
  that EasyRMM account. That includes an unverified address, or another
  tenant of a multi-tenant provider (the "nOAuth" class of bugs).
* **Login CSRF.** An attacker's own sign-in must not be completed in the
  victim's browser.
* **Weaker second factor.** EasyRMM requires a second factor (ADR-0006). A
  provider sign-in may or may not have used one.

## Decision
* **Library.** [coreos/go-oidc](https://github.com/coreos/go-oidc) v3
  (Apache-2.0) for discovery and ID token checks, and
  [golang.org/x/oauth2](https://pkg.go.dev/golang.org/x/oauth2) (BSD-3) for
  the code exchange. Both are maintained, widely used and on the licence
  allow-list.
* **Providers.** Zero or more, set up by super administrators under
  **Settings → Single sign-on**, stored in `identity_providers`. Each has:
  * a name (the sign-in button says "Sign in with *name*");
  * the issuer URL and the client ID;
  * the client secret, sealed under the secret key and never returned;
  * the email domains it may sign in (at least one);
  * two choices: whether its email addresses are managed by the
    organization, and whether EasyRMM's second factor is skipped;
  * whether it is enabled.

  Saving checks the issuer's discovery document, so a wrong URL is caught
  then and not at someone's first sign-in. The issuer must use HTTPS. Plain
  HTTP is allowed for loopback addresses only, for tests.
* **The flow.** Authorization code flow with PKCE (S256), `state` and
  `nonce`; scopes `openid email profile`.
  * The start step puts the provider, `state`, `nonce`, the PKCE verifier,
    the return path and an expiry (10 minutes) in a cookie,
    `__Host-easyrmm_sso`. The cookie is sealed under the secret key,
    HttpOnly, and SameSite=Lax, so it comes back on the provider's top-level
    redirect.
  * The callback requires that cookie and the matching `state`, and
    deletes it. A sign-in started in another browser (login CSRF) or
    replayed therefore fails.
  * The ID token is verified by go-oidc: signature against the provider's
    keys, issuer, audience (the client ID), expiry. The `nonce` must match.
* **One redirect URI.** `<EASYRMM_PUBLIC_URL>/api/v1/auth/sso/callback` for
  every provider: the cookie says which one. Administrators can register it
  with the provider before creating the provider in EasyRMM. Single sign-on
  therefore works only at the public URL. From another address, the
  sign-in page's buttons point there, as passkeys do (ADR-0032).
* **Accounts are linked, never created.**
  * An identity is the provider and the token's `sub`, stored in
    `user_identities`. Later sign-ins match on that alone, so a changed
    email address at the provider neither breaks nor moves the link.
  * At someone's first sign-in through a provider, EasyRMM links the
    identity to the active EasyRMM account with the same email address,
    only if:
    * the address's domain is one of the provider's domains; and
    * the provider says the address is verified (`email_verified: true`),
      or the administrator marked the provider's addresses as managed by
      the organization. Microsoft Entra ID sends no `email_verified`; for
      it, use the tenant's own issuer, never `common` or `organizations`.
  * Otherwise sign-in is refused: no account, a domain not allowed, an
    unverified address, or a disabled account. Each refusal is audited with
    its reason.
  * Accounts are still created by invitation (ADR-0006). There is no
    just-in-time creation and no role mapping from groups yet.
* **Second factor.**
  * By default a single sign-on is the first factor only. The person then
    uses their EasyRMM second factor, or sets one up if they have none,
    exactly as after a password.
  * An administrator who knows the provider enforces MFA can tick "This
    provider requires multi-factor authentication". Its sign-ins then
    complete EasyRMM's sign-in directly. EasyRMM cannot check this: `amr`
    claims are optional and inconsistent between providers. The setting
    says so.
* **Passwords stay.** People with a password can still use it. A setting
  to require single sign-on for a domain is not part of this decision.
  Actions that ask for the password again (adding a key, recovery codes)
  still need a password. Someone who only ever used single sign-on sets
  one through **Forgot your password?** or an administrator's reset.
* **Sessions.** A single sign-on produces an ordinary EasyRMM session with
  the same lifetime, idle timeout and revocation. Signing out of EasyRMM
  does not sign out of the provider, and the reverse is also true: the
  session ends at its own timeouts. Disabling the provider, or deleting
  it, stops new sign-ins through it.
* **Audit.**
  * `auth.login` with method `oidc` and the provider, on success or
    failure; failures carry their reason.
  * `auth.sso_link` when an identity is linked.
  * `sso.provider_create`, `sso.provider_update` and
    `sso.provider_delete`.
* **Tests** run against a real provider, Dex, in a container on the host
  network (`make test-oidc`), driving its login form like a browser.

## Consequences
* Leavers are cut off at the provider for new sign-ins. Sessions already
  open last until their timeout (at most 12 hours by default) unless an
  administrator revokes them or disables the EasyRMM account.
* The default asks for EasyRMM's second factor after the provider's own.
  That is safe but adds a step. The opt-out rests on the administrator's
  word about the provider.
* One public URL is part of the configuration at the provider. Changing
  `EASYRMM_PUBLIC_URL` means updating the redirect URI there too.
* Not built yet: just-in-time accounts, roles from groups, requiring
  single sign-on, SAML, and back-channel logout.

## Alternatives considered
* **Matching accounts by email on every sign-in.** Simpler, but an email
  change or a second provider asserting the same address would move the
  account. The `sub` is the stable identifier OIDC defines.
* **Trusting `amr` for the second factor.** Entra ID, Google and Okta differ
  in what they send, and some send nothing. An explicit setting is honest
  about who vouches for it.
* **A table of in-flight sign-ins instead of a cookie.** It gives the same
  guarantees once the cookie binds the flow to the browser, and needs
  clean-up. A sealed cookie needs neither.
* **SAML.** Older, XML signatures, more ways to get it wrong. Every provider
  above also speaks OIDC.
