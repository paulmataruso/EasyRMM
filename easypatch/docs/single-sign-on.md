# Single sign-on (OpenID Connect)

Administrators can sign in to the EasyPatch console with an OpenID Connect identity provider, such as
Microsoft Entra ID, Google or Keycloak. Each enabled provider adds a **Sign in with &lt;name&gt;** button
to the sign-in page. Signing in with an email address and password, and with a passkey, stays
available. Single sign-on is for the console only; agents never use it.

Super administrators configure providers under **Settings → Single sign-on**.

## How it works

* **Flow.** The authorization code flow with PKCE (`S256`), a `state` and a `nonce`. When the user
  clicks the button, the server stores the pending sign-in (the hash of `state`, the `nonce` and
  the PKCE verifier) and sends the browser to the provider. A pending sign-in is used once,
  expires after 10 minutes and is bound to the browser that started it by a random value in a
  `__Host-easypatch-sso` cookie (`HttpOnly`, `Secure`, `SameSite=Lax` so that it comes back with
  the provider's redirect; the server stores only its SHA-256).
* **Callback.** The provider sends the browser back to `/api/v1/auth/sso/callback`. The server
  redeems the code at the provider's token endpoint (with the client secret, or with PKCE only
  for a public client) and checks the ID token: the signature against the provider's published
  keys (JWKS; RSA and ECDSA algorithms only), the issuer, the audience (the client ID, and
  `azp` when there are several audiences), the expiry and not-before times (2 minutes of clock
  tolerance) and the nonce. The email address is read from the ID token; EasyPatch does not
  call the userinfo endpoint.
* **Discovery.** The server reads `<issuer>/.well-known/openid-configuration` and the key set
  over HTTPS only, without following redirects, with a 15-second timeout and size limits. The
  discovery document must name exactly the configured issuer (a trailing `/` is ignored), and the
  authorization and token endpoints must use HTTPS. Documents are cached for up to 12 hours;
  a token signed with an unknown key makes the server read the key set again (at most every 5
  minutes). **Check** on the settings page reads them immediately.
* **Outbound connections.** The `api` container connects to each configured provider's
  discovery, key set and token endpoints (TCP 443). The browser, not the server, talks to the
  authorization endpoint.

### Which EasyPatch account signs in

1. **Linked account.** A provider account that is already linked (by the token's issuer and
   subject, `iss` and `sub`) signs in as its EasyPatch user, whatever email address the provider
   reports now.
2. **First sign-in, existing user.** Otherwise the ID token's `email` claim is compared with the
   EasyPatch users' addresses (ignoring case). It is used only when the token says
   `email_verified: true`, or when **Trust the provider's email claim** is ticked. The matching
   user must be active and must not already be linked to another account at the same
   provider. The link is then stored, and later sign-ins use it.
3. **First sign-in, no user.** With **Create accounts on first sign-in** ticked (it is off by
   default), an account is created for an address in one of the **Allowed email domains**
   (required), with the chosen role: **Read only** (the default) or **Admin**, never super
   administrator. The account has no password and no organization restriction: it can access
   every organization until a super administrator restricts it under **Settings → Users**.
4. Otherwise the sign-in is refused.

Disabled and locked-out users cannot sign in with single sign-on either.

### MFA

By default EasyPatch's own MFA still applies after single sign-on: a user with an
authenticator app, a passkey or a security key completes that step as after a password, and
a user without one must set one up while the server requires MFA.

Tick **The provider enforces MFA** only when the provider requires MFA for every user of this
application (for example a Conditional Access policy in Entra ID). Sign-ins through such a
provider skip EasyPatch's second factor, and a user without one is not asked to set one up for
that session.

### Accounts without a password

Accounts created by single sign-on have no password. Where the console would ask for the current
password (adding or removing a passkey or security key once MFA is set up, removing the
authenticator app, generating new recovery codes), such an account must instead have signed in
within the last 10 minutes; otherwise it is asked to sign out and sign in again. A super
administrator can send them a password link under **Settings → Users** if they should also sign
in with a password.

### Errors

A refused sign-in returns to the sign-in page with a general message. The audit log (`auth.sso_failed`)
records the provider and the reason, for example `email_not_verified`, `no_matching_user`,
`domain_not_allowed`, `linked_to_other_account`, `inactive`, `state_expired`,
`other_browser`, `nonce_mismatch`, `issuer_mismatch` or `invalid_token:<check>`. Tokens,
authorization codes, client secrets and claims are never logged or audited.

## Settings

| Setting | Meaning |
|---|---|
| Name on the sign-in button | "Sign in with &lt;name&gt;" |
| Issuer | The provider's issuer URL (`https://`, no query). Use **Check** to read its discovery document |
| Client ID | The application (client) ID registered at the provider |
| Client secret | Write-only: stored encrypted with ASP.NET Data Protection (like the SMTP password) and never shown again. Leave it empty for a public client |
| Scopes | Separated by spaces; must include `openid`. Default `openid email profile` |
| Enabled | Shows the button. Disabled providers cannot start a sign-in |
| The provider enforces MFA | See [MFA](#mfa) |
| Trust the provider's email claim | Link by email address without `email_verified: true`. See the provider notes below |
| Create accounts on first sign-in | With **Role of new accounts** and **Allowed email domains** |

**Redirect URI.** Register `https://<EASYPATCH_DOMAIN>/api/v1/auth/sso/callback` at every
provider (the settings page shows the exact value, which comes from `EASYPATCH_PUBLIC_URL` or
`EASYPATCH_DOMAIN`). Providers generally require HTTPS, and Google does not accept an IP
address, so use a DNS name.

**Linked users.** **Settings → Users → Edit** lists a user's linked provider accounts (provider,
email address at linking, issuer and subject, last use). **Unlink** removes a link: that
provider account can no longer sign in as the user (it may link again on its next sign-in if
the email rules allow it). Removing a provider removes all its links; the users stay.

## Provider notes

### Microsoft Entra ID

1. In the Microsoft Entra admin center, open **App registrations → New registration**. Choose
   *Accounts in this organizational directory only* (single tenant), and add the redirect URI
   with the platform **Web**.
2. Under **Certificates & secrets**, create a client secret and copy its **Value**.
3. Under **Token configuration**, add the optional claim `email` to the ID token. Entra ID sends
   it only for users who have an email address.
4. In EasyPatch, the issuer is `https://login.microsoftonline.com/<Directory (tenant) ID>/v2.0`
   and the client ID is the **Application (client) ID**. Multi-tenant issuers (`common`,
   `organizations`) are not supported.
5. Entra ID does not send `email_verified`, so first-time linking by email address needs **Trust
   the provider's email claim**. Tick it only for a single-tenant application: anyone who can
   set a user's email address in your tenant could then link that user's EasyPatch account on
   its first single sign-on. Once linked, the account is matched by issuer and subject.
6. To skip EasyPatch's MFA, require MFA for the application with a Conditional Access policy,
   then tick **The provider enforces MFA**.

### Google (Google Workspace or Cloud Identity)

1. In the Google Cloud console, configure the OAuth consent screen (*Internal* limits sign-in to
   your organization's accounts), then create an **OAuth client ID** of type *Web application*
   with the redirect URI.
2. In EasyPatch, the issuer is `https://accounts.google.com`, with the client ID and secret.
3. Google sends `email_verified`; leave **Trust the provider's email claim** off.

### Keycloak

1. In the realm, create an OpenID Connect client with **Client authentication** on and
   **Standard flow** on, and add the redirect URI to **Valid redirect URIs**. Optionally set
   **Proof Key for Code Exchange Code Challenge Method** to `S256` under *Advanced*.
2. Copy the secret from the **Credentials** tab.
3. In EasyPatch, the issuer is `https://<keycloak-host>/realms/<realm>`.
4. Keycloak sends `email_verified` from the user's *Email verified* flag.

## Not supported

* Requiring single sign-on (turning password sign-in off). Password sign-in always stays
  available.
* Signing out at the provider (RP-initiated, front- or back-channel logout): signing out of
  EasyPatch ends only the EasyPatch session.
* Roles or organization access from provider groups or claims.
* Client authentication with `private_key_jwt`, encrypted ID tokens, and multi-tenant Entra ID
  issuers.
