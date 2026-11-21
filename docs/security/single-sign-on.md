# Single sign-on (OpenID Connect)

Source of truth: `server/internal/sso/` (providers, the sign-in flow,
linking) and `server/internal/httpapi/ssoapi/` (routes). Design: ADR-0034.

Technicians can sign in with their account at your identity provider:
Microsoft Entra ID, Google Workspace, Okta, Keycloak, Authentik, or any
provider that speaks OpenID Connect. The sign-in page then shows **Sign in
with *name*** beside the password form. Passwords keep working.

## How it decides who you are

* **EasyRMM never creates accounts.** You invite people as usual (**Settings
  → Users → Invite**). They do not have to choose a password before their
  first single sign-on.
* **First sign-in links the account.** EasyRMM links the provider's account
  to the active EasyRMM account with the same email address, if:
  * the address is in one of the provider's **email domains**; and
  * the provider says the address is verified (`email_verified`), or the
    provider is marked **Its email addresses belong to my organization**.

  Otherwise the sign-in is refused and the sign-in page says why.
* **Later sign-ins use the link.** The provider's identifier for the
  person (`sub`) is what matches from then on, not the email address.
  Renaming someone at the provider or in EasyRMM does not break the link or
  move it to another account.
* **The second factor still applies.** By default, after the provider
  EasyRMM asks for its own second factor (or its set-up), as after a
  password. Tick **It requires multi-factor authentication** only for a
  provider that enforces MFA for everyone in its domains. EasyRMM cannot
  check this itself.

## Setting up a provider

You need the **Single sign-on** settings (super administrators). They show
the **redirect URI**, the same for every provider:

```
https://rmm.example.com/api/v1/auth/sso/callback
```

It is `EASYRMM_PUBLIC_URL` plus `/api/v1/auth/sso/callback`. Single sign-on
works at the public URL only. From an IP address, the sign-in buttons go
there. If you change `EASYRMM_PUBLIC_URL`, update the redirect URI at every
provider you added. The Authentik that `setup.sh --with-authentik` set up
is updated by `sudo docker compose up -d` after you edit `.env`; see
[Sign-in with Authentik](../deployment/docker.md#sign-in-with-authentik).

At the provider, register a **web application** (a confidential client
with a secret) that uses the authorization code flow and this redirect URI.
It needs the `openid`, `email` and `profile` scopes. EasyRMM always uses
PKCE (S256), `state` and `nonce`. Then in EasyRMM, **Settings → Single
sign-on → Add provider**:

| Field | What to enter |
|---|---|
| Name | What the button says: "Sign in with *Name*" |
| Issuer URL | The provider's issuer (below). EasyRMM reads `<issuer>/.well-known/openid-configuration` when you save, so a wrong URL is caught then |
| Client ID, client secret | From the registration. The secret is stored encrypted under the secret key and never shown again; leave it empty when editing to keep it |
| Email domains | Your technicians' domains, one per line, such as `example.com` |

### Microsoft Entra ID

1. **Entra admin center → App registrations → New registration.** Choose
   **Accounts in this organizational directory only**. Under **Redirect
   URI**, choose **Web** and enter the redirect URI.
2. **Certificates & secrets → New client secret.** Copy the value (not the
   ID).
3. **Issuer URL:** `https://login.microsoftonline.com/<Directory (tenant)
   ID>/v2.0`. Use your own tenant's ID, never `common` or `organizations`:
   those accept accounts from any tenant.
4. Entra ID does not send `email_verified`. Tick **Its email addresses
   belong to my organization**, which is safe with your own tenant's
   issuer. The `email` claim is the user's **Email** attribute. Make sure it
   is set and matches their EasyRMM address. If it is empty, add the
   `email` optional claim under **Token configuration**.
5. If Conditional Access requires MFA for this application, you may tick
   **It requires multi-factor authentication**.

### Google Workspace

1. **Google Cloud console → APIs & Services → Credentials → Create
   credentials → OAuth client ID**, type **Web application**. Add the
   redirect URI under **Authorized redirect URIs**. On the consent screen,
   choose **Internal**, so only your Workspace's accounts can sign in.
2. **Issuer URL:** `https://accounts.google.com`.
3. Google sends `email_verified`, so leave **Its email addresses belong to
   my organization** off. The email domains decide which accounts can link.

### Okta, Keycloak, Authentik and others

* **Okta:** an **OIDC Web Application** integration with the redirect URI as
  a sign-in redirect URI. Issuer: `https://<your org>.okta.com` (the org
  authorization server), or your custom authorization server's issuer.
* **Keycloak:** a client with **Client authentication** on and the redirect
  URI under **Valid redirect URIs**. Issuer: `https://<host>/realms/<realm>`.
* **Authentik:** an **OAuth2/OpenID Provider** (confidential) and an
  application. Issuer: `https://<host>/application/o/<application slug>/`.

Whether these send `email_verified: true` depends on how their users are
managed. If sign-ins are refused with "did not confirm your email address",
check that first. Turn on **Its email addresses belong to my organization**
only when the provider holds no self-registered accounts.

## Using it

* **Sign in with *name*** goes to the provider and back. Where a second
  factor is due, it comes next. Where the person was going (`returnTo`) is
  kept.
* **Account → Single sign-on** lists the linked accounts. **Unlink** removes
  a link. The next sign-in through that provider links again, under the
  same email rules.
* **Turning a provider off** (untick **Offer it on the sign-in page**) stops
  new sign-ins through it and keeps the links. **Removing** it also forgets
  the links. Sessions already open continue until they end.
* Someone who leaves is cut off from new sign-ins when you disable them at
  the provider. EasyRMM sessions they already have last until they time
  out (`EASYRMM_SESSION_IDLE_TIMEOUT`, `EASYRMM_SESSION_MAX_AGE`). Disable
  them in EasyRMM too: that ends their sessions at their next request.
* Actions that ask for the password again (adding a key, new recovery
  codes) still need one. Someone who only uses single sign-on sets a
  password with **Forgot your password?**, or an administrator sends them a
  link.

## When it is refused

The sign-in page explains the reason, and every refusal is in the audit log
(**Sign-in and security**, `auth.login` with method `oidc` and a `reason`):

| Reason | Meaning |
|---|---|
| `no_account` | No active EasyRMM account has that email address. Invite them, or check the address the provider sends |
| `domain` | The address's domain is not one of the provider's email domains |
| `unverified` | The provider did not say the address is verified |
| `linked_other` | The EasyRMM account is already linked to a different account at this provider. Unlink it under **Account** first |
| `account` | The EasyRMM account is disabled or locked |
| `expired` | The sign-in started in another browser, took over 10 minutes, or the page was reloaded with an old link |
| `provider` | The provider refused, or its answer did not check out: wrong client secret, a code used twice, an ID token with the wrong audience, issuer or nonce. The audit entry has the details |
| `unavailable` | The provider is off, removed, or its discovery document cannot be read |

## Security notes

* The flow is the authorization code flow with PKCE. Its `state`, `nonce`
  and PKCE verifier travel in an encrypted, HttpOnly cookie
  (`__Host-easyrmm_sso`, 10 minutes, SameSite=Lax), deleted at the callback.
  A callback from another browser, or replayed, is refused.
* ID tokens are checked with the provider's published keys: signature,
  issuer, audience (the client ID), expiry and nonce.
* EasyRMM reaches providers over HTTPS only, never at link-local or cloud
  metadata addresses, and does not follow redirects. Plain HTTP is accepted
  for a loopback issuer only, for tests.
* The client secret is sealed with AES-256-GCM under the secret key,
  bound to the provider's id. It never appears in responses or the audit
  log.

## Audit

| Action | When |
|---|---|
| `auth.login` (method `oidc`) | Every sign-in through a provider, successful or not, with the provider and, for failures, the reason |
| `auth.sso_link` / `auth.sso_unlink` | An account is linked at a first sign-in, or unlinked |
| `sso.provider_create` / `_update` / `_delete` | Providers changed (the secret only as "changed") |

## Testing

`make test-oidc` starts Dex (a real OpenID Connect provider) on
`127.0.0.1:25556` with users and a client generated for the run. The
integration tests sign in through Dex's own login form, as a browser
would. CI runs them on every pull request.
