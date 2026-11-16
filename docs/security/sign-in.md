# Signing in

Source of truth: `server/internal/auth/` (`service.go` for passwords,
sessions, authenticator apps and recovery codes; `webauthn.go` for security
keys and passkeys). Design: ADR-0006 and ADR-0032.

## Second factors

A second factor is required for every account unless the deployment turns
it off (`EASYRMM_REQUIRE_MFA=false`, not recommended). At their first
sign-in, people set up one of these:

* **Security key or passkey.** A hardware key such as a YubiKey, or a passkey
  kept by the device (Windows Hello, Touch ID, Android) or by a password
  manager. Only offered when EasyRMM has a DNS name (see below).
* **Authenticator app.** Six-digit codes (TOTP) from an app such as Microsoft
  Authenticator, Google Authenticator or 1Password.

The other kind can be added later from **Account**. Someone with both can
use either at the second-factor step.

The first second factor, of either kind, comes with ten **recovery codes**.
Each signs in once in place of the second factor. **Account → New recovery
codes** replaces them all.

## Security keys and passkeys

Keys are bound by the browser to EasyRMM's name, so a look-alike site
cannot use them. That makes them the strongest choice against phishing.

* **As the second factor.** After the password, the browser asks for one of
  the person's keys. Touching the key is enough.
* **Sign in with a passkey.** On the sign-in page, without a password. The
  browser offers the passkeys it holds for EasyRMM, and must verify the
  person with a PIN or biometric: the passkey and that check are the two
  factors. A key that cannot verify its user (many older USB keys) still
  works as a second factor after the password.

Under **Account → Security keys and passkeys** people see their keys, with
when each was added and last used. "Synced" marks a passkey that a platform
or password manager copies between the person's devices. Adding a key asks
for the password again, so a stolen session alone cannot add a key that
would outlive it. Removing one asks for the password too.

Limits:

* At most ten keys per person; names are up to 64 characters and unique
  per person.
* While second factors are required, the last one cannot be removed: add an
  authenticator app or another key first.
* A key whose signature counter does not increase (a sign of a copied key)
  is refused, and the attempt is audited.

### They need a DNS name

Browsers allow security keys and passkeys only on a domain name, never on
an IP address. On an IP-only deployment (`EASYRMM_PUBLIC_URL=https://<ip>`)
they are not offered, and **Account** says why. With a name, they work only
at `EASYRMM_PUBLIC_URL`. A console opened at one of the server's IP
addresses links to that name.

Each key is registered to the name. **Changing the host of
`EASYRMM_PUBLIC_URL` makes every registered key stop working.** Before such
a change, make sure everyone has an authenticator app or their recovery
codes. Afterwards, they sign in with those and register their keys again,
or an administrator resets their second factor.

## Failed attempts

* **Password.** Five failures in a row lock the account for a minute, twice
  as long after each further failure, up to 30 minutes. Sign-in attempts are also limited
  per client address.
* **Second-factor step.** Five wrong codes or refused keys end that sign-in;
  the person starts again with their password. Attempts are limited per
  person.
* **Passkey sign-in.** Refused passkeys are audited and limited per client
  address. They do not lock the account: no password was tried, and a lock
  would let anyone lock a known person out.

## When someone loses their second factor

With a recovery code, they sign in and set up a new factor under
**Account**. Without one, an administrator who manages them opens their
user page and chooses **Reset second factor**. That removes their
authenticator app, security keys, passkeys and recovery codes, and signs
them out everywhere. They set up a new second factor at their next sign-in.
Confirm who is asking before you reset.

## Audit

| Action | Recorded when |
|---|---|
| `auth.login` | A sign-in, with `method: passkey` for passkey sign-in (successes and failures) |
| `auth.mfa_verify` | The second-factor step, with `method: webauthn` for a key (successes and failures, with the reason) |
| `auth.mfa_enroll` | An authenticator app is set up |
| `auth.webauthn_add` | A security key or passkey is added (its name, whether it is synced), or a registration is refused (with the reason) |
| `auth.webauthn_remove` | A security key or passkey is removed by its owner |
| `user.mfa_reset` | An administrator resets someone's second factor (with how many keys were removed) |
