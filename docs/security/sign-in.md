# Signing in

Source of truth: `server/internal/auth/` (`service.go` for passwords,
sessions, authenticator apps and recovery codes; `webauthn.go` for security
keys and passkeys). Design: ADR-0006 and ADR-0032. Signing in through an
identity provider (OpenID Connect) is in [single-sign-on.md](single-sign-on.md).

## Second factors

A second factor is required for every account unless the deployment turns
it off (`EASYRMM_REQUIRE_MFA=false`, not recommended). At their first
sign-in, people set up one of these:

* **Security key or passkey.** A hardware key such as a YubiKey, or a passkey
  kept by the device (Windows Hello, Touch ID, Android) or by a password
  manager. Only offered when EasyRMM has a DNS name (see below).
* **Authenticator app.** Six-digit codes (TOTP) from an app such as Microsoft
  Authenticator, Google Authenticator or 1Password.

The other kind can be added later from **Account**, after entering the
password again. Someone with both can use either at the second-factor step.
An authenticator app counts only once its first code has been confirmed:
set-up that was started and abandoned adds nothing that signs in.

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

**The offer after sign-in.** People without a key who sign in with a
password and a code are offered a passkey before they continue to the page
they wanted. It is the same form as on the Account page, named after their
device ("Passkey on Windows") and asking for the password again.

* **Not now** offers it again at a sign-in 30 days later.
* **Don't ask again** stops the offer for good; Account still adds keys.
* It is not shown where keys cannot work: an IP-only deployment, a browser
  without WebAuthn, or an address other than the public one.

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
  as long after each further failure, up to 30 minutes. Sign-in attempts are
  also limited per client address.
* **Second-factor step.** Five wrong codes or refused keys end that sign-in;
  the person starts again with their password. Attempts are limited per
  person. Wrong authenticator or recovery codes also count across sign-ins:
  ten in a row lock the account on the same schedule as wrong passwords, so
  someone who knows the password cannot keep guessing codes by signing in
  again. A correct second factor, a password reset or an administrator's
  **Unlock** starts the count over.
* **Passkey sign-in.** Refused passkeys are audited and limited per client
  address. They do not lock the account: no password was tried, and a lock
  would let anyone lock a known person out. For the same reason a passkey
  still signs in while the account is locked.
* **Confirming a change.** Changing the password, adding or removing a
  second factor and replacing recovery codes ask for the password again.
  Five wrong passwords end the session that tried them, and attempts are
  limited per person.

Limits per client address count an IPv6 client's whole /64 network as one
address, since a single host usually has one to itself.

The lockout is a trade-off: anyone who knows a person's email address can
keep their password sign-in locked by sending a wrong password now and then.
Passkeys keep working, every failure is audited with its source address, and
an administrator can **Unlock** the account. If this happens, block the
source at your firewall or reverse proxy.

## Sessions

A sign-in session ends after two hours without use, or twelve hours at most
(`EASYRMM_SESSION_IDLE_TIMEOUT`, `EASYRMM_SESSION_MAX_AGE`). It gets a new
token when the second factor is verified and when the password is changed,
so a token copied earlier stops working. Changing the password also signs out
the person's other sessions.

Each session records how it signed in, as OpenID Connect `amr` values:
`pwd` (password), `fed` (single sign-on), `otp` (authenticator app), `hwk`
(security key), `rc` (recovery code), and `mfa` for a passkey or a single
sign-on provider trusted to have asked for a second factor. Signing in to
EasyPatch through EasyRMM requires a second factor among them
([ADR-0036](../architecture/adr/0036-easyrmm-signs-in-to-easypatch.md)).
Sessions started before EasyRMM recorded this have none, so their person
signs in once more before EasyPatch accepts them.

## Password reset

**Forgot password** answers the same way whether or not the address has an
account, and answers before looking it up; the e-mail goes out afterwards,
so the time taken reveals nothing either. Each account gets at most three
reset e-mails at once and then one every 20 minutes, however many addresses
ask. A reset link works once, for 30 minutes (`EASYRMM_PASSWORD_RESET_TTL`),
and only the newest link works. Someone invited who has not chosen a
password yet is sent a new invitation link instead, valid for 72 hours.

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
| `auth.mfa_verify` | The second-factor step, with `method: webauthn` for a key (successes and failures, with the reason; `inARow` and `lockedUntil` when wrong codes lock the account; `denied` while it is locked) |
| `auth.mfa_enroll` | An authenticator app is set up, or a wrong password was entered to start set-up |
| `auth.password_change` | A password change (successes, and wrong current passwords with `signedOut` when the session ended) |
| `auth.recovery_codes_regenerate` | New recovery codes (successes and wrong passwords) |
| `auth.password_reset_request` | A reset e-mail for an account (`invitation` when a new invitation was sent; `denied` past the per-account limit) |
| `auth.webauthn_add` | A security key or passkey is added (its name, whether it is synced), or a registration is refused (with the reason, or a wrong password) |
| `auth.webauthn_remove` | A security key or passkey is removed by its owner (or a wrong password) |
| `user.mfa_reset` | An administrator resets someone's second factor (with how many keys were removed) |
