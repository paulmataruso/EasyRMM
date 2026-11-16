# ADR-0032: Security keys and passkeys (WebAuthn)

* Status: Accepted (2026-11-16).
* Refines: ADR-0006 (sessions and mandatory MFA).

## Context
ADR-0006 makes a second factor mandatory and offers one kind: TOTP codes from
an authenticator app. Codes can be phished. An attacker's page that relays a
password and a code in real time signs in as the technician. An RMM is a
prime target for that, since one technician account reaches every managed
machine. WebAuthn credentials are bound to the site's name by the browser, so
a look-alike site gets nothing it can use. Passkeys (discoverable WebAuthn
credentials that verify the user with a PIN or biometric) can also replace the
password altogether.

WebAuthn has two constraints that shape this design:

* Browsers allow it only on a domain name (and `localhost`), never on an IP
  address. EasyRMM can be deployed over IP only (ADR-0016).
* A credential belongs to one relying party ID, a domain. Changing EasyRMM's
  public name makes every registered key useless.

## Decision
* **Library.** [go-webauthn/webauthn](https://github.com/go-webauthn/webauthn)
  (BSD-3-Clause) does the protocol work: options, client data, authenticator
  data, COSE keys and signature checks. EasyRMM keeps the policy decisions:
  who may register, when a key counts, counters, storage and audit.
  Attestation is not requested (`none`), so any FIDO2 key or platform
  passkey works; EasyRMM does not restrict authenticator models.
* **Relying party.** The ID is the host of `EASYRMM_PUBLIC_URL`, and the
  only accepted origin is that URL's origin. When the host is an IP address,
  security keys and passkeys are unavailable. The console then says why, and
  that a name is needed. A console opened at another address (one of
  `EASYRMM_IP_ADDRESSES`) offers them only at the public URL.
* **Two uses of one credential.**
  1. *Second factor.* After the password, a user with a registered key can
     answer the MFA step with it instead of a code. The browser is offered
     only that user's keys, and user verification is not required; the
     password was the first factor.
  2. *Passkey sign-in.* **Sign in with a passkey** on the sign-in page asks
     for any discoverable credential for EasyRMM, with user verification
     **required**. A valid answer from an active user opens a fully
     signed-in session. A passkey verified by PIN or biometric is two
     factors in one, and phishing-resistant, so ADR-0006's mandatory MFA
     is met. The user handle is the user's id (a random UUID, no personal
     data).
* **Registering.**
  * From **Account**, with the current password entered again. A stolen
    session alone cannot plant a passkey that would outlive it.
  * At the mandatory set-up after a first sign-in, instead of an
    authenticator app. The password was just entered there. The first
    factor, either kind, issues the ten recovery codes, as before.
  * Each key gets a name (1–64 characters). At most 10 keys per user.
  * The browser is asked for a discoverable credential where possible
    (`residentKey: preferred`) and to verify the user if it can. A key that
    is not discoverable, or did not verify the user, still works as a
    second factor; it just cannot sign in without the password.
* **Ceremonies.** Each begin step stores the library's session data in
  `webauthn_challenges` for five minutes. It is bound to the sign-in
  session for registration and the MFA step, and to nothing for passkey
  sign-in. The finish step finds it by its challenge, deletes it (single
  use) and checks it was meant for this kind of ceremony and session.
  Passkey sign-in is rate-limited per client address like password sign-in.
* **Counters and flags.** A key whose signature counter does not move
  forward (when it uses one) is refused and audited as a possible clone.
  Synced passkeys report zero and are unaffected. The library refuses a
  credential whose backup-eligible flag changes. Each use records the time
  and the backup state.
* **Removing.** Users remove their own keys from Account, with the password
  entered again. EasyRMM refuses to remove the last second factor (no
  authenticator app, last key) while MFA is required. An administrator's
  **Reset second factor** (ADR-0006, user management) removes the keys as
  well as the authenticator app and recovery codes.
* **Failures.** A failed key at the MFA step counts towards the session's
  MFA failures, like a wrong code. Passkey sign-in failures are audited and
  rate-limited. They do not lock the account: no password was tried, and a
  lockout would let anyone lock a known user out.
* **Audit.** `auth.webauthn_add` and `auth.webauthn_remove` (with the key's
  name), `auth.mfa_verify` with method `webauthn`, and `auth.login` with
  method `passkey`, each with its outcome.

## Consequences
* Phishing-resistant sign-in for every deployment that has a DNS name.
  IP-only deployments keep TOTP and cannot use keys, which the console
  explains.
* Changing `EASYRMM_PUBLIC_URL`'s host invalidates every key. Users then sign
  in with an authenticator code or a recovery code, or an administrator
  resets their second factor. The deployment guide says so.
* New tables: `user_webauthn_credentials` and `webauthn_challenges`. Like the
  other authentication tables, they are reached only through the
  authentication service, at platform scope.
* New Go dependencies through go-webauthn: fxamacker/cbor, x448/float16,
  golang-jwt, google/go-tpm, go-viper/mapstructure, tinylib/msgp,
  philhofer/fwd and go-webauthn/x. Their licences are MIT, BSD and
  Apache-2.0, all on CI's allow-list.
  The attestation formats that use JWT and TPM code are never requested.
* No attestation, so EasyRMM cannot restrict sign-in to particular
  authenticator models. If that is needed later, it means requesting direct
  attestation and checking it against the FIDO metadata service.
