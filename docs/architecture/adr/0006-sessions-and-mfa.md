# ADR-0006: Opaque cookie sessions with mandatory MFA

* Status: Accepted (2026-11-15)
* Refined by: ADR-0032 (security keys and passkeys as second factors, and
  passkey sign-in)

## Decision
* Sessions are opaque 256-bit random tokens in a `__Host-easyrmm_session`
  cookie (`Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`). The database
  stores only the SHA-256 of the token. JWTs are not used: sessions must be
  revocable immediately.
* Idle timeout 2 h and absolute lifetime 12 h by default. Half-finished
  sign-ins (awaiting MFA) expire after 10 minutes.
* MFA is mandatory by default. Users without a second factor are forced into
  TOTP enrolment before anything else. TOTP codes cannot be replayed (last
  accepted step is stored). Ten single-use recovery codes are issued.
  WebAuthn/passkeys are planned as an additional factor.
* The token is rotated whenever a session's privilege changes (MFA verified,
  enrolment finished).
* CSRF: `SameSite=Strict`, an `Origin`/`Sec-Fetch-Site` check on every unsafe
  request, and a per-session synchronizer token (HMAC of the session id) sent
  in `X-CSRF-Token`.
* Brute force: per-address token bucket, per-account progressive lockout,
  identical responses and timing for unknown accounts.
* Passwords: Argon2id (64 MiB, t=3, p=2), parameters stored per hash and
  upgraded on login; NIST SP 800-63B rules (length ≥ 12, block list, no
  composition rules).
* Password reset: single-use 30-minute tokens delivered in a URL fragment;
  resets revoke all sessions and never bypass MFA.
