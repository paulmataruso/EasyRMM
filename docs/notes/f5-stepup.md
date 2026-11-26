# F5 step-up authentication (`ws/f5-stepup`)

Step-up only; approvals are not in this branch.

## Changelog lines

* Added step-up authentication: actions that need it ask for a second
  factor confirmed within the last 5 minutes (an authenticator app's code,
  a security key or passkey, or, for an account that signs in through a
  provider trusted to enforce MFA, a fresh sign-in there). A recovery code
  or a password is never enough. The console asks in a dialog and sends the
  request again by itself.
* Account page: **Confirm it is you** confirms ahead of time.

## Implementation-status rows

| Item | State |
|---|---|
| Step-up: `sessions.stepped_up_at`, TOTP, WebAuthn, `Sessions.RequireStepUp`, console dialog | Built, verified against PostgreSQL and the test Dex; the security-key path with a software authenticator only, no physical key |
| Step-up through a provider (`prompt=login`, `max_age=0`, `auth_time`, linked identity) | Built, verified against the test Dex; Dex asks for a sign-in on every request, so `prompt=login` is asserted on the request, not on the provider's behaviour |
| Actions using it | None built yet: ADR-0055 5b2 (names, DNS credentials), ADR-0057 (job-key rotation), ADR-0064 (one-off commands), ADR-0073 slice 4, ADR-0078 T3. Each attaches with `sessions.RequireStepUp(handler)` |

## How later features attach

* Server: wrap the handler after `RequireActive` and the permission check:
  `sessions.RequireStepUp(handler)`, or call `sessions.StepUp(r)` inside a
  handler that needs it for some requests only. It answers 401
  `step_up_required`.
* Console: nothing; `api` (`web/src/api/client.ts`) opens the dialog and
  sends the request once more.
* A service that must know in its own code: `auth.Service.CheckStepUp(sess)`.

## Privacy

Audit rows `auth.step_up` (success, failure, denied) hold the method, the key's
name, the provider and the failure reason; no code or token.

## Integrator

* Migration `00051_step_up.sql` (renumber). It also widens
  `webauthn_challenges.kind` with `stepup`.
* Two pre-existing breakages on `integration/2026-11`, fixed here in
  `web/e2e/` so the type check passes: the Repair test in `console.spec.ts`
  lost its closing `});`, and `e2e/agent.ts` had two `heartbeat` methods (the
  second, `{ facts, defender, installedFiles }`, is kept; the Repair test's
  call now passes `{ facts }`).
* Where one-off commands (ADR-0064) or the keystore are built, add the
  attachment and an integration test that the route answers
  `step_up_required` without a step-up.
