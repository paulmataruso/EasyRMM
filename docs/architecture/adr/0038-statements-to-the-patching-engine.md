# ADR-0038: EasyRMM's statements to its patching engine

* Status: Accepted (2026-11-18)
* Plan: the one-product plan (in the repository's history), phase B2.
* Refines: [ADR-0030](0030-easypatch-connector.md) (the connector) for the
  engine inside EasyRMM's deployment.

## Context
EasyPatch is becoming EasyRMM's patching engine, running beside EasyRMM on
the same server and reachable on loopback only. People use it only through
EasyRMM's console, and EasyRMM's own API calls the engine on their behalf.
EasyRMM decides who may do what. The engine needs to know who acts, with which role,
in which organizations, for its own checks and its audit trail.

What existed did not fit:
* **The connector's API token** is one identity for everyone: it can never be
  a super administrator, it is one rate-limit bucket, and the person it acts
  for is only a label.
* **A session per person**, created through ADR-0036's sign-in, would need
  user rows, a cookie jar per person inside EasyRMM, CSRF tokens and
  renewals, all to repeat a decision EasyRMM has already made.

## Decision
EasyRMM sends a **statement** with each request, in the
`X-EasyRMM-Assertion` header.

* **Format.** A JWT with header `{"alg":"HS256","typ":"easyrmm-gateway+jwt"}`,
  signed with a key of at least 32 bytes. `setup.sh` generates the key
  (`EASYRMM_PATCHING_KEY`), and both programs read it from the deployment
  (`EasyRmm__GatewayKey` for the engine). They run on one host, so a
  shared key gives an attacker on the host nothing they could not already
  read, and there is no public key to publish, fetch or rotate.
* **Claims.**
  * `iss` easyrmm and `aud` easypatch.
  * `sub`: the EasyRMM user's id, or `service` for EasyRMM's own work.
  * `name`: who the audit trail names, as `easyrmm:<name>`.
  * `role`: what this call needs, one of `ReadOnly`, `Admin` or
    `SuperAdmin`, by name only.
  * `orgs`: `"*"`, or the EasyPatch organization ids this call may touch. An
    empty list means none.
  * `htm` and `htu`: the method and the request target as sent, path and
    query. A statement is good only for that request.
  * `iat`, and `exp` 30 seconds later. The engine refuses any statement whose
    lifetime exceeds 60 seconds, allowing 5 seconds of clock difference.
* **The engine's `EasyRmm` scheme.**
  * **Selection.** The administrator API's scheme selector chooses it whenever
    the header is present, ahead of a session cookie or API token. A
    request with a statement is judged by it alone, so a bad statement is
    refused even beside a valid session.
  * **Signature first.** The signature is checked first, in constant time.
    Nothing in an unsigned statement is read.
  * **A stateless principal.** It is built from the claims: no user row, no
    session and no writes, so concurrent first calls cannot race.
  * **Roles and tenancy.** Role checks are EasyPatch's own. The tenant
    context limits the call to `orgs`, and the role never widens it: a
    super administrator's statement for one organization sees that one.
  * **No CSRF token.** The scheme is not a cookie, so session CSRF checks do
    not apply. EasyRMM's CSRF check protects the browser's leg.
  * **Rate limits** are per subject. The `service` subject has a separate,
    higher limit.
  * **Refusals.** A refused statement gets a 401 and a warning naming the
    reason, never the statement. EasyRMM never passes such a 401 to a
    browser (B3).
  * **No key, no statements.** An engine without the key refuses every
    statement. A key that is set but unusable stops it at start.
* **How EasyRMM fills them in (B3).** EasyRMM checks its own permissions
  first, then names only what the call needs:
  * a person's reads (the patching list, a device's updates, history and
    jobs) are `ReadOnly` in the EasyPatch organization of the device or
    list concerned;
  * a person's actions (scans, installs, cancels) are `Admin` in the
    organizations of the devices acted on;
  * EasyRMM's own work (link checks, organization lists, agent installs) is
    `service`, `Admin` in every organization, which is what the connector's
    API token allowed, named after whom it is for when anyone.
* **Interoperability.** One golden statement,
  `server/internal/easypatch/testdata/gateway-statement.json`, binds the two
  sides. EasyRMM's signer must produce exactly it, and the engine must accept
  exactly it.

## Consequences
* EasyRMM can act for each person with the role and organizations that one
  call needs, so a technician can scan their device without being able to
  edit a policy. The engine still enforces its own checks: the second of two
  independent checks.
* A statement copied from loopback traffic is useless for any other request
  and expires in seconds. Replays of the same request within its lifetime
  are possible for someone who can read loopback traffic, who could read the
  key as well.
* The engine's account features (sessions, MFA, users, API tokens) are not
  needed for this, and leave in the plan's phase R.

## Alternatives considered
* **ES256 with EasyRMM's identity-provider key (ADR-0036)** would have meant
  publishing that key on loopback, fetching and caching it in the engine,
  and reusing one key for two purposes. Its key set exists only once
  ADR-0036's client is set up. None of that buys anything on one host.
* **Mutual TLS on loopback** is a certificate authority and two
  certificates to identify one process to another on the same machine, and
  still carries no person or scope.
* **A list of used statement ids against replay** would need memory that a
  restart loses. Binding each statement to one request and 30 seconds is
  enough here.
