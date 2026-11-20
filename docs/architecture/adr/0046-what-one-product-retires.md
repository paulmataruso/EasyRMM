# ADR-0046: What one product retires

* Status: Accepted (2026-11-19). Carried out in phase R, in steps (R1 to R5
  below), each one a commit that passes the whole of CI.
* Plan: the one-product plan (in the repository's history), phase R.
* Supersedes: [ADR-0030](0030-easypatch-connector.md) (the API-token
  connector), [ADR-0035](0035-cohosting-easypatch.md) (EasyPatch on the same
  server) and [ADR-0036](0036-easyrmm-signs-in-to-easypatch.md) (EasyRMM signs
  in to EasyPatch). Amends [ADR-0031](0031-easypatch-agent-install.md) and
  [ADR-0039](0039-agents-on-easyrmms-name.md), which no longer have a
  connected server to describe.

## Context
Since phase S, every EasyRMM deployment runs EasyPatch's server as its
patching engine, on loopback, called with a signed statement per request
(ADR-0038); a standalone EasyPatch moves in by import (ADR-0045). EasyPatch
is part of EasyRMM from here on and is not released on its own.

That leaves code nothing can reach, which still has to be built, tested,
scanned and understood:

* EasyRMM's way to a separate EasyPatch server: the API-token connector,
  its settings page and links chosen by hand, co-hosting by SNI passthrough
  with the PROXY protocol, the product switch and its links into
  EasyPatch's console, and EasyRMM as EasyPatch's OpenID provider.
* EasyPatch's standalone product: its web console, its Caddy proxy image,
  its own Compose files, installer, backup and restore scripts, its
  standalone release, and its own accounts: sign-in, sessions, CSRF,
  passwords, second factors, passkeys, single sign-on and API tokens.

Most of the tests that exercise code the bundled engine *does* run were
written against these retired paths: EasyRMM's connector tests sign in with
an API token, the contract test drives most client calls with tokens, and
almost every EasyPatch integration test signs in with a cookie session.

## Decision
**Retire what nothing can reach, and move each test that covers living code
onto the path that stays before deleting the path it used.**

1. **R1, EasyRMM's links to a separate EasyPatch.** The product switch,
   `/go/to-easypatch` and the console's **Open EasyPatch** links go;
   `/go/from-easypatch` stays, because the engine's alert messages link
   to it. EasyRMM as EasyPatch's sign-in provider goes (the `idp` packages,
   their routes and settings page, the `sign-in` CI job), and a migration
   drops its tables. Co-hosting goes (the SNI router, the `proxyproto`
   package, `deploy/easypatch/`, the guide); `EASYRMM_EASYPATCH_HOSTNAME`
   set stops the server with "no longer a setting", as `EASYRMM_PATCHING`
   does, so an old `.env` is never silently ignored.
2. **R2, the API-token connector.** EasyRMM's integration tests and the
   contract test move from token clients to engine clients with
   statements; then the token paths, `PUT`/`DELETE
   /api/v1/settings/easypatch`, links chosen by hand and the connected
   server's branches go, and a migration drops `easypatch_connection`.
   **Settings → EasyPatch** keeps the engine's status, the organizations'
   automatic installs and **Devices not linked**.
3. **R3, EasyPatch's standalone product.** Its console (`easypatch/frontend`,
   its CI job, Dependabot entry and licence check), the proxy image and
   Caddy files, the standalone Compose files, installation guide and
   `backup.sh`, `restore.sh` and `init-secrets.sh` go. The logo and wordmarks
   the agent icons and documents use move out of the console first. The
   import keeps working: it reads the backups that releases up to 1.10.0
   make, whose format the import guide states.
4. **R4, EasyPatch's own accounts.** EasyPatch's integration tests move from
   cookie sessions to statements, including those that hold its own role
   and organization checks (the engine's second check, plan section 6).
   Then its sign-in, session, CSRF, password, second-factor, passkey,
   single sign-on, user and API-token endpoints, services and packages go,
   with the CLI commands that made or reset accounts. The engine accepts
   EasyRMM's statements and its agents' signed requests, nothing else.
   **The tables and entities stay**: an imported server's history names its
   users, and `prepare-import` disables them; no migration drops them.
5. **R5, one release.** `easypatch-release.yml` folds into `release.yml`:
   the engine's tests, agent builds signed with EasyPatch's release key,
   per-architecture images with their packages checked, and the manifest,
   for each EasyRMM release only. The engine's image gets the same
   vulnerability scan, SBOM and provenance as EasyRMM's. The standalone
   release (`easypatch-v*` tags, its GitHub Release and notes) and the proxy
   image go.

ADRs 0030, 0035 and 0036 stay in the index, marked superseded by this one.

## Consequences
* One product to build, test, scan and document; fewer places a request can
  enter the engine.
* Releases of EasyPatch up to 1.10.0 stay where they were published, in
  EasyPatch's former repository, which says it moved. Nothing newer is
  released on its own.
* MSP automation against EasyPatch's API (its API tokens) ends, as the plan
  says (section 3): it waits for EasyRMM's own API tokens (roadmap).
* Each step must hold the coverage floors with the tests it moved; a floor
  for a package that goes (`proxyproto`) goes with it.
