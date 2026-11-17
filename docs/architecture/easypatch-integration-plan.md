# EasyRMM and EasyPatch: integration plan

* Status: **Draft 2**, 2026-11-17. Draft 1 was critiqued against the code by an
  independent review and by its author. Section 13 lists every finding and
  what changed.
* Progress: P0 and P1 are built (see section 10); P2 is next.
* Scope: EasyRMM owns EasyPatch. Both live in this repository; EasyPatch is
  under `easypatch/`.

## 1. What the owner asked for

1. **EasyRMM owns EasyPatch.** One repository, two products.
2. **Simple patching in EasyRMM** through EasyPatch's API. For everything
   else, EasyRMM sends people to EasyPatch's own console.
3. **An elegant way to switch** between the two consoles.

## 2. Non-goals

* **One merged console, or EasyPatch shown inside EasyRMM.** EasyPatch refuses
  framing (`frame-ancestors 'none'`, `X-Frame-Options: DENY`), and should.
* **One agent.** Each managed computer keeps both agents. EasyRMM's agent
  installs EasyPatch's and reports on it (ADR-0031).
* **A shared database, or EasyRMM keeping copies of patch data.**
* **EasyPatch depending on EasyRMM.** EasyPatch stays a complete product on
  its own.
* **Per-organization roles in EasyPatch.** It keeps one role per person
  (section 6.4 explains the consequence).

## 3. Where things stand

**Repository**
* **History.** EasyPatch's whole history is merged under `easypatch/`
  (819ae8f), with its hashes unchanged.
* **Local files.** EasyPatch's machine-local files are copied in and ignored
  by git and by EasyRMM's Docker builds (246decb).
* **CI.** EasyPatch's workflows still sit in `easypatch/.github/`, where
  GitHub does not run them.
* **Release tags.** Both release workflows trigger on `v1.2.3` tags.
* **Security workflow.** EasyRMM's `security.yml` now also sees `easypatch/`:
  * gitleaks scans its whole history; a local scan of the 83 commits found
    nothing;
  * Trivy covers its files;
  * dependency review covers its manifests;
  * CodeQL analyses Go only.

**The connector** (ADR-0030, ADR-0031)
* EasyRMM calls EasyPatch with an API token and reads patch data live.
* It offers these actions:
  * scan;
  * install every eligible update, or chosen ones;
  * install later, when EasyPatch lists `scheduled-installs`;
  * cancel a job;
  * install the EasyPatch agent, on request or automatically per linked
    organization.
* Its tests run against `eptest`, a recording of EasyPatch 1.9.0's answers.
* The EasyPatch changes the connector was written for now sit in
  `easypatch/`, waiting for a release (section 10, P1):
  * `capabilities` in `server-info`;
  * `scheduledAt`;
  * `X-EasyPatch-On-Behalf-Of`;
  * exclusions by token.

**The two consoles**
* **Design system.** It is the same one, by copy. Both use React 19,
  Tailwind 4.3, react-router and lucide-react, with identical tokens and near
  identical primitives. They share no code.
* **Hosts and cookies.** Each has its own host name and its own SameSite=Strict
  session cookie: EasyRMM's in `server/internal/httpapi/session.go`, and
  `__Host-easypatch-session`.
* **CORS.** EasyPatch allows none.
* **Links between them.** The only one is EasyRMM's new-tab "Open EasyPatch"
  button, which goes to EasyPatch's home page.
* **Device ids.** EasyRMM's console learns a device's EasyPatch endpoint id
  only inside the device's Patches tab.

**Sign-in**
* **Both are OIDC clients:** EasyRMM (ADR-0034) and EasyPatch 1.10.0.
* **How EasyPatch finds an account:**
  1. by issuer and subject;
  2. then by a verified email, linked to *any* existing account, SuperAdmin
     included;
  3. optionally by creating one, with a default role and no organization
     restriction.
* **Discovery.** EasyPatch's server fetches each provider's discovery
  document, keys and tokens itself, over HTTPS only.
* **Its anonymous provider list** returns only an id and a name.
* **EasyRMM:**
  * records no email verification;
  * can run without a required second factor (`EASYRMM_REQUIRE_MFA=false`);
  * does not record on a session how the person signed in.
* **CSRF.** EasyRMM's CSRF check wraps every route except those that
  authenticate themselves, such as the agent API.

## 4. Principles

1. **EasyPatch stays complete on its own.** Everything it gains here is
   optional and off until a super administrator turns it on.
2. **EasyPatch is the source of truth for patching.** EasyRMM reads live.
3. **Two couplings, both named:**
   * EasyRMM calls EasyPatch's API with a token.
   * EasyPatch's server calls EasyRMM's sign-in endpoints (discovery, keys,
     tokens) when someone signs in through EasyRMM.

   Neither reads the other's database. Section 6.6 covers what each coupling
   needs: network reachability, trusted certificates, and what happens when
   the other side is down.
4. **The dividing line:**
   * **EasyRMM does one-off actions** on devices someone picked:
     * scan, install, restart, cancel and retry;
     * the **wiring between the two products**: linking organizations,
       installing the EasyPatch agent, and installing it automatically on
       new devices of a linked organization.
   * **Standing patch rules live only in EasyPatch:** policies, windows,
     automatic installs, exclusions, holds, tags and rings. So do its own
     administration and its less routine remedies: rollback, agent
     uninstall, user messages and restart prompts.
5. **Switching keeps the person's place.** Once single sign-on is on, it
   never asks them to sign in again.
6. **EasyRMM never vouches for something it has not checked.** It does not
   send `email_verified: true`, and it does not claim a second factor
   the session did not use.
7. **Every action carries the person's name** into EasyPatch's audit log.
8. **The contract is tested against the real EasyPatch**, built from the same
   commit, whenever either side of it changes.

## 5. The dividing line in detail

| Capability | EasyRMM | EasyPatch | Link from EasyRMM |
|---|---|---|---|
| Patch status per device and across the fleet | Yes (exists) | Yes | Device → endpoint page |
| Scan now (one or many) | Yes (exists) | Yes | |
| Install all eligible or chosen updates, now | Yes (exists) | Yes | |
| Install later (up to 31 days) | Yes (exists; needs EasyPatch 1.11.0) | No; its console schedules through windows | |
| Restart a device whose restart is pending | **New (P2)**: a fixed safe preset | Yes, with every option | |
| Retry a failed job | **New (P2)** | Yes | |
| Cancel a job | Yes (exists) | Yes | Job → `/jobs/{id}` |
| Link organizations; install the EasyPatch agent, by hand or automatically | Yes (exists, wiring) | Deployment codes and enrollment | |
| Update detail (CVE, KEV, affected endpoints, vendor links) | Title and severity | Yes | Update row → `/updates/{guid}` |
| Policies, windows, automatic installs, deferrals, Windows Update override, restart schedules | Read-only "effective window" card | Yes | Card → endpoint policy tab, or the organization's |
| Exclusions, holds, rollout guard | No | Yes | Update row → update page |
| Tags, pilot groups, rollout delays | No | Yes | |
| Rollback, uninstall the EasyPatch agent, user messages, winget apps | No | Yes | Device → endpoint page |
| Enrollment approvals, deployment codes, agent updates | No | Yes | |
| EasyPatch alerts, notifications, monthly PDF reports, audit log | No | Yes | Patching → EasyPatch reports |
| Users, single sign-on, API tokens, server settings | No | Yes | Settings → EasyPatch → console |

**The restart preset (P2).**
* The condition is always "only if a restart is pending". The mode is
  EasyPatch's default countdown, now or at a chosen time.
* There are no message or prompt options; those stay in EasyPatch.
* Servers, which EasyPatch marks with `isServer`, are listed by name and need
  an explicit confirmation, singly or in bulk.

**Contextual links.** Every view that shows something edited only in
EasyPatch links to the page where it is edited, labelled with the action:
"Change in EasyPatch", "Exclude in EasyPatch".

## 6. Switching between the consoles

### 6.1 The product switch

* **Where it goes.** A two-segment control sits directly under the logo at the
  top of each console's sidebar: **EasyRMM | EasyPatch**. On phones it sits
  at the top of the navigation drawer.
* **What it is.** A `<nav aria-label="Products">` with two links. The current
  product carries `aria-current="page"` and is styled as selected. The other
  is an ordinary link, so Ctrl-click and middle click open a new tab.
* **Why this and not a menu.** It is one click, always visible, and it says
  where you are, with no popover to open.
* **The other product's tooltip and accessible name** say where it goes:
  "Open DC-01 in EasyPatch", or "Open EasyPatch".
* **It opens in the same tab.** Back returns. The contextual links follow the
  same rule, and the two existing new-tab buttons become same-tab links.
* **When EasyRMM shows it.** EasyPatch is connected, and the person has
  EasyPatch access by `easyPatchAccess` (6.4). Someone with only site-scoped
  grants does not see it.
* **When EasyPatch shows it.** The person's account belongs to the EasyRMM
  provider (6.3). Local-only accounts never see a switch that would end at a
  sign-in page they cannot pass.
* **When EasyPatch is down.** EasyRMM keeps the connection's last check
  result. When EasyPatch is not answering, the segment shows a small warning
  dot and its tooltip says so. The link still works, in case EasyPatch has
  recovered.
* **Look.** It uses the shared tokens. The products are told apart by name
  and logo, not by a new accent colour.

### 6.2 Keeping the person's place

**EasyRMM to EasyPatch: an outbound redirect.**
* The switch and every contextual link point at EasyRMM's own server, for
  example:
  * `/go/to-easypatch?device=<id>&tab=updates`
  * `?organization=<id>`
  * `?job=<easypatch job id>`
  * `?update=<guid>`
* The server:
  * checks `patch.view` on that object;
  * looks the object up in its own link tables (`easypatch_devices`,
    `easypatch_organizations`);
  * redirects (302) to the matching EasyPatch page, with `from=easyrmm`
    added.
* When the object is not linked, or the person may not see it, the redirect
  goes to EasyPatch's matching list instead. For example, an unlinked device
  lands on `/endpoints?search=<host name>`.
* So the console needs no EasyPatch ids, and the switch works from any tab of
  a device page.

| EasyRMM page | EasyPatch page |
|---|---|
| `/devices/:id` (Patches view: available, installed, history, jobs) | `/endpoints/{endpointId}?tab=updates`, `installed`, `history` or `jobs`; `overview` otherwise |
| `/organizations/:id`, `/sites/:id` | `/organizations/{easypatchOrgId}` |
| `/patching?tab=jobs&job=X` | `/jobs/X` |
| `/patching`, everything else | `/endpoints`, or `/` |

**EasyPatch to EasyRMM: a resolver in EasyRMM.**
* EasyPatch's switch builds links into EasyRMM's `/go/from-easypatch/…`:
  `endpoints/:id`, `organizations/:id` and `jobs/:id`.
* EasyPatch needs only EasyRMM's address, which is its provider's issuer.
* EasyRMM resolves the id against its link tables, checks permissions, and
  opens:
  * the device's Patches tab;
  * the organization;
  * or the Patching job dialog.
* When nothing matches, it opens Patching, with a notice that says why.

The mappings are pure functions with unit tests on both sides.

### 6.3 Sign in once: EasyRMM is EasyPatch's sign-in provider

**Options**

| Option | For | Against |
|---|---|---|
| a. Both trust the MSP's identity provider | Works today | Needs one. There is still a sign-in step on each side, and nothing ties the two accounts together. |
| **b. EasyRMM is an OIDC provider for EasyPatch** | EasyPatch's OIDC client already exists. It is a standard protocol with one identity, EasyRMM's. | EasyRMM gains a small authorization server. |
| c. A custom signed hand-off | Fewest redirects | A new protocol to secure on both sides |

**Decision: (b).** Section 6.4 adds what EasyPatch needs so this cannot take
over accounts or over-grant.

**EasyRMM's provider** (`server/internal/idp`)

*Routes*
* Discovery is at `/.well-known/openid-configuration`, with the issuer set to
  `EASYRMM_PUBLIC_URL`. The keys are at `/oauth2/jwks`; authorization is
  `/oauth2/authorize` and tokens are `/oauth2/token`.
* They are mounted **outside** the session and CSRF chain, like the agent API.
* `authorize` reads the session itself.
* `token` authenticates its client itself and is rate-limited.

*The client*
* There is exactly one, EasyPatch. A super administrator creates it under
  **Settings → EasyPatch → Single sign-on**.
* The secret is shown once and stored as a hash.
* The redirect URI is exactly `<EasyPatch public URL>/api/v1/auth/sso/callback`.
* Rotating the secret is a manual action.

*The flow*
* Code flow only. PKCE S256, `state`, `nonce` and the `openid` scope are all
  required.
* A code is 256-bit, single use, valid for 60 s and stored hashed. It is
  bound to the client, redirect URI, user, session, nonce and challenge.

*Who may sign in*
* The person needs a complete session whose methods include a second factor.
  Sessions record their methods from P4 on (`amr`). Without a second factor,
  `authorize` refuses even when `EASYRMM_REQUIRE_MFA=false`.
* `easyPatchAccess(principal)` must grant something.

*Refusals*
* Errors go back to EasyPatch's callback as `error=access_denied` with
  `state`, as OAuth requires. EasyPatch then shows its own sign-in error
  page.
* So there is no refusal page on EasyRMM for Back to bounce off.

*No session yet*
* EasyRMM's cookie is SameSite=Strict, and arrives only on same-site
  navigations. EasyPatch on another domain is supported (the co-hosting
  guide allows it).
* So `authorize`, finding no session, redirects to EasyRMM's
  `/login?returnTo=/oauth2/authorize?…&bounced=1`.
* The console checks the session with its own same-origin request, which the
  cookie accompanies. Signed in, or once signed in, it leaves for any
  `returnTo` under `/oauth2/` with a **full page load**
  (`window.location.replace`). React-router navigation would show the
  console's 404.
* That load is same-origin, so the cookie goes with it.
* `bounced=1` allows one bounce. A second arrival without a session returns
  `error=login_required`.

*The ID token*
* Signed with ES256, using a key sealed under the server key. It lives for
  5 minutes.
* Claims:
  * `iss`, `aud`, `sub` (the EasyRMM user id), `exp`, `iat`, `auth_time` and
    `nonce`;
  * `name` and `email`, with **`email_verified: false`**;
  * `amr`;
  * `easypatch` (6.4).

*Audit*
* `idp.authorize`, on success and on each refusal with its reason.
* `idp.client_create` and `idp.client_rotate`.

### 6.4 Accounts and access

**One function decides EasyPatch access in EasyRMM.**
`easyPatchAccess(principal)` returns a role and a list of EasyPatch
organizations, or nothing. The switch, `authorize` and the claim all use it.

* An EasyRMM **super administrator** gets **SuperAdmin**, over all
  organizations.
* Otherwise **only organization-wide grants on linked organizations count.** A
  grant on one site never opens the whole EasyPatch organization. A global
  grant counts for every linked organization.
* A new permission, **`patch.configure`**, marks who may change EasyPatch's
  standing rules. The built-in roles from organization administrator up have
  it; technicians do not.
* The **role** is:
  * **Admin** over the organizations where the person has
    `patch.configure`, when there is at least one;
  * otherwise **ReadOnly** over the organizations where they have
    `patch.view`.

  EasyPatch gives one role per person. So the organizations someone may only
  view are left out when they may configure others. They still see those in
  EasyRMM. Gaining access somewhere never demotes anyone.
* **No grant means no access.** There is no switch and no sign-in.

**EasyPatch: a provider of the kind "EasyRMM".** The super administrator ticks
**"This provider is EasyRMM"**. That sets the following.

*Its accounts*
* They are **managed by EasyRMM**:
  * created at first sign-in, matched only by issuer and subject;
  * never linked by email;
  * excluded from automatic creation for other providers.
* Their role and organization access come from the `easypatch` claim. They are
  applied at every sign-in, before the session is created, and written only
  when they change.
* Unknown organization ids are ignored. If none remain, sign-in is refused.
* SuperAdmin is accepted only from this kind of provider.
* An existing local account is linked only by its owner, signed in to
  EasyPatch: **My account → Link EasyRMM**, which runs the same OIDC flow.
  After linking, the account's role becomes managed by EasyRMM, and the page
  says so first.

*Second factor*
* The second factor counts only when `amr` contains `mfa`. Otherwise
  EasyPatch asks for its own.
* The "provider enforces MFA" box does not apply to this kind of provider.

*Sessions*
* Sessions created through it last at most **1 hour**. A role taken away in
  EasyRMM therefore lasts at most an hour in EasyPatch.
* Renewal is silent. The browser remembers, in `localStorage`, that it last
  signed in through EasyRMM. When the session ends, the console starts that
  sign-in again once (guarded in `sessionStorage`) instead of showing the
  sign-in page.
* Signing out clears the memory.

*The anonymous provider list* marks this provider, so the sign-in page lists
it first and the console can find it.

*`from=easyrmm`*
* An anonymous visitor arriving with it goes straight to this provider's
  start URL, with `location.replace`.
* `from` is removed from `returnTo` first.
* It works once per tab (a `sessionStorage` guard), so neither a failure nor
  Back can loop.

*Capabilities*
* EasyPatch lists **`easyrmm-sign-in`**. EasyRMM offers this setup only when
  it is there.

**EasyPatch also fixes a hole of its own (P1).**
* A non-SuperAdmin with an empty organization list is unrestricted. Deleting
  an organization cascades its access rows, so a person restricted to one
  organization can silently gain access to all of them.
* The fix: users get an explicit **all organizations** flag, as API tokens
  have, and an empty list means no organizations.
* The migration sets the flag for users who have an empty list today, which
  keeps their access as it is.

### 6.5 What carries over

The theme does not carry over; each console keeps its own setting.

### 6.6 Couplings at run time

**EasyPatch reaching EasyRMM** for discovery, keys and tokens:
* It needs a route to EasyRMM's public address.
* When the two are co-hosted (ADR-0035), that needs either hairpin NAT or a
  host entry in EasyPatch's api container that points EasyRMM's name at the
  host. The co-hosting guide gains this step.
* If EasyRMM uses a private CA, EasyPatch's api container must trust it.
* When EasyRMM is down, EasyPatch's local sign-in still works for local
  accounts. EasyRMM-managed accounts cannot sign in until it is back.

**EasyRMM reaching EasyPatch.** Unchanged: the connector, with its existing
error states.

## 7. One repository

**Layout and licences**
* The root holds EasyRMM; `easypatch/` holds EasyPatch.
* `LICENSING.md` states the two licences: AGPL-3.0 for the root, and
  FSL-1.1-ALv2 for `easypatch/`, licensor DHI Technical Services LLC.

**CI: one entry point and one required check**
* `ci.yml` calls EasyPatch's server, agent and console workflows as reusable
  jobs, beside EasyRMM's.
* A `changes` job uses plain git to decide which product a change touches. A
  change to the connector (`server/internal/easypatch/**`) counts for both
  products.
* The aggregate **"CI result"** accepts `success` or `skipped`, so EasyPatch's
  checks are covered by the one required check.
* `merge_group` and `workflow_dispatch` run everything.
* `security.yml` is not filtered. CodeQL gains `csharp` and
  `javascript-typescript`.
* Every `uses:` path, cache and Docker context is prefixed with
  `easypatch/`, because `working-directory` applies only to `run` steps.

**Releases**
* EasyRMM's tags are `easyrmm-v*`, and EasyPatch's are `easypatch-v*`.
* The scripts strip the prefix. `git describe` uses `--match easyrmm-v*`.
* EasyPatch's signing runs in an environment named **`easypatch-release`**,
  open only to `easypatch-v*` tags, so no EasyRMM job can reach
  `EASYPATCH_RELEASE_KEY`.
* The GHCR packages `easypatch-server` and `easypatch-proxy` must give this
  repository's Actions write access.
* Each release sets `make_latest` deliberately: EasyRMM's are latest,
  EasyPatch's are not.

**Existing EasyPatch installs** are clones of the old repository. They
upgrade with `git fetch --tags && git checkout vX`.
* So the old repository **stays as a read-only mirror**. A job in the
  EasyPatch release workflow updates it with
  `git subtree split --prefix=easypatch` and the plain `vX` tag.
* It is archived only when EasyPatch's installation guide no longer depends on
  it.

**Development**
* The live EasyPatch instance still runs from the old folder.
* Running `docker compose` in `easypatch/` would take it over, because both
  folders give the Compose project name `easypatch`.
* `docs/development/monorepo.md` covers this, `git subtree pull` for stray
  commits, and how to run each product's tests.

## 8. The contract between the two

**A contract job** (built in P1: `make test-contract`, CI job "EasyPatch
contract")
* It runs when EasyPatch's server or its build, EasyRMM's connector,
  `go.mod` or the contract script changes.
* It builds EasyPatch's server image from the same commit, and runs it with
  PostgreSQL on the host network, over TLS.
* It creates an operator and a read-only API token with EasyPatch's CLI
  (`create-api-token`). No user account is needed.
* It runs a dedicated contract test (`contract_test.go`, build tag
  `contract`), not the connector's integration tests: those drive `eptest`
  directly and cannot point at a real server. The test enrolls a simulated
  Debian agent that signs its requests as EasyPatch's agents do, then drives
  every call of the connector, including an install canceled while the
  agent works on it.

**`eptest` stays** for fast unit tests. The contract test asks `eptest` and
the real server the same questions and fails when `eptest` sends a field
EasyPatch does not, or with another JSON type. Its first run found one: sites
carried an `isArchived` field that EasyPatch never sent.

**Versions**
* EasyRMM supports the EasyPatch release from the same commit and the previous
  minor release.
* Capabilities gate the newer features:
  * `scheduled-installs`;
  * `on-behalf-of`;
  * `easyrmm-sign-in`.
* Settings → EasyPatch warns when EasyPatch is older than supported.

**Upgrade order:** EasyPatch first, then EasyRMM. Each release's notes say
so.

## 9. Security review of the design

* **Trust direction.** EasyPatch trusts EasyRMM for identity and access, which
  is the point of "EasyRMM owns EasyPatch". A compromised EasyRMM already
  controls EasyPatch: it holds an Admin token, and runs commands on every
  device. The signing key is sealed like EasyRMM's other secrets.
* **Account takeover through email.** It is closed:
  * the provider never sends `email_verified: true`;
  * EasyRMM-managed accounts are matched by subject only;
  * existing accounts are linked only by their signed-in owner.
* **Second factor.** EasyRMM asserts `mfa` only for sessions that used one.
  EasyPatch requires `mfa` in `amr` for this provider.
* **Over-granting.**
  * Site-scoped grants give nothing in EasyPatch.
  * Technicians get ReadOnly.
  * Admin needs `patch.configure`.
  * EasyPatch's organization list no longer fails open.
* **Stale access.** EasyRMM-managed sessions last an hour at most. A disabled
  EasyRMM user cannot renew.
* **Open redirects.** EasyRMM's outbound redirect builds its targets from
  configuration and link tables. EasyPatch's `returnTo` stays path-only.
  EasyRMM's `returnTo` stays same-origin; only its `/oauth2/` prefix gets a
  full page load.
* **Loops.**
  * `from=easyrmm` is removed from `returnTo` and works once per tab.
  * `authorize` allows one bounce.
  * Refusals return to EasyPatch's own error page.
* **Login CSRF and code interception.**
  * EasyPatch's `state` cookie covers login CSRF.
  * PKCE, an exact redirect URI and a confidential client cover code
    interception.
* **CSRF exemption.** Only the provider's routes are outside EasyRMM's CSRF
  layer. Each authenticates on its own: `authorize` with the session's
  SameSite=Strict cookie, `token` with the client secret.

## 10. Phases

Each phase lands in its own commits, with its tests and documentation, and
with `IMPLEMENTATION_STATUS.md` updated.

**P0 Repository** (done; nothing has run on GitHub yet)
* `LICENSING.md`.
* CI through `ci.yml`, with one required result.
* CodeQL for C# and JavaScript.
* Prefixed release tags and the `easypatch-release` environment.
* The mirror job for the old repository.
* `docs/development/monorepo.md`.

*Done when:* a pull request here runs EasyPatch's checks, they feed "CI
result", and EasyRMM's checks are skipped for EasyPatch-only changes.

**P1 Contract and EasyPatch hardening**
* Done: the integration changes and `create-api-token`; EasyPatch's explicit
  "all organizations" flag for users; the contract job.
* Next: the 1.11.0 changelog, when EasyPatch is released.

*Done when:*
* EasyPatch's server tests pass, with a test that deleting an organization
  never widens anyone's access;
* the connector suite passes against EasyPatch built from the same commit.

**P2 Finish simple patching**
* The restart preset and retry in EasyRMM.
* Contextual links through `/go/to-easypatch`.

*Done when:*
* integration tests cover each action against the real EasyPatch;
* unit tests cover each link mapping;
* permissions and audit match the existing actions.

**P3 Switching from EasyRMM**
* The product switch in EasyRMM's console, with the warning when EasyPatch is
  not answering.
* `easyPatchAccess` and `patch.configure`, which also decide who sees the
  switch.

*Done when:* the mappings and permission checks are unit-tested, and the
switch keeps the device in a browser.

**P4 Sign in once, with access from EasyRMM**
* EasyRMM:
  * its provider;
  * sign-in methods recorded on sessions;
  * the full page load for `/oauth2/`;
  * the inbound resolver `/go/from-easypatch`.
* EasyPatch:
  * the EasyRMM provider kind, with managed accounts, the claim, `amr`, one-hour
    sessions with silent renewal, and Link EasyRMM;
  * `from=easyrmm`;
  * its product switch;
  * the `easyrmm-sign-in` capability.
* The co-hosting guide's step for EasyPatch reaching EasyRMM.

*Done when:*
* Go tests drive the provider with a standard OIDC client;
* EasyPatch's tests cover managed accounts and the refusal of email linking;
* an end-to-end test over TLS, with the two consoles on **different
  registrable domains**, switches from EasyRMM to EasyPatch with no sign-in
  page, and back.

**P5 Later**
* Back-channel logout.
* One-click pairing: the token and the sign-in client in one consent step.
* A shared design-token stylesheet.
* One installer for both on one server.
* Per-organization roles in EasyPatch.

## 11. Risks

* **The provider is security code.** It stays minimal: one client, one flow,
  no consent screen, no refresh tokens, no userinfo, and no dynamic
  registration. It is tested with a standard client and end to end.
* **The release secret and the GHCR permissions** are owner actions. Until
  they are done, EasyPatch releases from here fail at signing or at publishing
  images.
* **Two places to edit EasyPatch.** Commits made in the old folder must come
  over with `git subtree pull`, or they are lost.
* **CI cost.** EasyPatch's Windows and macOS jobs run only when `easypatch/`
  changes.

## 12. Decisions for the owner

1. **Licences.**
   * Do both stay as they are?
   * Does the licensor grant EasyRMM the EasyPatch-derived stylesheet and logo
     (ADR-0013)?
   * Should EasyRMM's CONTRIBUTING gain a relicensing grant like EasyPatch's?
     Code is copied between the two consoles (for example the product
     switch), and today EasyRMM contributions are granted only under the
     AGPL.
2. **The release environment.** Create `easypatch-release` here, with the
   `EASYPATCH_RELEASE_KEY` secret and an `easypatch-v*` tag rule.
3. **GHCR.** Give this repository's Actions write access to the
   `easypatch-server` and `easypatch-proxy` packages.
4. **The old EasyPatch repository** stays as a read-only mirror.
5. **EasyRMM super administrators become EasyPatch SuperAdmins** (6.4). This
   is the proposed default.

## 13. Critique and revisions

Draft 1 was reviewed against the code by an independent reviewer and by its
author. Every finding was checked in the code before it was accepted.

| # | Finding | Evidence | Change |
|---|---|---|---|
| 1 | **Account takeover.** EasyRMM records no email verification, and an organization administrator can invite any address and receive the invite link when it cannot be emailed. EasyPatch links a verified email to any account, SuperAdmin included. | `server/internal/users/users.go` (invite link returned when not emailed); EasyPatch `OidcService.cs` (email linking) | `email_verified: false` always. EasyRMM-managed accounts are matched by subject only. Existing accounts are linked by their signed-in owner (6.4). |
| 2 | **Cross-domain sign-in fails.** EasyRMM's cookie is SameSite=Strict, so a cross-site redirect to `authorize` arrives without it. EasyRMM's console would also show its 404 for a `returnTo` under `/oauth2/`. | `session.go` (SameSite Strict); `web/src/App.tsx` Gate | Bounce once through `/login`, then a full page load for `/oauth2/`. The end-to-end test uses two registrable domains (6.3). |
| 3 | **Over-grant.** Technicians hold `patch.manage`, which would map to EasyPatch Admin, the right to change standing rules. Under draft 1, gaining ReadOnly somewhere could demote an Admin everywhere. Site-only users would see a switch that ends in a refusal. | `rbac.go` | `patch.configure`. Admin covers only the organizations with it; the others are left out. One `easyPatchAccess` function serves the switch, `authorize` and the claim (6.4). |
| 4 | **EasyPatch fails open.** An empty organization list means all organizations, and deleting an organization empties lists. Applying access at every sign-in would also revoke the person's other sessions, and would fail on an unknown id. | EasyPatch `Authorization.cs`, `EasyPatchDbContext.cs`, `AuthService.cs` | An explicit "all organizations" flag (P1). Changes are applied before the session is created and only when different. Unknown ids are ignored. |
| 5 | **Sign-in shipped before roles is unsafe**, and the MFA trust had no basis: EasyRMM can run without a second factor and records no `amr`. | `config.go` (`EASYRMM_REQUIRE_MFA`); EasyRMM's session struct | Sign-in and roles merged into P4. `amr` is recorded and required, and the "enforces MFA" box does not apply to this provider. |
| 6 | **Role changes waited up to 12 hours.** | EasyPatch session lifetime | One-hour sessions, renewed silently (6.4). |
| 7 | **The token endpoint would fail EasyRMM's CSRF check**, and "EasyPatch never calls EasyRMM" was false. | `app.go` (CSRF wraps the mux); EasyPatch `OidcService.cs` (server-side fetches) | The provider's routes are mounted outside the CSRF chain. Principle 3 names both couplings, and 6.6 covers reachability, certificates and failure. |
| 8 | **`from=easyrmm` could loop**, Back from a refusal could restart sign-in, and matching the provider by issuer was fragile. | EasyPatch `App.tsx` Gate; `SsoEndpoints.cs` (anonymous list) | `from` is stripped and works once per tab, refusals return as `access_denied`, and an explicit provider kind replaces the separate EasyRMM address setting (6.3, 6.4). |
| 9 | **The switch could not find its counterparts.** EasyRMM's console knows the endpoint id only inside the Patches tab, and EasyPatch would show the switch to local-only accounts. | `DevicePatches.tsx` | A server-side outbound redirect works from any page, and EasyPatch shows the switch only to EasyRMM-managed accounts (6.1, 6.2). |
| 10 | **Draft 1 was out of date about P1.** The integration changes and `create-api-token` were already in `easypatch/` while it was reviewed. | `easypatch/CHANGELOG.md` | Section 3 and P1 updated. |
| 11 | **CI.** "CI result" requires `success`, so path-skipped jobs would fail it; workflow-level filters make EasyPatch's checks impossible to require; the contract job must run for either side; CodeQL covers Go only; `working-directory` does not reach `uses:` steps. | `ci.yml`, `security.yml` | One entry point and one required result that accepts `skipped`, a contract filter on both sides, and CodeQL for C# and JavaScript (7). |
| 12 | **Releases.** Both workflows parse `v…`, `git describe` would pick up either product's tags, the `release` environment would expose the key to any `v*` job, GHCR needs the new repository's write access, and there is one "latest release". | Both `release.yml` files, `Makefile` | Prefixed tags with prefix stripping, `--match`, an `easypatch-release` environment, a GHCR owner step, and `make_latest` (7). |
| 13 | **Existing EasyPatch installs upgrade by tags from the old repository**, so archiving it would strand them. | `easypatch/docs/installation.md` | The old repository stays as a mirror, updated by `git subtree split` on each release (7). |
| 14 | **The dividing line contradicted itself.** Automatic agent install is a standing rule in EasyRMM, and EasyPatch's restart carries user messaging. | `links.go` (AutoInstall); EasyPatch `AdminDtos.cs` (restart request, `isServer`) | The rule now includes the wiring between the products. The restart is a fixed preset, with explicit confirmation for servers (4, 5). |
| 15 | **Over-built:** carrying the theme over, a menu for two choices, a rotation schedule. **Missing:** non-goals, accessibility, EasyPatch being down, upgrade order, the licensing of copied code. | Review | The theme carry-over is cut; a two-segment nav with `aria-current` replaces the menu; rotation is manual; sections 2, 6.1, 8 and 12 added. |
| 16 | **(Author)** An unlinked device can still land somewhere useful. | EasyPatch endpoint list keeps `search` in the URL | `/endpoints?search=<host name>` (6.2). |
| 17 | **(Author)** "Install later" exists in EasyRMM but not in EasyPatch's own console. | Section 5 | Recorded as a deliberate asymmetry. |
