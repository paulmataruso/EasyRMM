# EasyRMM and EasyPatch as one product

* Status: **Draft 2**, 2026-11-18. Draft 1 was reviewed against the code by
  an independent reviewer; section 12 lists what changed because of it.
* Follows: the [EasyPatch integration plan](easypatch-integration-plan.md),
  whose P0 to P4 are done: one repository, one CI, the connector, the product
  switch, and signing in to EasyPatch through EasyRMM.
* Owner: the decisions in section 1 are the owner's (2026-11-18). Everything
  else here is a proposal, carried out in the order of section 10.

## 1. Decisions

1. **One licence.** All of the repository is under the Functional Source
   License, Version 1.1, ALv2 Future License (FSL-1.1-ALv2). The licensor is
   DHI Technical Services LLC, for EasyRMM's code as for EasyPatch's.
2. **EasyPatch is only part of EasyRMM from now on.** It is not a separate
   product, is not installed on its own, and has no console of its own.
3. **EasyRMM's interface is the standard.** EasyPatch's pages are rebuilt
   with EasyRMM's components, layout, wording and theme. Where the two
   differ, EasyRMM's way wins.
4. **Authentik is an option, chosen at install.** When it is chosen, setting
   it up must be dead simple: the person creates their own account once and
   is in.

## 2. What "done" looks like

An MSP installs EasyRMM on one server:

1. They point DNS at the server and run the installer, which asks for the
   address and an email for certificates. With `--with-authentik` it also
   asks for the sign-in name and the administrator's email (phase A).
2. Without Authentik, they open EasyRMM, create their account on the
   first-run page, and set up a second factor. With Authentik, the installer
   prints one link instead; they open it and create their account there.
3. They land on EasyRMM's dashboard. Patching is part of the console: the
   same sidebar, the same look, no second sign-in, no second product to set
   up. A device's page shows its updates; an organization's page shows its
   patch policy.
4. They install EasyRMM's agent on a machine with one command. Remote access,
   monitoring and patching all work on it; nobody installs, enrolls or links
   a second agent by hand.

Nothing in that journey says "EasyPatch" except, at most, the about box and
the licence files.

## 3. Not doing

* **Rewriting EasyPatch's server in Go, or EasyRMM's in .NET.** About 46,000
  lines of C# (server and agent) carry Windows Update, apt and dnf handling,
  signed agent updates, rollout rings and reports, checked on real machines.
  Rewriting them buys the user nothing they can see. EasyPatch's server stays
  a .NET program, the way MeshCentral stays a Node.js program: an internal
  engine behind EasyRMM.
* **One agent binary.** EasyRMM's agent already installs and supervises
  EasyPatch's agent (ADR-0031). Merging the two programs is a later question.
* **Keeping EasyPatch usable on its own,** after the switch-over (phase S).
* **macOS.** EasyRMM's agent is built for Windows and Linux. EasyPatch's
  experimental macOS agent was installed with deployment codes, which go;
  macOS patching leaves with it until EasyRMM has a macOS agent.
* **EasyPatch's public API for MSP automation,** until EasyRMM has API tokens
  of its own (roadmap). EasyPatch's API becomes internal.
* **Merging the two alert, job and audit systems** in this plan. Patch
  alerts, jobs and the engine's audit trail get their own pages inside
  EasyRMM's console (phase C); folding them into EasyRMM's lists is later
  work. EasyRMM's own audit log already records who asked for each patch
  action.

## 4. Target architecture

```
                         ┌──────────────────────── one server, host networking ─────────────────────────┐
 browsers ─────────────► │ :443 EasyRMM edge ── rmm.example.com ──► EasyRMM server: console, /api/v1/*  │
 EasyRMM agents ───────► │   (TLS for every name)                     │  typed patching API, its checks  │
 EasyPatch agents ─────► │   /api/v1/agents/*, /downloads/agent|winget/* ─► 127.0.0.1:18180 EasyPatch   │
                         │                                            │  per-call signed assertion ──►   │
                         │                                            │  127.0.0.1:18180 (internal API)  │
                         │                                            └► MeshCentral 127.0.0.1:14430      │
                         │ :443 auth.example.com (only with Authentik) ──► 127.0.0.1:18280 Authentik    │
                         │                                                                               │
                         │ PostgreSQL 127.0.0.1:15432: databases easyrmm, easypatch (and authentik)      │
                         │ EasyPatch worker (health 127.0.0.1:18181)   Authentik worker (127.0.0.1:18281)│
                         └───────────────────────────────────────────────────────────────────────────────┘
```

* **One public name**, `rmm.example.com`, plus `mesh.rmm.example.com` as
  today. EasyPatch needs no name of its own. Its agent paths do not collide
  with EasyRMM's, which are under `/api/agent/`. EasyRMM's edge passes them
  through unchanged, because EasyPatch agents sign the exact request path.
* **EasyPatch listens on loopback only.** It is bound with `ASPNETCORE_URLS`;
  `ASPNETCORE_HTTP_PORTS` would bind every interface.
* **People never reach EasyPatch's API.** EasyRMM's own patching API calls it
  on their behalf, with EasyRMM's permissions (B2, C).
* **One PostgreSQL**, with an owner and an application role per program.

Loopback ports, one block per program:

| Program | Ports |
|---|---|
| EasyRMM | 18080 (offload mode), 18081 (health) |
| EasyPatch | 18180 (API), 18181 (worker health) |
| Authentik | 18280 (HTTP), 18243 (HTTPS, unused but on loopback), 18281 (worker), metrics off |
| MeshCentral | 14430 |
| PostgreSQL | 15432 |
| Co-hosted EasyPatch (ADR-0035, until phase R) | 19080, 19443 |

A compose test fails if two services share a port, or if anything but the
edge (80, 443) listens beyond loopback.

## 5. Phases

`main` stays releasable throughout. The bundle is built behind a setting and
becomes the default only at the switch-over (S), once the console has
everything EasyPatch's own console offered (C). Until then the shipped way
to patch is today's: an EasyPatch server connected to EasyRMM.

### L. Licence (done)

Commit `a91c1e5` and its follow-up, [ADR-0037](adr/0037-one-licence.md):

* the FSL in one root `LICENSE.md`;
* `LICENSING.md` with what the licence allows and its history (copies
  obtained under the AGPL between 2026-11-15 and 2026-11-18 keep it);
* the contributor grant to DHI Technical Services LLC for the whole
  repository;
* "source-available" wording;
* CI licence checks for Go, npm and NuGet packages;
* Dependabot held below PDFsharp's AGPL releases.

### B. The engine inside EasyRMM's deployment

Built behind `EASYRMM_PATCHING=bundled`. The default stays today's
connector.

**B1. Services.** `deploy/docker-compose.yml` gains these, from EasyPatch's
server image, on host networking:

* `easypatch-db-init`, a one-shot service that creates the `easypatch`
  database, an owner role and an application role if they are missing. It
  uses the PostgreSQL superuser and is idempotent, so it also works on an
  existing install, where PostgreSQL's init scripts never run again.
* `easypatch-migrate`, running as the owner role.
* `easypatch-api` and `easypatch-worker`, running as the application role,
  with:
  * `ASPNETCORE_URLS=http://127.0.0.1:18180` and `:18181`;
  * `Database__Host=127.0.0.1`, `Database__Port=15432`;
  * `Database__MaxPoolSize` set to 20 each;
  * health checks on those ports.

`setup.sh` generates the passwords and the gateway key (B2), and creates the
key, winget and package directories owned by the image's user (UID 1654).
Rerun on an existing install, it adds what an older `.env` lacks without
touching what it has. *Done (B1): `--patching bundled`, tested on a fresh
database and on a second start; the worker starts after the API, which
creates the data-protection key.* The worker needs outbound HTTPS to Microsoft's update and security
feeds, CISA KEV and the Debian security tracker; the installation guide
lists them.

**B2. The gateway assertion.** EasyRMM calls EasyPatch with a short signed
statement per request, in its own header, `X-EasyRMM-Assertion`
([ADR-0038](adr/0038-statements-to-the-patching-engine.md)). *Done (B2):
EasyRMM's signer, EasyPatch's `EasyRmm` scheme, and one golden statement
that both sides' tests check.*

The statement:

* **Format.** A JWT with `typ` `easyrmm-gateway+jwt`, signed HS256 with a
  32-byte key that `setup.sh` generates into `.env` (`EASYRMM_PATCHING_KEY`),
  like the deployment's other secrets, and both programs read.
  They run on one host, so a shared key gives an attacker on the host nothing
  they would not already have. It also avoids distributing or rotating public
  keys.
* **Claims:**
  * `iss` easyrmm and `aud` easypatch;
  * `sub`, the EasyRMM user or `service`, and `name`, for the audit trail;
  * `role` for this call: ReadOnly, Admin or SuperAdmin;
  * `orgs`, the EasyPatch organizations this call may touch, or `*`;
  * `htm` and `htu`, the method and the path with its query, so a statement
    is good only for the one request it was made for;
  * `iat`, and `exp` 30 seconds later, with 5 seconds of leeway (both
    programs share one clock).

**EasyPatch's side.** A new authentication scheme, `EasyRmm`, which the
`Console` selector chooses when the header is present:

* **A stateless principal** built from the claims: no user rows, no
  per-request writes, no races.
* **Explicit branches** in three places: the tenant context (limited to
  `orgs`), the session-state handler (EasyRMM has applied its own sign-in
  and second-factor rules), and the two handlers that read a user id
  (settings and tag policies).
* **Audit and rate limits.** The audit actor is "EasyRMM: name". The rate
  limiter partitions by `sub`, and the service identity has its own, higher
  limit.
* **No CSRF check.** Session CSRF does not apply, because the scheme is not a
  cookie.
* **Failures.** A missing, forged, expired or mismatched statement gets a
  401, which EasyRMM never passes on to a browser.

**The service identity** (`sub` service, SuperAdmin, all organizations)
replaces the API token for EasyRMM's own work: provisioning, link checks and
installs.

**B3. The connector in bundled mode.** The connector's client talks plain
HTTP to `127.0.0.1:18180` with statements. The deployment configures it, not
a settings page, so there is no token to paste and no pairing step. *Done
(B3): `EASYRMM_PATCHING=bundled`; each person's call carries their role and
the organizations it concerns (ADR-0038); tested against a real engine in the
contract suite. No download goes through the connector yet, so streaming
waits for the first one (C-phase reports).*

Responses are mapped for the console:

* EasyPatch's authentication errors become `502 patching_unavailable`, never
  a 401 or 403 that the console would read as a lost session.
* Validation errors become EasyRMM's field errors.
* Downloads (CSV, PDF) stream through.

**B4. Agents on EasyRMM's name.** The edge forwards exactly
`/api/v1/agents/`, `/downloads/agent/` and `/downloads/winget/` to
EasyPatch. It:

* dispatches them first, before the session, CSRF and console fallbacks;
* keeps the path unchanged;
* replaces `X-Forwarded-For` with the client's address (or, in offload mode,
  with the address EasyRMM resolved from its own proxy);
* removes `X-EasyRMM-Assertion`;
* caps request bodies at 20 MB.

`/downloads/install/*` (deployment-code scripts) is not forwarded. A test
proves that EasyRMM serves nothing under those prefixes, and that the header
never reaches EasyPatch from outside. *Done (B4,
[ADR-0039](adr/0039-agents-on-easyrmms-name.md)): also refuses paths that
could mean another one to the engine, and sandboxes every answer on
EasyRMM's origin; the contract suite enrolls and checks in a signing agent
through the forwarder against a real engine.*

**B5. One set of organizations: a reconciler.** A loop in EasyRMM, driven by
the link tables, makes EasyPatch match EasyRMM, and retries while EasyPatch
is unavailable.

* **Organizations:**
  * created with EasyRMM's name and time zone (time zones drive monthly
    reports), and renamed with EasyRMM;
  * archived when EasyRMM deletes one, with a suffix that frees the name,
    because EasyPatch's names stay unique even when archived;
  * names that differ only by case are made distinct, because EasyRMM's are
    unique ignoring case and EasyPatch's are not.
* **Sites:** created and renamed the same way, recorded in a new site link
  table.
* **Devices:**
  * automatic install is on by default for every organization (ADR-0031);
  * a device deleted in EasyRMM has its EasyPatch endpoint revoked and an
    uninstall job sent;
  * a device moved to another site or organization takes its endpoint with
    it;
  * a per-device opt-out stops automatic installs, and EasyRMM never
    reinstalls what an opt-out removed.
* A reconcile test covers each case, plus a restart in the middle of one.

*Done (B5, [ADR-0040](adr/0040-one-set-of-organizations.md)): organizations
gain a time zone; names that clash get the EasyRMM id's first 8 characters;
an unlinked engine organization with the exact name is adopted, which also
makes a create whose reply was lost safe. A device moved to another
organization has its agent uninstall itself and is enrolled again there. An
agent that will not uninstall within 7 days is revoked. Device removals and
opt-outs also work with a connected server. EasyRMM's console has no device
move or retire screen yet; the reconciler acts on the database.*

**B6. Agent packages without a manual step.** EasyPatch's server image
carries the agent packages of its own version, signed by the release
workflow, the way EasyRMM's server image carries EasyRMM's agents. CI images
carry packages signed with a test key that only test agents trust.

*Done (B6, [ADR-0041](adr/0041-agent-packages-in-the-engine-image.md)):
Windows and Linux packages only (macOS stays out while experimental); each
signature is checked against the committed public key before the build, and
the image is checked after it. CI makes its test key per run and checks that
the release key refuses those packages. An image built from source carries
none until B8 publishes the engine's image.*

**B7. Installs addressed by IP.**

* On Windows, the EasyPatch agent receives EasyRMM's internal CA.
* On Linux, the agent needs the CA in the system trust store. Linux patching
  on an IP-addressed install therefore needs a publicly trusted name, or the
  agent's pinned-CA option (to build if missing).
* The installation guide says so.

*Done (B7, [ADR-0042](adr/0042-agents-trust-easyrmms-authority.md)): the
Linux agent's pinned-CA option was missing and is built (`enroll
--server-ca`, trusted for that server only). With the bundled engine and
`EASYRMM_TLS_MODE=internal`, install instructions carry EasyRMM's own
authority, so Windows and Linux agents enroll without changes to the
device's store. Older Linux agents are enrolled without the option and
need the store.*

**B8. One release.**

* EasyRMM's release workflow builds EasyPatch's server image and agent
  packages from the same commit, and the compose file pins them by digest.
* CI builds the image for the bundle test.
* EasyPatch's components keep their own version line, continuing above
  1.10.0, because EasyPatch agents pick updates by version. Each release's
  manifest records the versions.

*Done when:* `make e2e-bundle` passes in CI. It brings up
`deploy/docker-compose.yml` itself, bundled, on host networking, and then:

1. creates the first account on the first-run page, and an organization;
2. enrolls an EasyRMM agent in a container, whose EasyPatch agent is
   installed, enrolls through EasyRMM's name and links;
3. scans, and installs an update from a local package repository with a
   synthetic package, so that it doesn't depend on what a public mirror
   offers that day;
4. checks that the gateway refuses missing, forged, expired, replayed
   (another path) and out-of-scope statements;
5. checks that nothing but the edge listens beyond loopback.

*Done (B8, [ADR-0043](adr/0043-one-release.md)): the release workflow
builds the engine from the same commit and pins it by digest, with a
manifest; `make e2e-bundle` does all five and passed in CI, with every
other check (run 44423961831, at b718db5). The release workflow itself has not run on GitHub: no tag
has been pushed.*

### C. One console

EasyPatch's pages are rebuilt in `web/` with EasyRMM's components. They call
EasyRMM's own patching API, which grows per area. For each call, EasyRMM:

1. resolves its own ids;
2. checks view, manage or configure on the device, site or organization;
3. calls EasyPatch with a statement naming the person, the role that call
   needs, and only the organizations it concerns.

How EasyRMM's permissions map onto EasyPatch's roles:

* A technician with `patch.manage` gets Admin for a scan or install on their
  device, and nothing that edits a policy.
* A policy edit needs `patch.configure` on the organization.
* Server-wide patch settings need a super administrator.

| EasyPatch's console today | In EasyRMM's console |
|---|---|
| Endpoint detail: updates, installed, history, jobs, policy, exclusions, install preview, holds, restart (pending, restart, notify), agent version and update | The device page's **Patches** tab, which grows these sections |
| Organization detail: policy, sites, deploy | The organization page gains a **Patch policy** tab; sites are EasyRMM's |
| Site and endpoint policy overrides | The site page and the device page, beside the organization's |
| Global policy, tags and tag policies (priority layering) | Settings → **Patching** → Policies and Tags |
| Dashboard, Updates, Update detail, update holds | **Patching**: overview, update catalogue, update detail |
| Endpoints without an EasyRMM device (from an imported standalone server) | Patching → overview lists them, with a prompt to install EasyRMM's agent |
| Jobs | Patching → Jobs (EasyRMM's Jobs list later; see section 3) |
| Reports: compliance, installations, trend, monthly PDFs, schedules and email | **Reports** gains the patch reports; schedules under Settings → Patching |
| Alerts, alert rules, notification channels, SMTP | Patching → Alerts; rules, channels and email under Settings → Patching |
| Vulnerability feeds, OS lifecycle, server settings, audit log | Settings → Patching |
| Approvals (of agents enrolled with deployment codes), enrollment tokens, deployment codes, Deploy page | **Gone**: EasyRMM's agent installs EasyPatch's. Packages visible under Settings → Patching |
| Users, API tokens, single sign-on, account, sign-in pages | **Gone**: EasyRMM's |

**Overlap with EasyRMM's software actions.** Policy "application updates" and
EasyRMM's software actions (winget, ADR-0028) both install application
updates. The policy page links to the software page and says which one
applies. Choosing a single mechanism is decided in C4, with both side by
side.

**Order:**

* C1: the device's Patches tab (about 1,750 lines today).
* C2: the Patching overview, catalogue and holds.
* C3: jobs and restarts.
* C4: policies at every level, and tags (the policy editor is about 1,600
  lines).
* C5: reports.
* C6: Settings → Patching.
* C7: alerts and notifications.

*Done (C1): the device's Patches tab does what EasyPatch's endpoint page
did. To install: choose updates, see the install preview (what would be
installed, its size, likely restarts, what is left out and why), exclude an
update on the device and include it again. Installed: remove a Windows
update, excluding it too by default. History and jobs as before. **Policy**:
every effective value with the layer that set it, including tag names, and
how the device applied the Windows Update settings. The summary gains the
active job, what a pending restart is for (updates, servicing packages,
file operations), who is signed in and whether the EasyPatch icon reaches
them, preset messages to them, and the agent's version with **Update
agent…**. Holds show on each update; placing them is C2. Restart prompts and
schedules beyond **Restart…** are C3, and editing a policy is C4. Exclusions,
removals, messages and agent updates need `patch.manage` and are Admin
statements for the device's organization; the preview and the message list
are ReadOnly. Links into EasyPatch's console show only where it has one
(a connected server); the bundled engine has none. Not ported: the OS
overview cards (the device page has its own) and the endpoint's activity
tab (EasyRMM's audit log has what its console did). The bundle test
excludes, includes, previews and installs through the tab.*

*Done (C2): Patching opens on an overview instead of EasyPatch's dashboard:
the share of devices up to date with a bar of the rest, a worklist of what
needs attention worst first (exploited vulnerabilities, failures, missing
required updates, restarts, stale or missing scans, agents out of date or
offline, devices not patched from EasyRMM, endpoints with no EasyRMM device,
running jobs), each linked to the list that shows it, organizations least up
to date first, and the endpoints with no EasyRMM device with how to link
them. **Updates** is EasyPatch's update catalogue, counted over whole
organizations or one site (site-level roles choose a site), and an update's
page is its update detail: what it fixes, with CISA's and Microsoft's
exploitation data, the devices reporting it by state, installing it on
chosen devices or wherever it is missing, removing a Windows update across
devices, and holds (placed and released with `patch.configure` in the
organization; everywhere only by super administrators). The engine is asked
as ReadOnly for what is read, Admin for installs, removals and organization
holds, SuperAdmin for holds everywhere. Not ported: the dashboard's
compliance trend (reports, C5) and open alerts (C7), and removing and
holding in one step (two steps now). The bundle test finds the update in the
list, opens its page, holds it and releases the hold.*

*Done (C3): **Jobs** filters as EasyPatch's job list did (type, status,
trigger, requested since), over the newest 200 jobs that match in the
organizations the caller sees, and says when older ones are left out. A job
shows its trigger, when it was sent and how often, when a queued job gives
up, the job a retry runs again, a cancellation asked for, a time-out and its
progress. **Restart…** takes EasyPatch's restart options: countdown (1 to 60
minutes), prompt with a deadline (15 minutes to 7 days) or without, or
immediate; only if pending or always; and how long an offline device gets
(15 minutes to 24 hours). With always, EasyRMM reads each endpoint
(at most 100) for its product type, so servers still need a tick, and for
the restart capability. It is offered on any patched device. Planning is a
ReadOnly statement, the restart an Admin statement for the devices'
organizations. Not ported: forcing a restart past another job (EasyRMM
never forces), and recurring restarts, which are part of the policy (C4).
The bundle test filters the install on the Jobs tab, opens it, and plans a
restart of the machine whether or not one is pending, without sending it.*

*Done (C4): one policy editor serves every layer: the default policy
(Settings → **Patching**), an organization and a site (a **Patch policy**
tab on their pages), a tag (Settings → Patching → Tags) and a device
(**Set values for this device** on its Policy view). Each value is inherited,
with the layer it comes from, or overridden; saving replaces the layer, and
**Inherit everything** (on the default, **Restore EasyPatch's defaults**)
clears it after the layer's name is typed. Tags are added, changed, deleted
and given to organizations, sites and devices in EasyRMM. Organization, site
and device policies are Admin statements for the organization and need
`patch.configure` there; the default policy, tags and tags' policies are
SuperAdmin statements for every organization and need a super
administrator. EasyPatch's API tokens are never SuperAdmin, so with a
connected server EasyRMM reads the default policy and assigns tags but
leaves changing them, and tags' policies, to EasyPatch's console, and says
so. **Winget, decided:** the policy's application updates are how EasyRMM
keeps applications up to date on a schedule (winget, in the maintenance
window); the Software tab and Jobs → Install software (ADR-0028) stay as
one-off actions that do not wait for the window. The editor says which is
which and links to Jobs. Not ported: giving or taking a tag from many
devices at once, as EasyPatch's endpoint list did; tags are given one
organization, site or device at a time. The bundle test sets a value on the
organization and sees it inherited by the site, adds a tag with a policy,
gives it to the device with a value of the device's own, and finds each in
the device's policy in effect with its layer.*

*Done (C5): **Reports** has EasyPatch's reports: **Patch compliance** is the
device list as a report, with each operating system's build and support
status and why a device is not patched, above the dashboard's compliance
trend (now ported) over 30 or 90 days or a year, added up over the
organizations the caller sees whole; **Patch installations** is EasyPatch's
installations report, at most 5,000 rows; **Monthly patch reports** makes an
organization's PDF for a past month or the month so far, downloads, emails
and deletes it. Each organization's schedule is under Settings → **Patching**
→ **Report schedules**. Both reports are EasyRMM report definitions, so they
filter, export CSV and are audited like the others. The trend, the list and
the PDF are ReadOnly statements; making, emailing and deleting are Admin
statements needing `patch.manage` over the organization, and schedules need
`patch.configure`. **Email, decided:** with the bundled engine, EasyRMM gives
it the `EASYRMM_SMTP_` mail server at each start (a SuperAdmin service
statement), so one mail server serves the deployment; with a connected
server, reports use the mail server in EasyPatch's console, and EasyRMM says
so when there is none. The rest of EasyPatch's notification settings (alert
email and webhooks) is C7. The contract test gives the real engine mail
settings as EasyRMM does and reads them back, and sees it refuse to email
without a mail server and over an unencrypted one. Not verified: a report
delivered through a real mail server, and a PDF of a real Windows fleet. The bundle test lists the
device's compliance and the update it installed, downloads the CSV, makes
the month's report, downloads its PDF, is told no mail server is set,
deletes the report and sets a schedule.*

EasyPatch's console is about 18,800 lines of TypeScript without tests. Each
area is ported with its tests and compared against the old page.

*Done when:* every task in the table can be done in EasyRMM's console. Each
area also needs component tests, a bundle-test path through its main flow,
and a passing impeccable detector.

### S. Switch-over

* **The bundle becomes the default.** `setup.sh` installs it, and the
  `EASYRMM_PATCHING` setting goes.
* **Importing a standalone EasyPatch** (1.4 to 1.10) into a new or existing
  EasyRMM:
  * the database is moved with `pg_dump` and restore;
  * the data-protection keys and agent packages are copied out of its Docker
    volumes;
  * its organizations become EasyRMM organizations, with case collisions
    named rather than merged;
  * endpoints link to EasyRMM devices as EasyRMM agents appear;
  * its accounts are not imported, because EasyRMM's accounts and roles
    apply;
  * its old host name stays served by EasyRMM's edge, with a certificate, so
    that agents already enrolled, which cannot be repointed, keep reporting;
  * an import test runs against a 1.10 database.
* **No co-hosted installs to migrate.** No EasyRMM release was ever
  published, so no co-hosted installs (ADR-0035) exist.

### A. Authentik, when chosen

`./setup.sh --with-authentik` asks two more things: the sign-in name (for
example `auth.example.com`) and the administrator's email.

**Authentik's services:**

* `authentik-server` and `authentik-worker` run the pinned image by digest.
* Every listener is on loopback: server 18280 and 18243, worker 18281, and
  metrics off. Both containers default to 9000, 9443 and 9300.
* Its data is the `authentik` database in the same PostgreSQL.
* Update checks, analytics and error reports are off. Trusted proxies are
  loopback only.
* It gets its own name, because its sub-path mode has open bugs in 2026.8.5.
  EasyRMM's edge terminates TLS for the name and forwards it.

**A blueprint applied at first start creates:**

* the OpenID provider and application for EasyRMM, with the client secret
  from `setup.sh`, EasyRMM's callback as redirect URI, and groups in the
  profile scope;
* a second factor (TOTP or WebAuthn), required in the authentication flow
  and enrolled if missing;
* self-registration off;
* user settings that don't let people change their own email address, so
  that an address in Authentik is the one the administrator set.

**The invitation.** The invitation is not in the blueprint: blueprints are
re-applied, so a single-use invitation deleted on use would come back.
Instead, `setup.sh` creates it once with Authentik's `ak` command:

* the administrator's email is fixed in it, and it expires after seven days;
* its enrollment flow asks for a name, a password and a second factor, then
  redirects to EasyRMM's sign-in;
* `setup.sh --new-invitation` issues another one.

**Authentik's own break-glass.** `akadmin` gets a random password from
`setup.sh`, kept in a 0600 file. It is Authentik's emergency account, not
the person's.

**EasyRMM's side** (an addition to ADR-0034, not a replacement):

* **A deployment-managed provider.** The deployment configures it, and the
  settings page shows it locked. It is marked as managing its addresses
  (true here, as above) and as enforcing MFA. Its allowed domain is the
  domain of the administrator's email.
* **The first super administrator.** `setup.sh` creates them with the
  administrator's email and no password. ADR-0034's existing rule links them
  to their Authentik account at first sign-in, so the first-run page is not
  needed.
* **No group mapping.** Authentik's groups never grant EasyRMM roles. Mapping
  them would make anyone who can edit a group in Authentik an RMM super
  administrator, with script execution everywhere. Roles are granted only in
  EasyRMM.
* **Later accounts.** People are invited in EasyRMM, as today. Sending them
  an Authentik invitation from EasyRMM's invite is a follow-up (A2).
* **The first organization** is created from the console's empty state.
* **Hairpin NAT.** EasyRMM's discovery, key and token calls to
  `auth.example.com` go over loopback, through EasyRMM's own edge, still
  verifying TLS for the public name. Many routers do not loop a server's own
  public address back to it.
* **EasyRMM's break-glass,** for when Authentik is down or broken: a command
  on the server, `easyrmm-server recover`, prints a one-time local sign-in
  link for a super administrator. Shell access to the server is the trust
  root anyway, and no standing password exists.

*Done when:* `make e2e-authentik` passes in CI:

1. a fresh install with the flag comes up;
2. a browser opens the printed link, creates the account with TOTP, and
   lands on EasyRMM's dashboard as super administrator;
3. it creates an organization, and patching works;
4. the invitation link no longer works;
5. a second Authentik user, without an EasyRMM account, is refused;
6. signing in again asks for the second factor;
7. `easyrmm-server recover` signs in with Authentik stopped.

### R. Retire what one product no longer needs

Once S has shipped, these go.

**EasyPatch's standalone pieces:**

* its console (`easypatch/frontend`), with its CI jobs, Dependabot entry and
  licence check;
* the proxy image and Caddy files, including the proxy image in
  `easypatch-release.yml`;
* the standalone compose file and installation guide.

**What the gateway replaces:**

* signing in to EasyPatch through EasyRMM (ADR-0036's browser flow) and
  EasyPatch's OIDC client side;
* the product switch and `/go/to-easypatch`;
* co-hosting by SNI passthrough (ADR-0035), the PROXY protocol code once
  nothing else uses it, and the `EASYRMM_EASYPATCH_*` settings;
* the API-token connector, its settings page and its contract tests;
* the `sign-in` CI job;
* the parts of the threat model and the sign-in docs that describe these.

**EasyPatch's own accounts:** its sessions, passwords, MFA, passkeys, SSO,
users and API-token endpoints. Nothing can reach them any more, so removing
them means less code and less to attack.

**Release workflows:** `easypatch-release.yml` folds into `release.yml`.

**Kept from P4:**

* the grant logic in `access.go`, which now drives B2's role and `orgs`;
* the id resolver behind `/go/from-easypatch`, because EasyPatch's alert
  emails link to endpoint ids and must land on the right EasyRMM page.

*Done when:* the repository builds one product, and a search finds no
route, page, CI job or document for the retired parts.

### D. A real test instance

With the owner:

* a server, and DNS names `rmm`, `mesh.rmm`, plus `auth` with Authentik;
* the installer run from a release candidate, with real Let's Encrypt
  certificates;
* real Windows and Linux machines enrolled with one command, and patched;
* the whole of section 2 walked through, both with and without Authentik.

## 6. Security of the gateway

* **Only EasyRMM can authenticate people's work.** EasyPatch's API is bound
  to loopback, and its only authenticators for people's work are EasyRMM's
  statements. The edge strips the statement header from everything it
  forwards.
* **A statement is narrow.** It lasts 30 seconds and is good for one method
  and path. It names the role that one call needs and the organizations it
  concerns, so a bug in EasyRMM's routing cannot widen a call beyond what
  EasyRMM decided. A copied statement cannot be used for anything else.
* **EasyPatch still checks.** It enforces its role and tenant checks on every
  statement: the second of two independent checks.
* **Access changes apply at once.** Removing someone's access in EasyRMM
  takes effect at their next request.
* **One sign-in rule for the whole product.** EasyRMM's sign-in rules apply
  to patching, including its second-factor policy. ADR-0036 had required a
  second factor for EasyPatch separately.

## 7. DNS and certificates

* Without Authentik: `rmm.example.com` and `mesh.rmm.example.com`.
* With Authentik: also the sign-in name, for example `auth.example.com`.
* After importing a standalone EasyPatch: also its old name.
* Before asking for certificates, the installer checks that each name
  resolves to the server, and says which one does not.

## 8. Tests

* **Unit and integration tests** per phase, as today. EasyPatch's integration
  tests cover the `EasyRmm` scheme's refusals and tenant limits.
* **End-to-end tests:** `make e2e-bundle` (from B, extended through C) and
  `make e2e-authentik` (A). Both run against `deploy/docker-compose.yml`
  itself, on host networking.
* **Retiring:** `make e2e-sign-in` goes with ADR-0036's flow in R.
* **The backup drill** dumps every database and copies EasyPatch's
  data-protection keys and Authentik's media.
  `docs/operations/backup-restore.md` says what each holds.

## 9. Risks

* **The gateway is security code.** It is small, tested for refusals first,
  and reviewed independently before it merges.
* **Phase C is the largest.** Behaviour that must not be lost, such as the
  policy editor, restarts and holds, is ported with its tests.
* **Authentik moves fast,** and must be upgraded through every minor version
  in order. The installer pins it, and the upgrade notes say which versions
  to step through.
* **Licence history.** Earlier copies stay AGPL for those who have them; the
  docs say so.

## 10. Order of work

L (done) → B1 → B2 → B3 → B4 → B5 → B6 to B8 → C1 … C7 → S → A → R → D.

A depends only on B's deployment work, so it can move earlier if the owner
wants the Authentik option sooner.

## 11. Defaults chosen

None of these blocks the work, and the owner can overrule any of them:

* the bundle stays behind a setting until the console has everything;
* macOS patching leaves until EasyRMM has a macOS agent;
* Authentik's groups never grant EasyRMM roles.

## 12. Critique (2026-11-18) and what changed

An independent review of Draft 1 against the code. These findings changed the
plan:

* **Port collisions.** EasyRMM already uses 18080 and 18081, and
  `ASPNETCORE_HTTP_PORTS` binds every interface. Now: a port block per
  program, `ASPNETCORE_URLS` on loopback, and a compose test.
* **A generic proxy to EasyPatch's API could not apply EasyRMM's
  permissions.** Technicians would have lost patching or gained policy
  edits. Now: EasyRMM's typed API, with a role and organization scope per
  call.
* **The "session-equivalent" principal was wrong.** EasyPatch's scheme
  selector, tenant context, session-state handler, CSRF check and user-id
  handlers each need a change, and they are now listed. Per-request user
  rows would race on unique keys, so the principal is now stateless.
* **"Only from loopback" would break or add nothing** behind forwarded
  headers. It is replaced by binding to loopback and stripping the header at
  the edge.
* **Key distribution.** EasyRMM's keys are published only once ADR-0036's
  client exists, and only on public origins. Now: an HS256 key that the
  deployment gives both programs.
* **A prefix allow-list could not separate needed from forbidden routes.**
  The question disappears with the typed API, which exposes only what EasyRMM
  chooses.
* **Phase B would have left no way to manage policies before C.** The bundle
  now stays behind a setting until the switch-over (S).
* **"One release" was needed in B, not R.** Moved to B8.
* **Missing pieces, now added:**
  * upgrading installs that have no EasyPatch (`easypatch-db-init`,
    `setup.sh --upgrade`);
  * device lifecycle;
  * IP-addressed installs;
  * reconciling organization names, case and time zones;
  * the full list of what R removes.
* **Phase C's table was wrong in places.** EasyPatch's "Approvals" are
  approvals of agents, not of patches. It also missed tags, holds, restarts,
  site and endpoint policy, lifecycle, feeds and report schedules. EasyRMM
  has no notification channels, so C7 keeps EasyPatch's under Settings →
  Patching.
* **Authentik:**
  * the blueprint would have re-created a used invitation;
  * mapping a group to super administrator is an escalation path;
  * EasyRMM had no break-glass;
  * port 9443 was missed;
  * there was no first organization;
  * hairpin NAT was not handled.

  Each is changed as described in A.
* **Section 9 targeted installs that don't exist.** No release was ever
  published, so there are no co-hosted installs. Phase S now covers
  importing a standalone EasyPatch, and keeps its old name for enrolled
  agents.
* **Agent packages.** The server cannot check their signatures, because it
  has no release key. B6 now ships them in the image instead of downloading
  them.
* **NuGet licences were not checked.** A check was added, and Dependabot is
  held below PDFsharp's AGPL releases (phase L).
* **Smaller items, all adopted:**
  * pool sizes and the image's user id;
  * the worker's outbound needs;
  * the body cap and replacing `X-Forwarded-For`;
  * error mapping;
  * agent version ordering;
  * a deterministic update source for CI;
  * the backup drill.

**Answered rather than adopted:**

* *A stored list of used statement ids against replay.* Binding each
  statement to a method, a path and 30 seconds is enough on loopback, and
  needs no memory that a restart would lose.
* *Keeping ADR-0036's browser flow.* It retires in R as planned; its grant
  logic and id resolver stay.
* *Rechecking memory about the owner's test servers.* Already current: they
  were removed on 2026-11-18.
