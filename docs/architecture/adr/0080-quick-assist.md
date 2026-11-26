# ADR-0080: Quick Assist, ad-hoc support sessions

* Status: Proposed (2026-11-26). Design only; no code is changed by this ADR.
* Asked for by the owner on 2026-11-26 (binding): "one time quick assist
  agent package, we can generate a link to send to a user, or we can
  generate a permanemt link. Upon download it will run the full RMM
  Agent+Mesh+Patching adhoc. Once the agnet is running, we will have a
  seperage navbar for quick assist devices. You will just accept the
  connectio request in the GUI, and the device will remain in the list for
  the entire session. There will also be an option to install the agent for
  both us and the client. They can then be moved to somewhere else or keep
  in the quick assist sectoin." Everything marked *decided in review* is the
  writer's call; everything marked *owner decision* is open.
* Builds on: [ADR-0015](0015-enrollment-and-meshagent-delivery.md) and
  [ADR-0024](0024-enrollment-approval.md) (tokens, approval),
  [ADR-0059](0059-the-agents-websocket-channel.md) (the channel that pushes
  the connection request and the session's end),
  [ADR-0071](0071-our-meshagent-alongside-others.md) (a MeshAgent that is
  ours alone), [ADR-0031](0031-easypatch-agent-install.md) (EasyPatch
  install), [ADR-0072](0072-what-each-page-shows.md) (what a nav section
  shows), [ADR-0055](0055-lets-encrypt-in-one-step.md) section Step-up
  (5 minutes), [ADR-0007](0007-audit-log.md) (audit),
  `server/internal/devscope`.

## Context

A user with a problem is not an enrolled device, and an MSP does not want to
install a service on a stranger's computer to look at it once. Today the
only way in is the installer, which leaves a service, a MeshAgent, an
EasyPatch agent, Defender exclusions and a device in the tree. The owner
wants a link the user opens, a program that runs for the length of the
session, a technician who accepts the request, and, if both sides agree, a
way to turn the session into a normal device.

### What the code gives us (read 2026-11-26)

* **One binary, several modes.** `easyrmm-agent` dispatches `install`,
  `enroll`, `repair-install`, `run`, `status`, `uninstall`
  (`agent/cmd/easyrmm-agent/main.go:159`). `enroll` without `install`
  already means "enroll, do not make a service" (`enroll(…, service=false)`,
  `:188`), and `run` is the loop a service manager starts. A quick-assist
  mode is a new subcommand over the same enrollment, state store, signed
  requests and run loop, not a second program.
* **Enrollment tokens** are `ert_` + 32 random bytes, hash stored, sealed
  copy kept (ADR-0015, ADR-0047). A deployment token names a site and a use
  limit; an approval token names no site and leaves the device waiting for
  a super administrator (ADR-0024). Neither fits: a quick-assist session
  needs a token tied to one session, a short life, and an acceptance by the
  technician who is on the call, who is not a super administrator.
* **MeshAgent** has a `ModeChild` the EasyRMM agent starts and supervises
  (`agent/meshagent/meshagent.go:48`), and ADR-0071 fixes how ours stays
  apart from any other: its own service name, folder, `.msh`, registry key,
  certificate subject and node id, and every touch of it by exact identity.
  A temporary MeshAgent is the same thing with an identity that is made
  for one session and removed at its end.
* **EasyPatch's agent** has `run` and `enroll` commands
  (`easypatch/agent/EasyPatch.Agent/Program.cs:12-21`), but it ships as an
  MSI, `.deb` or `.rpm`, and enrolls with an EasyPatch token the server
  creates (ADR-0031). Nothing in the repository runs it without the
  installer, and I have not run it that way.
* **Remote control** needs `device.remote_desktop`, and RDP is typed per
  session (ADR-0026, ADR-0079). Both go through the server's gateway.
* **Code signing is on hold.** The agent is not signed (ADR-0020), so a
  downloaded exe meets Windows SmartScreen and the browser's download
  warning. That is the biggest friction in this feature and it is not
  fixable by design.
* **Dev scope.** `devscope.Allowed(orgID)` exists (`server/internal/devscope`)
  and gates every automatic behaviour.

## Decision

### Words

* **Link**: a URL the technician gives a user. **Session**: one run of
  the runner on one computer, from the user's consent to cleanup.
  **Runner**: the program the user downloads. **Quick Assist device**: the
  device row a session creates.

### Links

* **One-time link.** `https://<console>/qa/<token>`. The token is `qal_`
  + 32 random bytes, hash only stored (not shown again: the technician
  copies it when made, since a one-time link is short-lived; this
  differs from ADR-0047 on purpose). Valid until the first download
  starts or until its expiry, whichever is first: default 24 hours, at
  most 7 days. A second open of the page says "this link was used".
  A started download that never produced a session frees nothing: the
  link stays used, and the technician makes another.
* **Permanent link.** The same URL form with `qap_`. It never expires on
  its own, can be revoked at any time, and has these limits, which exist
  because anyone who holds it can start sessions that land in our queue:
  * created only with **step-up** (5 minutes, ADR-0055) and
    `quickassist.link.permanent`, a permission of its own, off for every
    role by default except platform and organization administrators;
  * belongs to one organization (and optionally a site); it cannot be
    created without one; at most 5 live per organization (setting,
    1 to 20);
  * **a session from it waits for acceptance as any request does**, with
    no auto-accept option in v1, so a leaked permanent link can queue
    requests but never open a session without a technician;
  * rate limits: 20 downloads per link per hour, 5 per source address per
    hour, 20 waiting requests per organization at once; over the limit
    the page says to call the technician and the technician sees
    `quickassist.link.throttled` in the audit log and an alert (once per
    link per day, through ADR-0053's sender);
  * an optional **name** shown to the user ("Support for Contoso") and an
    optional note;
  * after 90 days of no use the console marks it stale, and
    after 180 it is revoked automatically (*decided in review*).
* **Per organization or site.** A link carries `organization_id` and
  `site_id`; sessions inherit the organization, which is what RBAC and
  `devscope` read. A link for an organization outside the dev scope
  cannot be created while a scope is set, and its page says it is not
  available.
* **Revoking** ends the link at once; a waiting request from it is
  rejected; a running session continues until it ends (revocation is for
  future use, not a kill switch; **End session** is the kill switch).
* **The link page** (`/qa/<token>`) is public and served by the
  server's own web server. It shows the organization's or MSP's name, the
  link's name, the text of what the runner will do (below), the file's
  SHA-256 and a download button for the user's platform. It carries no
  scripts from other origins and `frame-ancestors 'none'`, and a
  `Referrer-Policy: no-referrer`. A bad or expired token answers one
  page with one message and the same timing for every bad token (no
  oracle between "never existed" and "expired").
* **The download.** The server serves the same signed-by-us-later
  `easyrmm-agent` binary as for install, with the link's **ticket**
  appended as a trailer (a JSON block, an Ed25519 signature by the
  server's job key over `ticket|link|expiry|server URL`, and a length
  tail). The runner reads its own trailer, verifies the signature
  against the key pinned in the binary's build, and refuses a bad or
  expired one. The ticket carries the link id, the server URL and an
  expiry of 1 hour, so a file kept for a week does nothing. *Decided in
  review.* When code signing lands, a trailer breaks an Authenticode
  signature, so the ticket then moves to the file name's companion: the
  user types the 9-character **link code** the page shows beside the
  button (the same signed ticket, base32). The runner already asks for
  that code when it finds no trailer, so this is the fallback now and the
  main path later.
* **Phishing.** Three different risks, and what each gets:
  1. *An attacker copies our page to hand out their own exe.* We cannot
     prevent a copy; we make the genuine one checkable: the page shows
     the file's SHA-256 and, once signing exists, the publisher; the
     runner prints the server's name in its first window; the technician
     reads the session code (below) over the phone, so a user who got a
     link from a stranger has no code to read to anyone. Link text
     tells the user to run the file only when the technician who called
     them asked, and that EasyRMM staff never ask for a password.
  2. *An attacker uses our real link page to trick a user* ("Microsoft
     support: open this"). The runner shows whose server it is, the
     organization's name and what it will share, and requires a click on
     **Allow**; nothing is shared before it, and nothing is shared that
     the user did not read. The attacker gets nothing, because the
     request goes to our technicians, not to them.
  3. *An attacker uses a permanent link to flood or to impersonate a
     user.* Rate limits and acceptance above; the session code binds a
     real person to a request.
  Until code signing, SmartScreen will warn on every exe. The page says
  so, in plain words, with the steps ("More info, Run anyway") and the
  hash to compare. **Owner decision:** accept that warning for the first
  release, or hold the feature until code signing is back on the plan
  (the design does not change either way).

### What runs (Windows first)

The runner is `easyrmm-agent quick-assist`, one exe the user double-clicks.
No service, no scheduled task, no auto-start, no Defender exclusion
(ADR-0070's exclusions are for the installed agent; a session cannot add
them, and a Defender block is reported, not worked around).

1. **Consent window.** Before it contacts anything but the server's
   `/qa/ticket` check, it shows, in a window of its own that cannot be
   skipped by a command-line flag:
   * who: the link's name and the server's host name;
   * what: "lets the technician see and control your screen, run
     programs, see your computer's details and installed updates, and
     transfer files, until you close this window";
   * the **session code**, six digits chosen by the runner from a CSPRNG
     and shown large; the technician is asked to confirm it, so the
     request is tied to the person on the phone;
   * **Allow** and **Cancel**. Cancel exits and deletes the runner's
     files. A visible **End session** stays on screen for the whole
     session, and closing the window ends it.
2. **Elevation is the user's choice.** The runner starts as the user.
   Without elevation, the technician sees and controls the user's own
   session only (no UAC prompts, no other users); with **Run as
   administrator** (the window offers it), the session can do more. The
   console shows which one it is.
3. **A temporary identity** (builds on ADR-0071). Folder
   `%ProgramData%\EasyRMM\QuickAssist\<session id>` when elevated,
   `%LOCALAPPDATA%\EasyRMM\QuickAssist\<session id>` otherwise, ACL'd to
   the user (and SYSTEM). Inside: a fresh Ed25519 key, `state`, our
   MeshAgent binary and a `.msh` with `meshServiceName =
   EasyRMMQA-<8 hex>`, so its registry key (`HKLM` only when elevated),
   certificate subject (`CN=EasyRMMQA-<8 hex>_NodeCertificate`) and
   node id are its own, and none collide with the installed
   `EasyRMMMeshAgent`, with a customer's own MeshAgent, or with another
   session. The MeshAgent runs as a child of the runner (`ModeChild`), so
   it dies with it; nothing installs a service.
   The EasyRMM agent, MeshAgent and (below) EasyPatch agent are started
   with the server's pinned certificate or CA exactly as the installed ones.
4. **Enrollment.** The runner enrolls with its ticket. The server checks
   the ticket (link live, not revoked, rate limits, `devscope`) and creates
   a **session** row and a **Quick Assist device** in the organization's
   Quick Assist site (below), state `requested`. No job, script, remote
   session or file transfer is accepted for it until a technician accepts.
5. **EasyPatch, said honestly.** *Amended 2026-11-26 (decided in review):*
   the owner's "RMM Agent + Mesh + Patching ad hoc" is delivered for the
   first two and not for patching in v1. The EasyPatch agent is an MSI,
   `.deb` or `.rpm` that registers a service and enrolls with a server-made
   EasyPatch token (ADR-0031); I found an agent `run` command but no
   evidence it works from a temporary folder, without the installer's
   registrations and (on Windows) without an installed .NET runtime. So:
   * v1 installs no EasyPatch agent for a session, and the Quick Assist
     device shows **Patching: available after install**;
   * the patch inventory still appears, because the EasyRMM agent's own
     facts include the installed updates it can read; what is missing is
     EasyPatch's scan and its install of updates;
   * **slice QA6** is a one-day spike: run `EasyPatch.Agent.exe run` from
     a temporary folder on a test VM with a one-time EasyPatch token. If it
     works with no residue, a session may start it (through the same
     ADR-0031 instruction, `devscope`-gated and shown on the consent
     text), and the EasyPatch device is deleted at the end; if not,
     patching stays "after install" and the ADR says so.
   * **Install permanently** (below) is the path that brings EasyPatch,
     exactly as ADR-0031 does today.
6. **The end of a session** (any of: the user's End or close, the
   technician's End, the idle limit, the maximum length, link revoked
   with **End sessions** chosen, the runner's process dying):
   * the runner stops MeshAgent, the EasyPatch agent when one ran, and its
     own children, by exact image path (never by name, #122); removes the
     certificates it made, the registry key and the files; schedules its
     own exe for deletion (the exe is the file the user downloaded: it is
     deleted from where it ran, and a copy in `Downloads` the user keeps
     is theirs, so the final window says so);
   * then **verifies**: it lists its own folder, registry key, certificate
     subject, process image paths and listening sockets and sends a
     `cleanup` report, signed by its key, with each check's result and the
     SHA-256 of the manifest. A check that fails is retried 3 times over
     10 seconds, then reported as `residue: <what>`, never hidden;
   * the server records the result on the session and sets the device
     **Ended** with `cleanup: verified`, `residue` or `unconfirmed` (no
     report within 10 minutes, e.g. a power cut). The technician sees
     which. Nothing on the server pretends a clean computer it did not
     hear about.
   * **A crash** leaves residue the runner cannot remove. The next run of
     any runner (or `easyrmm-agent quick-assist --clean`) removes folders
     under `...\QuickAssist\` whose session is not running (found by a
     lock file the live runner holds), and reports it against the old
     session. A reboot ends the MeshAgent child with the runner.

### The console

* **A separate navigation section, Quick Assist** (`web/src/nav/sections.ts`,
  a section with its own tree, following ADR-0072: the main page of every
  level says what it covers). Permission `quickassist.view`. Its tree has
  *Links*, *Requests* (with a count badge, like Waiting for approval), *Active*
  and *Ended*, then the organizations that have Quick Assist devices.
  These devices **do not appear in the Devices tree, patching, reports,
  alerts or monitoring** while they are in Quick Assist (they are in
  one-device-tree views only by an explicit "include Quick Assist" filter).
* **A request** shows: the link's name and organization, the computer's
  name, operating system and address, whether it is elevated, the
  **session code** to compare, the time, and **Accept** and **Decline**.
  It arrives within a second through the ADR-0059 channel when the
  technician's console is open (and by the held poll otherwise), and the
  section's badge and the page title show the count.
* **Accept** needs `quickassist.session` at the organization, the code
  typed or confirmed by clicking it (a click on the displayed code, so a
  technician cannot accept without looking), and is bound to that
  technician: the session's `accepted_by` is the person, and only that
  person (or someone with `quickassist.session.takeover`) can open remote
  desktop, a terminal, files or a script on the device, or end it. Another
  technician sees the device and who has it; they ask for it, and a holder
  or an administrator hands it over, each audited.
* **While the session lasts the device stays listed**, in *Active*, with
  the holder, the time, elevation, whether Mesh is connected, and the same
  tabs a device has (Overview, Hardware, Software, Patches, Logs) plus the
  remote buttons. It does not depend on the technician's browser being
  open.
* **End, timeout, disconnect.**
  * *Ended by the user or technician*: cleanup above; the device moves to
    *Ended* with a read-only summary: who, when, what was done, cleanup
    result; kept for 30 days (setting 1 to 365), then deleted.
  * *Declined or not accepted within 10 minutes*: the runner is told, shows
    "not accepted", and cleans up.
  * *Idle*: no remote session, job or technician action for 30 minutes
    ends it (setting, 5 to 240).
  * *Maximum length*: 8 hours (setting, 1 to 24); the runner warns the
    user 5 minutes before and the technician can extend once with a click.
  * *Disconnect*: when the runner's channel drops, the device shows
    **Disconnected** and the session holds for 10 minutes for it to
    return (the same key, no new request); after that it ends as
    `lost`, cleanup `unconfirmed`.
  * *A server restart* resumes the same way (sessions are rows, not
    memory).
* **Install permanently, both sides agree.** The technician chooses
  **Install agent** on an active session; the runner shows the user a
  second consent window ("keep EasyRMM on this computer so the technician
  can support it; it runs in the background and starts with Windows") with
  the organization's and site's names and **Install** and **Not now**.
  Only the user's click on the runner (never anything the server sends
  alone) lets it proceed, and the technician's click is recorded first.
  Then:
  1. the runner asks the server for a **conversion**: a deployment token
     bound to this device's organization and the *Quick Assist* site, one
     use, 30 minutes, with `devscope` checked again;
  2. it runs the normal install path in place (the one `install` uses:
     service, MeshAgent as `EasyRMMMeshAgent`, EasyPatch by ADR-0031's
     instruction, Defender exclusions as ADR-0070 says, subject to the
     same refusals), **elevated only**: a non-elevated session asks the
     user to restart the runner as administrator first;
  3. the device row is kept: the same device id, history and audit; the
     session ends with `converted`; the temporary MeshAgent, key and
     folder are removed by the cleanup above, after the permanent ones
     answer, and verified;
  4. **Where it lives afterwards:** it stays in the Quick Assist site
     (**Keep in Quick Assist**, the default, a normal agent that is listed
     there) or is **moved** to any site by the existing move action
     (ADR-0069's one move rule, `device.move`), after which it is an
     ordinary device. Either is the technician's choice at any time, and
     the user's consent covers the organization the link named.
  A failed conversion leaves the session as it was and reports why; the
  install's own rollback (ADR-0020) removes what it made.

### Data model

Migration `server/migrations/98080_quick_assist.sql` (the integrator
renumbers it), goose up and down.

* `quick_assist_links(id, organization_id, site_id null, kind
  ('one_time'|'permanent'), name, note, token_hash, state
  ('active'|'used'|'expired'|'revoked'), expires_at null, created_by,
  created_at, used_at null, last_used_at null, revoked_at null,
  revoked_by null, download_count)`. Unique `token_hash`. A check:
  `kind = 'one_time'` implies `expires_at is not null` and at most 7 days.
* `quick_assist_sessions(id, link_id, organization_id, device_id,
  state ('requested'|'active'|'declined'|'ended'|'lost'|'converted'),
  session_code_hash, elevated, requested_at, accepted_by, accepted_at,
  ended_at, end_reason, last_seen_at, cleanup ('none'|'verified'|
  'residue'|'unconfirmed'), cleanup_report jsonb, source_ip, expires_at)`.
  The code is stored as a hash with the session's id as salt and is
  compared only by the server; it is never in the audit log.
* `sites.kind text not null default 'normal'` (`'normal'|'quick_assist'`)
  and a partial unique index so each organization has at most one Quick
  Assist site, created on first use (`name 'Quick Assist'`). A Quick
  Assist site cannot be deleted while it holds devices, and it is
  filtered out of site pickers except as a move source. *Decided in
  review:* a site, not a flag on devices, because every existing query,
  foreign key and RLS rule already works per site.
* `devices.quick_assist boolean not null default false`, true from
  enrollment until moved to a normal site (then false); the Quick Assist
  nav lists `devices.site in Quick Assist sites`.
* Row-level security on all three tables follows ADR-0063 and the
  organization column, as the other tenant tables do.
* Retention: ended sessions and their devices after 30 days; links 1 year
  after revoked or used. A janitor job (checks `devscope.Allowed` per
  organization before each deletion or alert) does it.

### Permissions

New (`rbac.go`, additive): `quickassist.view`, `quickassist.link.create`
(one-time links), `quickassist.link.permanent` (permanent links, step-up),
`quickassist.session` (accept, use, end), `quickassist.session.takeover`,
`quickassist.install` (conversion), all at the organization. Using the
remote tools on a Quick Assist device also needs the usual
`device.remote_desktop`, `device.terminal` and so on; Quick Assist adds
the holder rule, it never replaces them. Defaults: technicians get
view, link.create and session; administrators the rest.

### Security

* **Step-up** (ADR-0055 section Step-up, 5 minutes) for: creating a
  permanent link, raising the permanent-link cap, and revoking another
  person's link. Not for a one-time link or accepting a session (it must
  be quick on a call), which are audited and rate limited instead.
* **Audit** (ADR-0007), each with the actor, link or session id, the
  organization and the source address, never the code or the token:
  `quickassist.link.create`, `.revoke`, `.download` (as the user, source
  address), `.throttled`, `quickassist.session.request`, `.accept`,
  `.decline`, `.takeover`, `.end` (with reason), `.lost`,
  `.cleanup` (with result), `.install`, `.converted`.
* **Server never trusts the runner's claims about consent.** The runner's
  consent click is a signed message from its key that the server stores;
  the server refuses to enable remote control for a session with no
  consent message, an unaccepted request, or a different holder.
* **Isolation.** The runner's enrollment ticket and key work only for its
  own session; a session's device cannot read other devices' data, and its
  job key is not the permanent one. A session's key is valid until the
  session ends, then revoked.
* **Abuse.** All the limits above; every public endpoint (`/qa/…`, the
  ticket check, the enrollment) is rate limited per address and per link,
  and answers with timing that does not depend on the token's state.
* **`devscope`.** Every automatic behaviour here (link-created alerts,
  the janitor, the stale-link revoker, the session sweep, the push of a
  request) calls `devscope.Allowed(orgID)` first, as ADR-0059 does. While
  a scope is set, a link for an organization outside it is refused at
  creation and at its page, and the runner's enrollment answers 404.
  The agent side has nothing to check. A test proves a second
  organization's link neither serves nor enrolls.
* **What the user keeps.** The window says what is shared, the technician
  cannot change it silently, **End session** is one click, and the audit
  log is the user's record: it can be exported by the organization.

### Platforms

* **Windows first.** Everything above.
* **Linux, if feasible (second).** `easyrmm-agent quick-assist` runs as
  the user in a terminal or, with a desktop session, from a small
  `.AppImage`-free download: a self-extracting shell script
  (`install.sh`'s relative) that runs the binary from a temporary
  directory under `$XDG_RUNTIME_DIR` (or `/tmp` with mode 0700) in the
  foreground and prints the consent text and code in the terminal, since
  a graphical prompt cannot be assumed. Remote *desktop* on Linux needs
  an X session MeshAgent can capture, and Wayland blocks that; the first
  Linux cut is terminal, files and inventory, and the device's page says
  "desktop not available" instead of showing a broken button. Cleanup is
  the same list (processes by exact path, folder, no unit files) and is
  verified the same way. Patching is not run ad hoc on Linux (the
  `.deb`/`.rpm` needs root and a package manager).
* **macOS: not in this ADR.** The repository has no macOS agent
  (`supported()` is Linux and Windows); EasyPatch has macOS sources but the
  EasyRMM agent does not. Quick Assist waits for a macOS agent.

### Tests

* **Unit.** Ticket sign/verify and expiry; link state machine (one-time
  used once, expiry boundaries, revoke); rate-limit counters; code
  compare; the session state machine (every transition and every
  forbidden one); trailer parse (truncated, forged, oversize);
  cleanup manifest; identity names never collide with `EasyRMMMeshAgent`.
* **Integration** (real PostgreSQL): the migration up and down; a link's
  lifecycle and its RLS; a session end to end against the real server
  with a fake runner that speaks the real protocol (no mocks of our own
  code); a second organization and a scope test for `devscope`; step-up
  required and refused on a stale session; takeover and holder rules;
  conversion keeps the device id; retention and janitor.
* **Web.** Vitest for the Quick Assist section, request list and badge;
  an e2e spec: make a link, run a simulated runner, accept, see the device
  in Active, end it, see Ended.
* **Real runs (not done by this ADR; required before it is called done).**
  * **Windows test VM** (a clean Windows Server or client VM, a snapshot
    before each run): run the exe with and without elevation; confirm the
    SmartScreen text matches the page; accept; remote desktop works;
    end; confirm with a before/after listing of folders, services,
    registry, certificates, processes, scheduled tasks and Defender
    exclusions that **nothing remains**; kill the runner mid-session and
    confirm the next run cleans up; run **beside** a stock MeshAgent and
    beside the installed EasyRMM agent; convert to a permanent install and
    move it; revoke a link mid-session.
  * **Linux in a Proxmox VM** (the test PVE, a throwaway VM, never the
    reserved ones): the same list, adapted, on a distribution with and
    without a desktop.
  * Stated plainly in the report of whoever builds it: what was run on
    which system and what was not.

### Slices

* **QA1** schema, link create/revoke/page, ticket, rate limits, audit,
  RBAC, `devscope`. Server only.
* **QA2** session and acceptance on the server (request, accept, holder
  rule, end, timeouts, janitor), channel push, Quick Assist site.
* **QA3** the runner on Windows (consent window, temporary identity,
  MeshAgent child, enrollment, end, verified cleanup, crash cleanup).
  **First a one-day spike**: MeshAgent in `ModeChild` from a temporary
  folder with no service, as a non-admin user, on the Windows VM. If
  remote desktop needs more than that, this design's non-elevated mode
  is cut back before building.
* **QA4** the console section and pages (ADR-0072 main pages, nav, badge).
* **QA5** install permanently and conversion.
* **QA6** the EasyPatch ad hoc spike, as above, decided on its result.
* **QA7** Linux runner (terminal, files, inventory).
* Each slice leaves the tree green and builds on the last.

## Consequences

* A technician gets one way in for a stranger's computer and one switch to
  keep it. A user gets a program that says what it does, asks, and removes
  itself.
* Unsigned, the exe will be warned about by SmartScreen; users must click
  through. This is a real cost and the page says so.
* Patching of an ad-hoc session is inventory-only until the EasyPatch
  spike proves more; the owner's wording said full patching, so this is a
  deliberate reduction with a reason.
* A permanent link is a standing door to the request queue. It cannot
  open a session on its own, but it can fill the queue; limits, alerts and
  revocation answer that.
* Cleanup is verified by the runner's signed report, not by anyone else.
  A runner that is compromised could lie, which is a statement about a
  user's own computer, and is why `unconfirmed` and `residue` exist.
* A new device kind adds a filter to the device queries, which the
  tests above and ADR-0072's views must keep honest.

## Owner decisions

1. **SmartScreen.** Ship the first release with the unsigned-exe warning,
   or wait for code signing. (Recommendation: ship it with the page's
   instructions; signing slots in later without changing the design.)
2. **Patching ad hoc.** Accept inventory-only for v1 with EasyPatch
   decided by the QA6 spike, rather than holding the feature for it.

Everything else is decided in review above.

## Amended 2026-11-26 (decided in review)

* Patching is not part of the ad-hoc runner in v1 (see *What runs*, item 5);
  the owner's words said it was.
* macOS is out of scope: there is no macOS EasyRMM agent.

## References

ADR-0007, 0015, 0020, 0024, 0026, 0031, 0047, 0050, 0055 (step-up), 0059,
0063, 0069, 0070, 0071, 0072, 0079; `agent/cmd/easyrmm-agent/main.go`,
`agent/meshagent/meshagent.go`, `server/internal/devscope`,
`easypatch/agent/EasyPatch.Agent/Program.cs`.
