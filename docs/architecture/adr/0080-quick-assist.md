# ADR-0080: Quick Assist, ad-hoc support sessions

* Status: Accepted (2026-11-26, after an independent review). Design only; no code is changed by this ADR.
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
  (5 minutes), [ADR-0007](0007-hash-chained-audit-log.md) (audit),
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
* **EasyPatch's agent** ships as an MSI, `.deb` or `.rpm`, and enrolls with
  an EasyPatch token the server creates (ADR-0031). It is self-contained
  and a single file (`EasyPatch.Agent.csproj:10-11`), so it needs no .NET
  runtime. What stops it running ad hoc is four things in our own code:
  `run` refuses unless elevated or LocalSystem (`Program.cs:44-47`); its
  data directory is fixed, `C:\ProgramData\EasyPatch`
  (`AgentRuntimeOptions.cs:5`, `AgentComposition.DataDirectory`), with a
  registry key of its own; a single-instance lock on that directory
  (`AgentInstanceLock`, `Program.cs:62`); and `AddWindowsService`
  (`Program.cs:74`). We own it, so it gets an ad-hoc mode (below).
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
  * **abuse limits.** A **token bucket per link** is the primary limit
    (burst 5, refill 1 per 3 minutes; settings), because an attacker can
    rotate addresses and cannot rotate the link. Per-address limits (5
    downloads an hour, 20 enrollments an hour) are secondary and only
    stop one machine hammering. **A waiting request expires after 10
    minutes** and the runner is told. **The per-organization cap** (20
    waiting requests) **evicts the oldest unanswered request** when a new
    one arrives, so one stranger cannot fill the queue and lock real
    users out; an evicted runner is told "not accepted, try again". A
    link over its bucket answers the page's "call your technician" text,
    audits `quickassist.link.throttled` and raises one alert per link per
    day (ADR-0053's sender);
  * a link can be **paused** (the page says "paused, call your
    technician") and resumed by anyone with `quickassist.link.permanent`,
    without step-up, so a technician can stop a flood in one click;
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
* **Threat model, said plainly.** The runner is a program on the user's
  own computer. Anyone who can run a modified runner there already has
  code execution as that user, so **the runner's consent window protects
  the user from us and from a misdirected link; it is not a control the
  server can rely on to defend itself.** The server therefore enforces
  its own rules (no remote control before a technician's acceptance, the
  holder rule, expiry, revocation, rate limits) and does not believe the
  runner about consent beyond recording it. What the design does and does
  not stop:
  1. *A copied binary or page pointing at somebody else's server.* This is
     the generic remote-support scam: a user is talked into running a
     program. We cannot prevent it. We make the genuine one checkable: the
     page shows the file's SHA-256, the consent window names the MSP's
     organization and the server's domain, the technician's call supplies
     a code the user reads out, code signing will show a publisher when it
     lands, and a link can be revoked at once. A user who does not check
     these is not protected, and the page says so in plain words.
  2. *Our genuine runner used to deceive a user.* The consent text names
     who asks and what is shared, and nothing is shared before **Allow**.
     A scammer cannot use our server for this: the request goes to our
     technicians.
  3. *A permanent link used to flood or to impersonate.* The limits and
     acceptance above; the code the technician types binds a real person
     to a request.
  Until code signing, SmartScreen warns on every exe; the page explains
  it ("More info, Run anyway"). **Owner decision 1** below.

### What runs (Windows first)

The runner is `easyrmm-agent quick-assist`, one exe the user double-clicks.
No service, no scheduled task, no auto-start, no Defender exclusion
(ADR-0070's exclusions are for the installed agent; a session cannot add
them, and a Defender block is reported, not worked around).

1. **Consent window.** Before it contacts anything but the server's
   `/qa/ticket` check, it shows, in a window of its own that no
   command-line flag skips:
   * who: the **MSP's organization name** (the link's organization) and
     the **server's domain**, in large text;
   * what: "lets the technician see and control your screen, run
     programs, see your computer's details and installed updates, and
     transfer files, until you close this window";
   * the **session code**, six digits from a CSPRNG, shown large. The user
     reads it to the technician on the call; **the technician must type
     it** (the console never displays it, only the runner does), so
     acceptance proves the technician is talking to the person at that
     computer. Three wrong entries close the request, the runner is told,
     and the audit log records `quickassist.session.decline` with reason
     `code_failed`;
   * **Allow** and **Cancel**. Cancel exits and deletes the runner's
     files. **End session** stays on screen, and closing the window ends
     it.
2. **Elevation by default.** The runner asks for elevation through UAC
   when it starts (the exe's manifest is `asInvoker`; the runner
   relaunches itself with `runas`, so the consent window is the first
   thing the user sees either way). If the user declines UAC, the runner
   continues **not elevated**: the session is **screen only plus
   inventory** (the user's own desktop through MeshAgent, the facts the
   agent reads as a user), with no jobs, scripts, services, file system
   outside the user's folders and no patching; the console shows
   "Not elevated: screen and inventory only" on the request and device.
3. **A temporary identity** (builds on ADR-0071). Folder
   `%ProgramData%\EasyRMM\QuickAssist\<session id>` when elevated,
   `%LOCALAPPDATA%\EasyRMM\QuickAssist\<session id>` otherwise, ACL'd to
   the user (and SYSTEM). Inside: a fresh Ed25519 key, `state`, our
   MeshAgent binary and its `.msh` and `.db`, and the EasyPatch data
   directory (item 5). Nothing is installed as a service. The EasyRMM
   agent, MeshAgent and EasyPatch agent are started with the server's
   pinned certificate or CA as the installed ones are. The MeshAgent is
   described next.
4. **Enrollment.** The runner enrolls with its ticket. The server checks
   the ticket (link live, not paused or revoked, token bucket, `devscope`)
   and creates a **session** row and a **Quick Assist device** in the
   organization's Quick Assist site (below), state `requested`. No job,
   script, remote session or file transfer is accepted for it until a
   technician accepts.
5. **EasyPatch, ad hoc.** *Amended 2026-11-26 (decided in review),
   replacing this ADR's first draft, which cut patching:* EasyPatch gets
   an **ad-hoc mode**, `EasyPatch.Agent run --adhoc --data-dir <dir>
   --registry-key <name> --lock <name>`, changed in
   `easypatch/agent/EasyPatch.Agent` (new paths proposed in the Slices
   section). In it:
   * it runs as a **console child of the runner**, no `AddWindowsService`;
   * its data directory is `<session folder>\EasyPatch`, and its registry
     key and single-instance lock names carry the session id, so none
     touches `C:\ProgramData\EasyPatch`, `HKLM\SOFTWARE\EasyPatch` or
     an installed agent's lock;
   * it **starts only when the runner is elevated** (the elevation check
     at `Program.cs:44-47` stays: it needs to scan and install updates)
     and **refuses to start when a real EasyPatch install exists** on the
     computer (the service, its data directory or its registry key), so
     there is no collision and the real agent is never disturbed; the
     console then says "EasyPatch already installed; its patching
     applies";
   * the server gives it an EasyPatch token as ADR-0031 does (single use,
     one hour, for the linked EasyPatch organization, only if the
     organization is linked and `devscope.Allowed`), and **deletes the
     EasyPatch device at the end** through the engine's API, as it
     removes the MeshCentral node below;
   * it dies with the runner (job object on Windows, below), so a reboot
     leaves no EasyPatch process, no service and no data directory.
   A non-elevated session, an unlinked organization or an existing real
   install gets inventory only, and the device says why.

### The MeshAgent for a session

*Verified against MeshAgent master (`meshcore/agentcore.c`) and MeshCentral
1.3.1 (`webserver.js`, `meshuser.js`, `agents/meshcore.js`), the version
`deploy/docker-compose.yml:237` pins. A run on a real Windows VM is not
yet done.*

* **Which no-install mode.** MeshAgent has a foreground mode that needs no
  installation: `meshagent run` or `meshagent connect`
  (`agentcore.c:5663`, `paramLen == 2` with `run` or `connect`), which runs
  the agent from the folder it is in and reads the `.msh` and `.db`
  beside the executable (`agentcore.c:5134-5142`; ADR-0071 row 3). **We use
  `connect`** as a child of the runner. **MeshCentral Assistant** (served
  by `webserver.js:6417-6420`, `id=10006`, `AutoConnect`) is a separate
  Windows program with its own flags, a system tray and the Assistant
  settings; it is not our MeshAgent, we do not control its folder or
  identity, and it would be a second thing to isolate, so we do not use it.
  The "agent invite" page (`webserver.js:2346-2571`, `agentinvitecodes`,
  `installflags`) hands out installers and sets `InstallFlags` in the
  `.msh` (`webserver.js:6416`); it is an installer path, and we do not use
  it either. We write our own `.msh` as the installed agent does.
* **Which device group.** The server makes **one MeshCentral device group
  per organization named "Quick Assist"** (`CreateMesh`,
  `server/internal/meshcentral/commands.go:79`, on first use; MeshCentral
  `createmesh`, `meshuser.js:2212`), separate from the organization's
  site groups. The temporary node joins it by the `.msh`'s
  `MeshID`/`ServerID`/`MeshServer`, which the server composes for that
  group the same way it does for the real ones. Technician access is
  through the same per-user mesh rights EasyRMM already sets
  (`SetMeshRights`, `commands.go:138`), so a technician sees it only
  through the gateway as for any device.
* **A per-session identity, minted by the server.** The `.msh` carries
  `meshServiceName=EasyRMMQA-<8 hex of the session id>` (the same setting
  ADR-0071 uses, `agentcore.c:5317-5327`) and `Tag=<session id, hex>`
  (`webserver.js:6414`, alphanumeric only). That makes its folder, `.db`
  and node key, registry key (`Software\Open Source\<name>`,
  `agentcore.c:5503-5505`) and, when the Windows store is used, its
  certificate subject (`CN=<name>_NodeCertificate`, `agentcore.c:2277-2283`,
  `:2396-2402`) its own, and different from `EasyRMMMeshAgent`, from a
  customer's own `Mesh Agent`/`meshagent` and from every other session.
  The node's id is the one our own MeshAgent binary prints for its
  `.db` (`NodeID`, `agent/meshagent/meshagent.go:526`); the runner sends
  it on the signed channel, the server finds the node with `Nodes()`
  (`commands.go:165`) and cross-checks the `Tag`, and refuses on a
  mismatch. Where the certificate lives (the Windows store or the `.db`:
  `agentcore.c:2264` reads `SelfNodeCert` from the `.db` and skips the
  store when it is set) is read in QA3 and the cleanup removes whichever
  one is used, by exact subject.
* **Removal.** At the session's end the server calls `RemoveDevice`
  (MeshCentral `removedevices`, `meshuser.js:2965`; `commands.go:187`)
  with the recorded node id, so no stale node stays in the group, then
  deletes the group if it has no nodes (one per organization, kept
  otherwise). It never uses `uninstallagent` (nothing is installed),
  and never matches by name. A node left by a crash is removed by the
  server's session sweep when the session is marked `lost`.
* **Isolation from other MeshAgents.** Everything ADR-0071 requires holds
  with different names: no shared service, folder, registry key,
  certificate, process or pipe; our force-stop matches the **exact image
  path** in the session folder, never a name; the UDP 16990 socket is
  shared by design (`SO_REUSEPORT`, ADR-0071 row 8). A customer's own
  MeshAgent is neither read, stopped nor changed.

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
   * **Mechanisms.** The runner starts every child (MeshAgent, EasyPatch)
     inside a **Windows job object** with `KILL_ON_JOB_CLOSE`, so the
     children die with the runner, including when it crashes or is
     killed, and the runner holds no persistence (no service, no Run key,
     no task), so a **reboot** ends the session and nothing restarts. The
     **idle limit** is a timer in the runner's loop: it measures its own
     last activity (a remote session, a job, a technician request relayed
     by the server) and ends the session at 30 minutes; the server has the
     same timer on the session row as a second check. *Linux:* children
     are started in their own process group with `PR_SET_PDEATHSIG` and
     the runner is a foreground program, so closing the terminal ends it.
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
* **Accept** needs `quickassist.session` at the organization and the
  technician **types the six-digit code** the user reads to them; the
  console does not show it. Three wrong entries close the request. The
  session is bound to that technician: `accepted_by` is the person, and
  only that person (or someone with `quickassist.session.takeover`) can
  open remote desktop, a terminal, files or a script on the device, or end
  it. Another technician sees the device and who has it; they ask for it,
  and a holder or an administrator hands it over, each audited.
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
  1. **The approval step is replaced.** ADR-0024 has a super
     administrator approve waiting devices; here the technician's accept
     plus a **step-up** (5 minutes, ADR-0055) done for this action stands
     in for it, *decided in review*, because the technician is on the call
     with the user and the device is already in an organization the link
     named.
  2. The server issues a **conversion token**: a deployment token for this
     organization and the Quick Assist site, one use, valid for **30
     minutes**, `devscope` checked again. The token is consumed only by an
     enrollment that succeeds; **a failed install can retry until it
     expires**, and the token is revoked when the session ends.
  3. The runner runs the normal install path (service, MeshAgent as
     `EasyRMMMeshAgent`, EasyPatch by ADR-0031's instruction, Defender
     exclusions as ADR-0070), **elevated only**; a non-elevated session
     asks the user to restart the runner as administrator first.
  4. **It is a new enrollment**: new device key, new MeshAgent node and
     (when linked) a new EasyPatch device. It is **not** the temporary
     identity promoted. **Continuity of the audit trail** comes from
     linking: the conversion records `quick_assist_session_id` on the new
     device (`devices.origin_session_id`) and the session's `device_id`
     moves to the new device, so the session's audit rows, notes and
     history show under the new device and `quickassist.converted` names
     both ids. The temporary device row, key, node and folder are then
     removed, after the permanent agent has answered, and cleanup is
     verified as at any end.
  5. **Where it lives afterwards:** it stays in the Quick Assist site
     (the default, a normal agent listed there) or is **moved** to any
     site by the existing move action (ADR-0069's one move rule,
     `device.move`), after which it is an ordinary device. Either is the
     technician's choice at any time; the user's consent covers the
     organization the link named.
  A failed conversion leaves the session as it was and reports why; the
  install's own rollback (ADR-0020) removes what it made.

### Data model

Migrations `server/migrations/00063_quick_assist_links.sql`, `00064_quick_assist_sessions.sql`
and `00065_quick_assist_orgs.sql` (placeholders; the integrator renumbers them), goose up and down.

* `quick_assist_links(id, organization_id, site_id null, kind
  ('one_time'|'permanent'), name, note, token_hash, state
  ('active'|'used'|'expired'|'revoked'), expires_at null, created_by,
  created_at, used_at null, last_used_at null, revoked_at null,
  revoked_by null, download_count)`. Unique `token_hash`. A check:
  `kind = 'one_time'` implies `expires_at is not null` and at most 7 days.
* `quick_assist_sessions(id, link_id, organization_id, device_id,
  state ('requested'|'active'|'declined'|'ended'|'lost'|'converted'),
  session_code_hash, code_failures, elevated, requested_at, accepted_by, accepted_at,
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
  nav lists `devices.site in Quick Assist sites`; `devices.origin_session_id
  uuid null` links a converted device to its session.
* `organizations`-level Quick Assist MeshCentral group id and EasyPatch
  link state are kept in `quick_assist_orgs(organization_id, mesh_id)`.
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

* **Step-up** (ADR-0055 section Step-up, 5 minutes) for: **creating a
  permanent link**, raising the permanent-link cap, converting a session
  to a permanent install, and revoking another person's link. Not for a one-time link or accepting a session (it must
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
    exclusions, and the EasyPatch data directory and registry key that
    **nothing remains**, with an installed EasyPatch agent present (the
    ad-hoc mode refuses and the real one is untouched) and without; kill the runner mid-session and
    confirm the next run cleans up; run **beside** a stock MeshAgent and
    beside the installed EasyRMM agent; convert to a permanent install and
    move it; revoke a link mid-session.
  * **Linux in a Proxmox VM** (the test PVE, a throwaway VM, never the
    reserved ones): the same list, adapted, on a distribution with and
    without a desktop.
  * Stated plainly in the report of whoever builds it: what was run on
    which system and what was not.

### Slices

Existing files are real (grepped 2026-11-26); paths marked *proposed* do
not exist yet. Hotspot files (`rbac.go`, `app.go`, `agentproto`,
`runner.go`, the nav tree) get small additive edits.

* **QA1: links, ticket, limits (server).** Proposed
  `server/internal/quickassist/` (links, tickets, token bucket),
  proposed `server/internal/httpapi/quickassistapi/` (console API) and
  the public `/qa/` page beside the existing installer templates in
  `server/internal/httpapi/agentapi/` (`install.ps1.tmpl`); proposed
  `server/migrations/90131_quick_assist.sql`;
  `server/internal/rbac/rbac.go` (permissions), `server/internal/app/app.go`
  (wiring), `server/internal/audit` (event names),
  `server/internal/devscope` (the check).
* **QA2: sessions and acceptance (server).** Proposed
  `server/internal/quickassist/session.go`; the enrollment and ticket
  check in `server/internal/agents/enroll.go` and `tokens.go`
  (`approval.go` is the model for the waiting request);
  `server/internal/agents/heartbeat.go` and `internal/agentproto` (session
  state in the heartbeat); the channel push of ADR-0059 in
  `server/internal/agentchannel`; the Quick Assist site in
  `server/internal/tenancy`; the janitor in `server/internal/jobs`.
* **QA3: the Windows runner.** `agent/cmd/easyrmm-agent/main.go` (the
  `quick-assist` subcommand, next to `enroll` and `run`), proposed
  `agent/quickassist/` (consent window, job object, cleanup and
  verification), `agent/meshagent/meshagent.go` (a `connect` mode beside
  `ModeChild`), `agent/host/` (exact-path stop, `force_windows.go`),
  `agent/state/state.go` (the session folder), `agent/runner/runner.go`
  (the session loop, one small block). **First a one-day spike on the
  Windows VM:** `meshagent connect` from a temporary folder as a standard
  user and as an administrator; remote desktop and where the node
  certificate is kept. If the standard-user case fails, the
  not-elevated mode is cut back before building.
* **QA4: the console.** `web/src/nav/sections.ts` and `SectionNav.tsx`
  (the section and its tree), proposed `web/src/pages/quickassist/`
  (links, requests, active, ended), `web/src/pages/devices/DeviceDetailPage.tsx`
  (holder badge, additive), `web/src/api/` (client and hooks).
* **QA5: install permanently and conversion.** `agent/cmd/easyrmm-agent/main.go`
  (`install` reused), `server/internal/agents` (the conversion token),
  `server/internal/httpapi/quickassistapi/`, the console dialog.
* **QA6: EasyPatch ad-hoc mode.** `easypatch/agent/EasyPatch.Agent/Program.cs`
  (`run --adhoc`, the elevation and existing-install checks),
  `AgentComposition.cs` (data directory, service name, lock, registry
  key as parameters), `easypatch/agent/EasyPatch.Agent.Core/AgentRuntimeOptions.cs`,
  `easypatch/agent/EasyPatch.Agent.Tests` (collision, refusal, no
  service), `agent/easypatch/` (the runner side), `server/internal/easypatch`
  (token and device removal at the end).
* **QA7: Linux runner.** The same subcommand with a process group and a
  terminal consent text; a shell fetcher beside
  `install.sh.tmpl`; no EasyPatch (it needs root and a package manager).
* Each slice leaves the tree green and builds on the last.

## Consequences

* A technician gets one way in for a stranger's computer and one switch to
  keep it. A user gets a program that says what it does, asks, and removes
  itself.
* Unsigned, the exe will be warned about by SmartScreen; users must click
  through. This is a real cost and the page says so.
* Patching ad hoc needs a change to the EasyPatch agent (QA6) and works
  only for elevated sessions on computers with no real EasyPatch install.
* A permanent link is a standing door to the request queue. It cannot
  open a session on its own, but it can fill the queue; limits, alerts and
  revocation answer that.
* Cleanup is verified by the runner's signed report, not by anyone else.
  A runner that is compromised could lie, which is a statement about a
  user's own computer, and is why `unconfirmed` and `residue` exist.
* A new device kind adds a filter to the device queries, which the
  tests above and ADR-0072's views must keep honest.

## Owner decisions

1. **SmartScreen, until code signing is back.** Options:
   * **(a) Ship unsigned.** Every download meets the browser and
     SmartScreen warnings; the page explains the click-through and shows
     the SHA-256. Fast, honest, and a poor first impression for users who
     were told to expect a support call; it also teaches clicking through
     warnings, which is a real cost.
   * **(b) Hold Quick Assist until signing.** No warning at launch, but
     the feature waits on an unscheduled item, so nothing ships.
   * **(c) Ship to technicians' own test links only until signing.** One-time
     links to the owner's and testers' own computers (a setting that
     limits who may create links), proving the flow on real systems while
     real customers wait for a signed build. Costs one flag and a gate.
   **Recommendation: (c) now, then (a) only if signing slips past the
   first customers.** It builds and exercises everything, avoids training
   customers to ignore warnings, and does not block on signing.

Everything else is decided in review above.

## Amended 2026-11-26 (decided in review)

* EasyPatch runs ad hoc, through a new ad-hoc mode in its agent (*What
  runs*, item 5), elevated sessions only; the first draft's "inventory
  only" is withdrawn, and its claim that .NET might be missing was wrong
  (the agent is self-contained).
* The technician types the code; the console never displays it.
* Conversion is a new enrollment, with the technician's accept plus
  step-up standing in for ADR-0024's approval.
* macOS is out of scope: there is no macOS EasyRMM agent.

## Built so far (2026-11-26)

*Amended 2026-11-26 (decided in review), while building QA1, QA2 and the Linux part of QA7:*

* **Owner decision 1 is built as option (c), pending the owner.** The one
  switch is the platform setting `quickassist.link_mode`: `own_test` (the
  default, also when the setting is missing or unreadable) or `open`.
  In `own_test` only **one-time** links can be made, each is marked a test link
  (`quick_assist_links.test`, shown on the link page and in the console), and
  **only the person who made a link accepts a session from it** (another
  technician's accept is refused and audited as denied). Changing the mode
  needs `settings.manage` platform-wide and a step-up, and is audited
  (`quickassist.settings.update`). Lifting the restriction is that one setting
  and nothing else changes.
* **The ticket carries the server's public key.** A release build is shared by
  every server, so the runner cannot hold a per-server key in its build, and
  the "key pinned in the binary's build" above cannot be done. The runner
  checks that its trailer is whole, signed and unexpired against the key the
  ticket carries (a courtesy against damage and old files); the **server is the
  only authority**, checking every ticket against its own key at enrollment.
  The consent window names the server from the ticket, as before.
* **Not built yet:** the 9-character link code (a signed ticket does not fit
  in 9 characters; it needs a short server-side code and is for when signing
  makes the trailer unusable); the one-alert-per-link-per-day mail for a
  throttled link (the audit row `quickassist.link.throttled` and the link's
  `last_alert_at` column exist; ADR-0053's sender is not called); the stale-link
  revoker (90 and 180 days); the settings for the bucket, caps and timings
  (they are constants in `server/internal/quickassist`); the idle limit; the
  maximum-length extension; the holder rule on remote desktop, terminal, files
  and scripts (acceptance and the holder rule are enforced on the Quick Assist
  actions only; `remote`, `jobs` and `agentfiles` do not yet ask whether a
  device is a Quick Assist device); the EasyPatch link state in
  `quick_assist_orgs` and the MeshCentral group (the table exists, unused).
* **Slices.** QA1 (links, ticket, limits, rbac, audit, `devscope`), QA2 (the
  session, acceptance by the typed code, the Quick Assist site and its device
  filter, the sweep and retention) and QA4 (the section, requests, active,
  links, ended, the badge) are built. QA7's Linux runner is built without
  MeshAgent (terminal consent, enrollment, status loop, clean-up and its
  signed report, crash clean-up by `quick-assist --clean`); there is no shell
  fetcher beside `install.sh.tmpl` yet. **QA3 (the Windows runner, job object,
  MeshAgent `connect`), QA5 (install permanently and conversion) and QA6
  (EasyPatch ad-hoc mode) are not built.** The runner's `--server` flag
  reaches the server at another address than the ticket's (tests, a private
  network); the consent window names the address used and the server still
  checks the ticket against its own.
* **The download's SHA-256.** The page cannot show the hash of the file the
  user will download, because the trailer differs per download; the response
  carries the program's hash (before the ticket) in `X-Program-Sha256`.
* **Not run on a real system.** Nothing here was run on Windows. The Linux
  runner ran against the real server in tests and in the browser end-to-end
  run only.

## References

ADR-0007, 0015, 0020, 0024, 0026, 0031, 0047, 0050, 0055 (step-up), 0059,
0063, 0069, 0070, 0071, 0072, 0079; `agent/cmd/easyrmm-agent/main.go`,
`agent/meshagent/meshagent.go`, `server/internal/devscope`,
`easypatch/agent/EasyPatch.Agent/Program.cs`.
