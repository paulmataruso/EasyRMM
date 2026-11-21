# ADR-0053: One notification sender, and notifications for device alerts

* Status: Proposed (2026-11-21). Not implemented.
* Builds on: [ADR-0019](0019-monitoring-and-alerts.md) (monitoring and
  alerts), [ADR-0023](0023-audit-forwarding.md) (audit forwarding and the
  address rule of the platform's integrations),
  [ADR-0038](0038-statements-to-the-patching-engine.md) (statements to the
  engine), [ADR-0047](0047-tokens-shown-again.md) (secrets shown again),
  [ADR-0048](0048-the-engine-keeps-what-is-reached.md) (nothing left that
  nothing reaches) and [ADR-0050](0050-removing-a-device.md) (removing a
  device).
* Amends: [ADR-0052](0052-the-host-updater.md), "Downtime and alerts": its
  offline rule delays the opening of offline alerts only (see **Restarts**).
* Part of [the feature plan](../feature-plan.md): F2 and feature 7.

## Context
Technicians need to hear about trouble without watching the console, and
an MSP wants to set up its email list, its Teams channel and its PSA
tool's webhook once. Patching sends notifications today; device alerts do
not.

What exists, and what it means here:

* **The patching engine sends its own.** Settings → Patching →
  Notifications (`web/src/pages/patching/Notifications.tsx`, through
  `server/internal/easypatch/notifications.go`) manages the engine's
  channels: email, and webhooks in three formats
  (`easypatch/backend/Core/Entities/Notifications.cs`). Super administrators
  only; channels are server-wide.
  * **Deciding**: `AlertEngine` (worker task `alerts`, every 2 minutes)
    opens and resolves patching alerts, reopens one resolved less than an
    hour ago without a notification, and queues one delivery per channel
    and kind (opened, resolved, reminder) per run, with at most 25 alerts
    and a count of the rest, for every format, the generic one included.
  * **Sending**: `NotificationDispatcher` (task `notifications`, every 30
    seconds; each worker task runs under its own advisory lock) takes up to
    50 due deliveries a run within 25 seconds, retries from 1 minute
    doubling to an hour, and gives up after 24 hours (tests after 3
    attempts). One test per channel every 30 seconds
    (`NotificationEndpoints.TestInterval`). Stored errors are its own
    sentences (`Cannot reach <host> (…).`, `<host> answered HTTP 500.`),
    never a response body.
  * **Generic webhooks** carry `X-EasyPatch-Event` and
    `X-EasyPatch-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256>` over
    `t.body`, keyed with the secret's text as UTF-8
    (`NotificationRenderer.Sign`). The server makes the secret and shows it
    once, and again only by replacing it.
  * **Addresses** (`WebhookAddressPolicy.cs`, `WebhookHttp` in
    `NotificationTransport.cs`): checked on the address actually connected
    to, with no proxy and no redirects. Loopback, link-local, multicast,
    reserved and documentation ranges are refused, and so is **every
    network of the machine's interfaces**. Every service of the deployment
    runs on host networking (`deploy/docker-compose.yml`), so those networks
    are the customer's LAN: a PSA tool on it cannot be reached even with
    private addresses allowed. Private addresses are one switch for every
    channel (`AllowPrivateNetworkWebhooks`).
  * **Secrets** (webhook URLs, signing secrets) are encrypted with ASP.NET
    Data Protection; the worker reads the key ring only to decrypt them
    (`easypatch/backend/Worker/Program.cs`).
  * **Escaping**: HTML email is encoded, Slack's `&`, `<` and `>` are
    escaped, but Teams' `TextBlock`s are Markdown and only square brackets
    in link text are escaped: a host name with Markdown in it is formatted.
  * **Monthly reports** are emailed with their PDF through the same SMTP
    client (`MonthlyReportService.DeliverPendingAsync`; up to 15 MB, only
    over STARTTLS or TLS).
* **EasyRMM's mail server** is `EASYRMM_SMTP_*`, read at start
  (`server/internal/config/config.go`). `server/internal/mailer` sends plain
  text to one recipient, over STARTTLS or TLS with the system's roots,
  unencrypted only to loopback. Invitations and password resets use it;
  without it password reset is off (`auth.Service.ResetAvailable`). EasyRMM
  gives it to the engine at every start (`syncMail`,
  `server/internal/easypatch/engine.go`), so the engine's email and reports
  already go through it. Changing it means editing `.env` and restarting.
* **Audit forwarding** (ADR-0023, `server/internal/auditfwd`) is set up by
  super administrators, can trust a named certificate authority and keeps
  a client key sealed. It dials through `server/internal/netguard`, which
  refuses link-local and two cloud metadata addresses and nothing else,
  because "an integration often runs on the same host or network as
  EasyRMM".
* **Device alerts** (ADR-0019, `server/internal/monitoring`): policies at
  the shared, organization and site levels watch offline, processor,
  memory or disk, with severity warning or critical. `Evaluate` runs every
  minute in one transaction at platform scope under an advisory lock; it
  inserts alerts with `ON CONFLICT DO NOTHING`, resolves with `UPDATE`, and
  returns counts only (`Result{Opened, Resolved, Skipped}` from
  `RowsAffected`), not which alerts. People with `alert.manage` acknowledge
  an alert (it stays active and stops being news) or resolve it by hand (it
  opens again at the next evaluation if its condition holds). Policy
  changes resolve alerts with a reason. Deleting a device deletes its
  alerts (`ON DELETE CASCADE`, migration 00006). A device is offline when
  neither its agent has reported within 3 minutes nor MeshAgent is
  connected.
* **Devices have no tags.** They have an organization, a site, a device
  group, a platform and an operating system's description (migration
  00002); tags are the engine's, on its endpoints. The Windows agent reads
  `InstallationType` (`WindowsInfo.Server`, `agent/host/system_windows.go`)
  but reports nothing of it, and counts only `Server`, not `Server Core`.
* **The agent says nothing when it stops.** The Windows service accepts
  stop and shutdown and handles them alike
  (`agent/cmd/easyrmm-agent/service_windows.go`); on Linux, systemd stops
  it with SIGTERM, and its unit is ordered after `network-online.target`
  (`agent/host/service.go`). `easyrmm-agent uninstall` without `--removal`
  tells the server nothing and says the device "stays listed in the
  EasyRMM console as offline". The only report an agent sends about
  leaving, `POST /api/agent/v1/removed` (ADR-0050), deletes the device
  (`server/internal/agents/removal.go`), so a local uninstall cannot use it.
* **Tenancy and secrets.** Tenant tables force row-level security on the
  `easyrmm.scope_*` settings ([database.md](../database.md)); a transaction
  runs at `database.System` or at a `database.Scope` naming organizations
  and sites. `server/internal/secrets` seals values with
  `EASYRMM_SECRET_KEY` (AES-256-GCM), bound to their row by associated data.
* **The bundle test** (`scripts/e2e/bundle.sh`) runs the deployment and a
  Debian machine with systemd on host networking, never a bridge. The
  import test (`scripts/e2e/import.sh`) imports a standalone EasyPatch 1.10
  with a webhook channel and checks that it decrypts with the old server's
  keys. The contract test (`scripts/contract/easypatch.sh`) starts the
  engine's API only, not its worker.
* **ADR-0052's offline rule**, as written ("count a device as seen no
  earlier than the moment the server began serving agents (its start, or
  the end of a hold) plus 5 minutes"), would resolve open offline alerts
  at every restart: `decide`
  (`server/internal/monitoring/evaluate.go`) resolves an offline alert as
  soon as its condition does not hold, and a device "seen" in the future
  does not meet it. With notifications, every device that was offline
  across an upgrade would send a false *resolved* and, minutes later, a
  second *opened*.

## Decision

### Channels
* **One list, EasyRMM's** (`notification_channels`), of four kinds:
  **email** (1 to 20 recipients), **webhook** (generic JSON, signed),
  **Slack** (incoming webhook) and **Microsoft Teams** (Workflows webhook,
  as the engine uses). Each has a name, unique per owner ignoring case, and
  can be turned off.
* **Owner**: the platform (super administrators) or one organization (its
  administrators). It never changes. An organization's channels and rules
  go with it.
* **Which rules may use which channels**: a rule uses channels of its own
  owner or the platform's; a platform rule only the platform's. The
  database enforces it. Channels and rules carry an owner key that is never
  NULL (the organization's ID, or the nil UUID for the platform, kept equal
  to `organization_id` by a `CHECK`), because a composite foreign key with a
  NULL column is not checked. A rule's link to a channel carries both
  owners, with composite foreign keys to `(rule id, owner)` and
  `(channel id, owner)` and a `CHECK` that the channel's owner is the
  platform or the rule's. A delivery carries its channel's owner by the
  same kind of key, and the organizations its content is about, with a
  `CHECK` that an organization's delivery is about that organization only.
* **Row-level security**, forced: channels, rules and deliveries are read
  and written at platform scope, or in their organization's scope
  (`easyrmm.scope_orgs`; a site assignment gives none). Platform channels
  are also readable in an organization's scope, so that its administrators
  can choose them in rules; the API gives them only a platform channel's
  name and kind. The service checks the permissions under **Who**.
* **Deleting a channel** takes it out of every rule (device rules through
  the foreign key; patching rules through the engine, before the delete)
  and drops its pending deliveries; the dialog names the rules it leaves.
  Turning one off drops its pending deliveries, recorded as not sent.

### The sender
* **The delivery table** (`notification_deliveries`) is the outbox: owner,
  channel, kind (alerts, site outage, notice, report, test), event, the
  message as data (JSON, no secrets), status (pending, sent, failed,
  dropped), attempts, next attempt, last error, and when it was queued and
  sent. Deliveries are queued only in the transaction that decided them
  (**Nothing lost or queued twice**). Ended ones are removed after 30 days.
* **One worker** in the server, under a session-level advisory lock, so
  one server on a database sends. It looks for due deliveries every 5
  seconds and sends up to 8 at once, at most one per channel, and **in
  order per channel**: a channel's later message waits while an earlier
  one is retried, until it is sent or given up, so a ticket is never
  closed before it is opened.
  Database work is in short transactions; nothing is held open across the
  network.
* **Under the destination's scope**: each attempt reads its delivery and
  channel in the channel owner's scope (`database.Scope` with that one
  organization, or platform scope for the platform's), so an
  organization's delivery cannot open another organization's channel or
  its secrets.
* **Retries**, as the engine's: from 1 minute, doubling to an hour; given
  up 24 hours after queueing. Tests give up after 3 attempts.
* **Tests**: one per channel every 30 seconds (`429 test_rate_limited`, as
  the engine answers). A test
  is a delivery like any other, picked up at once; the console shows its
  result as it comes.
* **Errors** are EasyRMM's own sentences naming the host only: never a
  URL's path or query (Slack and Teams URLs carry their secret there) and
  never a response body. A response is read up to 64 KiB and discarded.
* **At least once.** A delivery is queued exactly once, and sent at least
  once: a server that stops between the receiver's answer and recording it
  sends that message again. Webhooks carry `X-EasyRMM-Delivery`, the same
  on every attempt, and an email's `Message-ID` is made from the
  delivery's ID, so a receiver or mail client can drop the copy.
* **The server held** (ADR-0052): while `hold` exists, neither the worker,
  the evaluator nor the engine's collector runs. A rollback that restores
  a backup brings back deliveries pending in it, which may be sent again;
  their IDs are the same.

### A failing channel
* A channel is **failing** once a delivery to it has failed for 15
  minutes without a success since, or was given up; it recovers at its
  next success. Tests do not count.
* **The console raises an alert** to whoever manages the channel: on the
  Alerts page, on the dashboard and as a banner on Settings →
  Notifications, with the last error. An email channel failing at the mail
  server says that the mail server is the problem.
* **It is also an event rules can send** (source *EasyRMM*, below): an
  organization's rule may ask for its own channels' failures and
  recoveries, a platform rule for any channel's. It is never sent to the
  failing channel itself.

### The address policy
For every destination an organization owns: its webhook, Slack and Teams
channels now, its syslog destinations with log forwarding later.

* **Checked on the address dialled**: a `net.Dialer` `Control` function,
  as `netguard` uses, sees each address the dialer tries after name
  resolution, so a name that resolves, or later re-resolves, to a refused
  address is refused. An IPv6 address with an IPv4 address inside
  (IPv4-mapped, NAT64 `64:ff9b::/96`, 6to4 `2002::/16`, IPv4-compatible) is
  checked as both, as the engine does.
* **Always refused**: unspecified and "this network" (`0.0.0.0/8`, `::`),
  loopback, link-local, multicast, broadcast, reserved (`240.0.0.0/4`),
  IETF protocol assignments (`192.0.0.0/24`), documentation
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`),
  benchmarking (`198.18.0.0/15`), discard (`100::/64`), the old site-local
  range (`fec0::/10`), every cloud metadata address `netguard` lists
  (`fd00:ec2::254` and `100.100.100.200`, which lie inside ranges below and
  stay refused when those are approved), and **the server's own
  addresses**: each address of its interfaces, read again every minute.
  Not their networks: on host networking those are the LAN.
* **Private addresses** (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`,
  CGNAT `100.64.0.0/10`, ULA `fc00::/7`) only for a destination a **super
  administrator approved**. An approval names one channel and one or more
  prefixes: proposed are the addresses the channel's host resolves to when
  approval is asked, each as a single address, which the super
  administrator may widen. A delivery may dial a private address only
  inside its own channel's approved prefixes. Changing the URL's host
  clears its approvals. Until approved, deliveries fail with "waiting for
  approval", the channel's alert says so, and super administrators see the
  request in the console. Approvals and their withdrawal are audited.
* **HTTPS only**, TLS 1.2 or later, the host name always verified; **no
  redirects** (an answer of 3xx is a failure); **no proxy** (the
  environment's proxy settings are ignored); no cookies; 10 seconds to
  connect, 30 for the whole request.
* **A certificate authority to trust** (PEM) may be named per destination,
  for receivers with a private certificate; it is then the only trust
  anchor, as for audit forwarding. A self-signed certificate is given as
  its own authority. There is no "do not verify".
* **The platform's own destinations** (platform channels, the mail server,
  audit forwarding, the engine's connection) keep `netguard`'s rule as it
  is: loopback, private addresses and the server's own are allowed,
  link-local and cloud metadata refused. The mail server is now dialled
  through it too (`mailer` dials without it today).
* `netguard` gains the organizations' policy beside its current rule; both
  are tested together.

### The signature
* **Header**: `X-EasyRMM-Signature: t=<unix seconds>,v1=<hex
  HMAC-SHA256(key, t + "." + body)>`, the engine's scheme under EasyRMM's
  name. The key is the secret's text as UTF-8, as the engine uses it, so a
  moved channel's secret verifies the same. With it come
  `X-EasyRMM-Event`, `X-EasyRMM-Delivery` and `Content-Type:
  application/json`. Every attempt is signed anew, with its own `t` and
  `sentAt`.
* **The secret**: 32 random bytes, base64url without padding, made by the
  server. Rotating it replaces it at once, as the engine does.
* **Receivers**, says the guide, compare in constant time and refuse a `t`
  more than 5 minutes from their clock.
* **Transition for receivers of `X-EasyPatch-Signature`**: a channel moved
  from the engine also sends `X-EasyPatch-Signature` and
  `X-EasyPatch-Event`, with the same values, until a super administrator
  turns them off on that channel. The switch can only be turned off; new
  channels never send them. The old headers are removed in a later
  release, announced in the CHANGELOG one release before.
* **The body** keeps every field of the engine's generic body, with its
  meaning: `event`, `deliveryId`, `sentAt`, `subject`, `summary`,
  `alerts[]` (`id`, `severity` as `Info`, `Warning` or `Critical`, `title`,
  `organization`, `details`, `url`, `at`), `moreCount` and `consoleUrl`. It
  adds `source` (`devices`, `patching` or `easyrmm`), and for each alert
  `key`, `status`, `organizationId`, `site`, `siteId`, `device`,
  `deviceId`, `condition`, `openedAt`, `resolvedAt` and `resolution`, and
  `site` with the outage's ID for site events. Events: `alerts.opened`,
  `alerts.reminder`, `alerts.resolved` (the engine's names), `sites.offline`,
  `sites.online`, `channels.failing`, `channels.recovered` and `test`.

### Secrets
* **Sealed** with `EASYRMM_SECRET_KEY` and bound to the channel's ID and
  field: the URL of every webhook, Slack and Teams channel (Slack's and
  Teams' URLs are secrets in themselves), the signing secret, and the
  mail server's password. Never in the audit log (the host is), in logs or
  in errors.
* **Shown again** (as ADR-0047 does for tokens):
  `POST /api/v1/notifications/channels/{id}/reveal` answers the URL and the
  signing secret to whoever manages the channel, with `Cache-Control:
  no-store`, and is audited (`notification_channel.reveal`). Lists show the
  host only.
* **The mail server's password** is write-only: nobody needs it back.
* Rotating `EASYRMM_SECRET_KEY` works as for other sealed values.

### The mail server in the console
* **Settings → Notifications → Mail server**, for super administrators:
  host, port, security (STARTTLS required, TLS from the first byte, or none
  only to loopback, as now), user name, password, sender's address and
  name, and a certificate authority to trust. One row at platform scope.
  It applies at once, without a restart, to notifications, invitations and
  password resets; `ResetAvailable` follows it.
* **`EASYRMM_SMTP_*` still works**: when `EASYRMM_SMTP_HOST` is set, the
  deployment's mail server is used, and the console shows it read-only,
  says that it comes from `.env`, and still sends test messages. Removing
  it from `.env` hands the mail server to the console. One mail server is
  in force at a time, and the console says which.
* **A test message** goes to an address the super administrator enters
  (their own by default), at most one every 30 seconds, and shows the mail
  server's answer.
* **The mailer gains**: HTML with a plain-text alternative
  (`multipart/alternative`); several recipients in one message (a
  recipient the server refuses is reported and the others still receive
  it; all refused is a failure); attachments (monthly reports); the
  sender's name; the trusted authority; and a `Message-ID` from the
  delivery.

### Content
Values that come from agents (device and host names, operating systems)
or from people (names of policies, sites, organizations, channels) are
text, escaped for each format when the message is rendered:

* **Email**: HTML through Go's `html/template`, which escapes by context;
  the plain-text part without control characters. The subject is one
  line, without control characters, at most 200 characters, and encoded.
* **Slack**: Block Kit, with these values in `plain_text` objects, which
  Slack does not format; the notification's fallback `text` has `&`, `<`
  and `>` escaped, so a name can neither link nor mention (`<!channel>`).
* **Teams**: an Adaptive Card with these values in `TextRun`s of a
  `RichTextBlock`, which Teams does not read as Markdown, unlike the
  engine's `TextBlock`s.
* **Generic webhooks**: JSON encoding only.

Links in a message are only EasyRMM's own pages, at its public address,
never taken from a value.

### Device alert rules
* **A rule** belongs to the platform or one organization and has a name,
  an on/off switch, filters, when it notifies, and 1 to 20 channels.
* **Filters**, each *any* or a list: organizations (platform rules only),
  sites, device groups, kind of device (servers, workstations), severity
  (warning, critical) and condition (offline, processor, memory, disk).
  Lists are checked when the rule is saved. An ID that no longer exists
  matches nothing, so deleting a site never widens a rule to every site;
  the console marks the rule. An organization's rule matches only its own
  organization's devices, whatever its lists hold.
* **Instead of tags, device groups**: EasyRMM's devices have no tags. A
  tag filter comes when devices have tags.
* **Kind of device**, from its operating system as the plan says, made
  exact: the agent reports a `role` with its facts, on Windows from
  `InstallationType` (`Client` is a workstation; `Server`, `Server Core`
  and other server values are servers). Without it (an older agent, a
  device known only to MeshCentral) the server reads the operating
  system's description: a Windows one that starts `Windows Server` is a
  server, other Windows a workstation, Linux a server, macOS a
  workstation. A technician with `device.edit` can set a device's kind,
  which wins. A device whose kind is still unknown matches only *any*.
* **When**:
  * **On opening**: at once, or only once the alert has been open N
    minutes (0 to 1,440), on top of the policy's own minutes. An alert
    resolved or acknowledged before then sends nothing.
  * **On resolving**: on or off for email, Slack and Teams. A generic
    webhook told that an alert opened is always told that it resolved.
  * **Reminders** every N hours (0 for never, up to 720) while the alert is
    open and not acknowledged. Acknowledging stops them.
  * **Once told, told to the end**: a channel told that an alert opened is
    told that it resolved even if the rule changed or was deleted since,
    with the resolution: cleared, by hand (and by whom), not covered,
    policy off, changed or deleted, agent uninstalled, or device removed.
    A deleted channel is told nothing more.
* **Maintenance windows, per site**: weekly (days, start, length, in the
  site's time zone, daylight saving included) or once (start and end).
  During one, the site's devices still raise alerts in the console, but
  nothing new is sent about them. When it ends, alerts still open and not
  acknowledged are sent, in one message; those resolved meanwhile are not.
  An alert told before the window began is still told when it resolves.
* **A site goes offline**: when offline alerts open on a site's devices
  and every device of that site that has an EasyRMM agent, is not
  uninstalled and is watched by an enabled offline policy is offline, and
  there are at least two, the site is down (`site_outages`). Channels that
  would have been sent those devices' opened alerts get one item instead,
  "Site X: all 40 devices offline"; devices whose alerts open later during
  the outage are folded into it. It ends when any of them is online again:
  "Site X is back online: 38 of 40 devices", with the device alerts that
  resolved folded in; the devices still offline then are sent as their own
  opened alerts. Generic webhooks get `sites.offline` and `sites.online`
  with the outage's ID and the ID of every alert folded in.
* **Digests**: one message per channel per evaluation. Email, Slack and
  Teams get sections (sites offline and back, new, resolved, still open)
  with at most 25 alerts in all, a count of the rest and a link. Generic
  webhooks get one delivery per event, as the engine sends, with every
  alert, split into deliveries of at most 100: a PSA tool opens a ticket
  per alert, and an alert left out of a count would never be ticketed.
* **For PSA tools**: the alert's `id` is stable from opened through
  reminders to resolved; `key` (policy and device) is the same for every
  alert of one condition on one device, so a tool can tell a recurrence;
  site events have the outage's ID.
* **Sources**: a rule is about device alerts or about *EasyRMM* itself
  (channels failing and recovering now; the upgrades of feature 4b, the
  certificates of 5a and log storage of feature 3 add their events).
  Patching alerts keep the engine's rules (below).

### Nothing lost or queued twice
* `Evaluate`'s `INSERT` and `UPDATE` gain `RETURNING`, and, in the same
  transaction, the planner matches the alerts it opened and resolved
  against the rules, records per alert and channel what is due
  (`alert_notifications`), and queues
  every delivery due now: those just decided; those whose wait or
  maintenance window ended; reminders; site outages; and the resolutions
  of alerts resolved elsewhere since the last evaluation (by hand, by a
  policy change, by an uninstall, or with a removed device: the per-alert
  record has no foreign key to the alert, so a deleted alert is noticed).
  It marks them queued in the same commit. A crash before the commit
  queues nothing and loses nothing; the advisory lock keeps two servers
  from planning at once.
* Changes made in a person's transaction (a resolve by hand, a policy
  change) are sent by the next evaluation, within a minute, rather than
  queued in that transaction, whose scope cannot write the platform's
  deliveries.

### Restarts
* **The server's** (amending ADR-0052): its offline rule delays only the
  opening of offline alerts. None opens until the server has served agents
  for 5 minutes plus the policy's minutes. An open offline alert resolves
  only when its device is online again, never because the server
  restarted. The evaluator does not run while the server is held.
* **A device's planned restart**: before it stops, the agent sends
  `POST /api/agent/v1/stopping`, signed with its device key as every agent
  request, with `{"reason": "shutdown"}` or `{"reason": "stop"}`, waiting
  at most 5 seconds for an answer.
  * **Windows**: the service also accepts pre-shutdown, which Windows gives
    more time than shutdown, and sends `shutdown` on either; `stop` when
    only the service is stopped.
  * **Linux**: on SIGTERM, `shutdown` when systemd says the system is
    stopping (`systemctl is-system-running` answers `stopping`), else
    `stop`. Its unit's ordering after `network-online.target` stops it
    before the network at shutdown.
  * Not when it restarts to update itself or uninstalls itself.
* **The grace period**: after `shutdown`, the device's offline alerts open
  only once it has been silent for the grace (15 minutes by default, 0 to
  120, set by super administrators) or the policy's minutes, whichever is
  longer. The console shows the device as *restarting* meanwhile, and an
  alert that then opens says the device shut down at that time. A `stop`
  gets no grace: the alert says the agent's service was stopped. A notice
  counts once per check-in, so a device cannot keep itself quiet by
  sending them. Older agents send none and get no grace.
* The grace delays the **alert**, not only its notifications, so that the
  console does not show a restarting server as down either.

### *Uninstalled*
* **`easyrmm-agent uninstall`** without `--removal` (and so the removal of
  an agent package, feature 6) removes the service, then sends
  `POST /api/agent/v1/uninstalled` signed with the device key (best
  effort, 10 seconds), then removes its files. It says whether the server
  heard; if not, the device stays offline in the console, to be removed
  there.
* **The server** marks the device *Uninstalled*, audited
  (`device.agent_uninstalled`), and resolves its alerts in the same
  transaction (resolution `uninstalled`). Policies, site outages and rules
  leave it out. Devices shows *Uninstalled*, with the date and a filter;
  removing it deletes it at once, as **Remove anyway** does (ADR-0050),
  without waiting for an agent that is gone.
  A later check-in with its key (an agent restored from a backup) clears
  the mark.
* A removal from the console (ADR-0050) is unchanged; the alerts deleted
  with the device are sent as resolved (`device removed`) by the next
  evaluation.

### The patching engine hands its notifications to EasyRMM
* **The engine keeps deciding when**: `AlertEngine`, its rules, reminders
  and reopening stay. Its rules now name **EasyRMM's channels**: the
  platform's, or that organization's when a rule is limited to one.
  EasyRMM, the engine's only caller (ADR-0048), checks this when a rule is
  saved and again when it takes a notification over; the engine stops
  checking channel IDs against its own table (`ApplyAsync` in
  `NotificationEndpoints.cs` does today). An item for an organization's
  channel with an alert of another organization, or of an engine
  organization linked to none, is refused, recorded and raised as a
  console alert to super administrators.
* **An outbox in the engine**: where `AlertEngine` queued deliveries, it
  writes one item per channel and event per run, with every alert (no
  cap): what each alert says (title, details, severity, organization,
  endpoint, link, times), as plain text. A monthly report to email,
  scheduled or sent by hand, is an item too (the report's ID and its
  recipients).
* **EasyRMM collects**: every 30 seconds it reads
  `GET /api/v1/notifications/outbox`, then acknowledges what it took with
  `POST /api/v1/notifications/outbox/acknowledge`. Each call carries a
  statement (ADR-0038) with subject `service`, role `SuperAdmin`, every
  organization, bound to its method and target; the engine refuses these
  routes to a statement naming a person. EasyRMM records the items' IDs
  (`engine_handoffs`, unique), maps the engine's organizations to its own
  (ADR-0040) and queues the deliveries in one transaction, then
  acknowledges. An acknowledgement lost on the way returns the items once
  more, and their IDs are already taken. The engine drops items not
  collected within 24 hours and says how many in each answer; EasyRMM
  raises a console alert for them.
* **Why EasyRMM pulls**: the engine needs no address or credential for
  EasyRMM, and trust keeps going one way, as ADR-0038 set it, with no new
  key.
* **Rendering is EasyRMM's** for patching too: the formats, escaping,
  signature and digests above. Patching items have `source: patching`.
  Generic webhooks now get every patching alert, not 25 and a count.
* **Monthly reports**: EasyRMM fetches the PDF as its console does
  (`Client.MonthlyReportPDF`) and mails it, up to 15 MB and only over
  STARTTLS or TLS, as the engine did. The delivery log and the report's
  row show how it went.
* **Moving the channels**: at start, and after an import, EasyRMM asks
  `GET /api/v1/notifications/channels/export` (the same statement; the
  engine decrypts with its own key ring and answers `no-store`) for the
  channels still in the engine's table. It creates each as a **platform
  channel with the same ID**, so the engine's rules keep pointing at it,
  with its name (` (patching)` added on a clash), state, recipients or
  format, URL and signing secret sealed with EasyRMM's key, and the
  `X-EasyPatch-*` headers on. Then `POST
  /api/v1/notifications/channels/moved` with their IDs, and the engine
  deletes them. Audited (`notification_channel.moved`), and repeatable:
  an ID already moved is skipped. This is not a SQL migration: the two
  databases are separate and the secrets are sealed with different keys.
  `AllowPrivateNetworkWebhooks` needs no successor, since platform channels
  may reach private addresses. The engine's migration turns its deliveries
  still pending into outbox items, so none is lost across the upgrade.
* **Retired, as ADR-0048 rules** (each test of living behaviour moved
  first):
  * in the engine: `NotificationDispatcher` and its task;
    `NotificationTransport` (its SMTP client and its webhook HTTP client);
    `WebhookAddressPolicy`; the notification settings (SMTP and
    `AllowPrivateNetworkWebhooks`) and the deliveries table; the routes to
    list, create, change, delete, rotate and test channels and to list
    deliveries; emailing reports (`DeliverPendingAsync`); the worker's
    reading of the Data Protection keys.
  * in EasyRMM: `syncMail` and the engine's `Mail` option; the patching
    notification routes, `NotificationsView` and `SetNotificationSettings`;
    the console's Settings → Patching → Notifications.
* **What stays, because something reaches it**: the engine's alert rules
  and alerts, and Settings → Patching → Alert rules, which chooses among
  EasyRMM's channels; the outbox; and the engine's channel table with its
  export route, because an import (ADR-0045) brings channels from a
  standalone EasyPatch, which the move then picks up.

### Tables
All with row-level security forced, on the `easyrmm_scope_*` functions:

| Table | Holds | Read and written |
|---|---|---|
| `notification_channels` | Channels: owner, kind, name, recipients, sealed URL and signing secret, host, trusted authority, the `X-EasyPatch-*` switch, `failing_since`, `last_error`, `last_success_at` | Platform scope, or the organization's (`scope_orgs`); platform rows also readable in an organization's scope |
| `notification_channel_approvals` | Private prefixes approved per channel, who asked, who approved | Read in the channel's scope; an organization's scope may only ask; approving and withdrawing need platform scope |
| `notification_rules`, `notification_rule_filters`, `notification_rule_channels` | Rules, their lists (foreign keys to organizations, sites, device groups) and their channels (the owners' constraint above) | Platform scope, or the organization's; filters and channels follow their rule |
| `notification_deliveries` | The outbox and the delivery log | Platform scope, or the owner's; an organization's scope inserts only its own tests |
| `alert_notifications` | Per alert and channel: what was sent, what is due and when, and the alert as it was (no foreign key to `alerts`) | Platform scope only |
| `site_maintenance_windows`, `site_outages` | Windows; outages and the alerts folded in | Read with their site; windows written in the site's scope, outages at platform scope only |
| `mail_server` | The console's mail server, one row, the password sealed | Platform scope only, as `audit_forwarding` |
| `engine_handoffs` | The engine's items taken | Platform scope only |

`devices` gains `role`, `role_set_by_user`, `agent_stopping_at`,
`agent_stopping_reason` and `agent_uninstalled_at`; `alerts.resolution`
gains `uninstalled`; the grace is a key of `settings`. Every migration goes
into database.md.

### Who
| What | Who |
|---|---|
| An organization's channels and rules: change, test, reveal, the delivery log | `notification.manage` in that organization: Organization Administrators (a new permission, from organization-wide grants only; a site assignment never gives it), and super administrators |
| The platform's channels and rules; approving private destinations; the restart grace | Super administrators |
| The mail server | Super administrators (`settings.manage`) |
| Maintenance windows | `monitoring.manage` at the site (Site Administrators and above); read with `monitoring.view` |
| Patching alert rules | Super administrators, as now (`patch.configure` platform-wide) |
| A failing channel's alert | Whoever manages the channel |

Every change, test, reveal, approval and move is audited.

### The console
* **Settings → Notifications**, a part of its own for whoever holds
  `notification.manage` anywhere:
  * **Channels**: each with its state (sending, failing and why, waiting
    for approval), its last delivery, *Test*, *Show secret*, *Replace
    secret*; super administrators see every organization's, by
    organization, and approve private destinations here.
  * **Rules**, with their filters, when they notify, and channels.
  * **Maintenance windows**, by site.
  * **Delivery log**: 30 days, by channel, status and event.
  * **Mail server** and **planned restarts' grace** (super administrators).
* **Alerts** links to it and lists failing channels; **Devices** shows
  *restarting* and *Uninstalled*. Settings → Patching loses its
  Notifications view; its Alert rules choose among EasyRMM's channels.

### Slices
Each merges, and is verified, on its own:

1. **The mailer and the mail server in the console**: HTML and text,
   several recipients, attachments, the trusted authority, the console's
   settings and `.env`'s precedence, the test message; invitations and
   resets through it; `syncMail` gives the engine the mail server in
   force, until slice 6. *Verified*: a test message from the console
   arrives in Mailpit in the bundle test.
2. **Channels, the sender and the address policy**, with email and generic
   webhooks: tables, row-level security and the constraint, retries,
   tests, reveal, approvals, failing channels in the console. *Verified*:
   tests to an organization's webhook in its own network namespace,
   refused until approved, then signed and received; an email channel's
   test in Mailpit.
3. **Device alert rules** (feature 7): rules and filters, the agent's
   `role`, when they notify, reminders, maintenance windows, site outages,
   digests, `RETURNING` and the planner, ADR-0052's offline rule as amended.
   *Verified*: a device goes offline, the signed webhook and the email
   arrive; it comes back, the resolutions arrive.
4. **Planned restarts and *Uninstalled***: the agent's two notices and the
   grace. *Verified*: a restart within the grace sends nothing; a local
   uninstall shows *Uninstalled* and sends the resolution.
5. **Slack and Teams**. *Verified* by hand on real ones.
6. **Patching through EasyRMM**: the engine's outbox, the collector, moving
   the channels, report emails, everything retired. *Verified*: the
   contract and import tests; a patching alert reaches a webhook in the
   bundle test.

Until slice 6, patching's notifications still go out through the engine.

## Testing
* **Integration** (PostgreSQL, with the race detector and coverage
  floors for the new packages):
  * rules: each filter, an organization's rule never matching another's
    devices, a deleted site matching nothing, the kind of device and its
    override;
  * timing: a wait that the alert outlives and one it does not,
    acknowledgement before the wait ends, reminders and their end, a
    rule deleted after an alert was sent and its resolution still sent;
  * maintenance windows, weekly and once, across a daylight saving change
    in the site's zone, and the message at their end;
  * site outages: all down, one never enrolled, one uninstalled, one coming
    back first, a straggler, and devices still offline when it ends;
  * digests: 25 and a count for people, every alert in deliveries of 100
    for generic webhooks;
  * the sender: retries on a fake clock, giving up, order per channel,
    the test rate, the failing alert and its recovery;
  * the address policy: every range in both policies, embedded IPv4, the
    server's own addresses, an approval and a host change clearing it, a
    name that resolves first to a public and then to a private address;
  * the database: an organization's rule refused a link to another
    organization's channel, and an organization's delivery about another
    organization refused, with the service's checks bypassed; row-level
    security between two organizations, the worker in one organization's
    scope unable to read another's channel;
  * the transaction: a failure injected after the alerts' changes and
    before the commit leaves neither alerts nor deliveries; two servers
    evaluating at once queue each delivery once;
  * sealed values copied to another row do not open; every reveal is
    audited;
  * the offline rule after a restart: an open offline alert stays open, no
    new one opens early;
  * the engine's handover against `eptest`: an item taken once, an
    acknowledgement lost, an organization not linked.
* **Rendering**: golden messages for each format and event, with device
  names carrying HTML, Slack's `<!channel>`, Markdown and control
  characters; signatures checked against a vector computed by the engine's
  `NotificationRenderer.Sign`.
* **HTTP API and console**: permissions for each route; the console's
  tests for every view.
* **Agent**: the notices' reasons from systemd's state (Linux), from the
  service's controls (Windows unit tests), the uninstall's report; on CI's
  Windows runner, a service stop sends `stop`. Pre-shutdown on real Windows
  is checked by hand on the owner's computers, and marked unverified until
  then.
* **The bundle test**, in a job of its own reusing the images built once:
  * **Mailpit**, on host networking, offering STARTTLS with a certificate
    from an authority made for the run, which the mail server names.
  * **A webhook receiver** (a small HTTPS server written for the test,
    recording each request) in a **network namespace of its own**, joined
    to the host by a **veth pair**: no bridge and no Docker network. The
    script picks a /30 from `10.0.0.0/8` that the runner does not route,
    gives the host's end the first address and the namespace the second,
    and runs the receiver with `ip netns exec`, its certificate made for
    that address by the run's authority.
  * **The story**: an organization's webhook to the receiver is refused
    (private, not approved) and its channel shows failing; a super
    administrator approves it; its test arrives, signed with the secret
    the console reveals. An organization's webhook to `127.0.0.1` and to
    the host's own address is refused. A rule sends the organization's
    offline alerts (an offline policy of 3 minutes) to the webhook and an
    email channel; the machine's agent is stopped; the signed
    `alerts.opened` and the email arrive; it starts again; the resolutions
    arrive. With slice 4: the machine is restarted within the grace and
    nothing is sent; the agent is uninstalled and the device shows
    *Uninstalled*. With slice 6: a patching alert from the engine arrives
    at the same receiver.
* **The contract test** starts the engine's worker beside its API: a
  patching alert on a rule naming an EasyRMM channel appears in the
  outbox; acknowledged, it does not appear again; a report sent by hand
  appears as an item; the export answers a channel with its secrets and
  forgets it once moved; the retired routes answer 404; a statement naming
  a person is refused on these routes; `eptest`'s answers are recorded
  from the real engine.
* **The import test**: the standalone EasyPatch's webhook becomes an
  EasyRMM platform channel with the same ID and secret, and a test to it
  carries both signatures, each valid.
* **Slack and Teams** by hand: a real Slack workspace and a real Teams
  Workflows webhook, with a device whose name carries markup; the messages
  and the date recorded in IMPLEMENTATION_STATUS.

## Consequences
* An MSP sets up its email lists, Teams, Slack and PSA webhooks once, for
  device alerts, patching and EasyRMM's own problems; customers'
  administrators set up their own, for their organization only.
* There is one SMTP client and one HTTP client for notifications, one
  address policy, one renderer. Until slice 6, there are two senders.
* Webhooks are delivered at least once; receivers drop copies by
  `deliveryId`. Queueing is exactly once.
* Organizations' administrators can have the server make HTTPS requests:
  to public addresses only, unless a super administrator approved a
  private one for that channel. The platform's destinations may reach
  loopback, private addresses and the server's own networks, as audit
  forwarding may today; the engine's webhooks never reached loopback or
  the server's own networks, and private addresses only with its switch.
* More secrets rest on `EASYRMM_SECRET_KEY`: channels' URLs and signing
  secrets, and the mail server's password when it is set in the console.
* Receivers of the engine's webhooks keep working through the transition;
  they get every alert instead of 25 and a count, and the body gains
  fields. Teams messages no longer format names as Markdown.
* Offline alerts no longer resolve and open again across a restart of the
  server; a restarting device does not alert within the grace, and a
  local administrator who shuts a computer down delays its offline alert
  by the grace once.
* Rules cannot filter by tag until devices have tags.
* The engine keeps a channel table and its export route for imports;
  everything else of its notification sending goes.
* `alerts.resolution` gains `uninstalled`; devices gain their kind and
  their *Uninstalled* and *restarting* states; database.md, the guide,
  rbac.md, IMPLEMENTATION_STATUS, ROADMAP and the CHANGELOG change with
  each slice.

## Risks
* **The server as a way into a customer's network.** An organization's
  administrator can make the server send HTTPS requests. Every dialled
  address is checked, private ones need a super administrator's approval
  for that channel alone, and the server's own addresses, loopback and
  cloud metadata are never reached; no redirect, proxy or response body
  gets back to the person who set the channel up.
* **A storm**: a power cut at a large site, or EasyRMM's own outage. Site
  outages, digests per evaluation, ADR-0052's offline rule and the restart
  grace keep it to a few messages per channel.
* **One bad receiver delays its own channel only.** Order per channel
  holds a channel's later messages behind a failing one for up to 24
  hours; other channels are not held, and the channel shows failing within
  15 minutes.
* **A message sent twice** after a crash or a rollback: receivers drop it
  by its delivery ID; the guide says so.
* **A mail server set wrong in the console** stops notifications,
  invitations and password resets at once. The test message comes first in
  the form, the failing channels' alert says the mail server is the
  problem, and `EASYRMM_SMTP_*` in `.env` takes over when set.
* **Windows' pre-shutdown** is unverified until it is checked on real
  Windows; until then a restarting Windows computer may alert as a plain
  stop would.
* **Slice 6 changes two products at once.** The engine and EasyRMM ship in
  one bundle; the engine's migration keeps its pending deliveries as
  outbox items, and EasyRMM collects only once the channels have moved, so
  every item finds its channel and nothing is sent by both or by neither.
