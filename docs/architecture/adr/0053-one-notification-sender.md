# ADR-0053: One notification sender, and notifications for device alerts

* Status: Proposed (2026-11-21). Not implemented.
* Revised after an independent review (2026-11-21), with the owner's
  decisions on sharing platform channels, `alerts.acknowledged`, `.env`'s
  mail server and the old signature headers.
* Builds on: [ADR-0019](0019-monitoring-and-alerts.md) (monitoring and
  alerts), [ADR-0023](0023-audit-forwarding.md) (audit forwarding and the
  address rule of the platform's integrations),
  [ADR-0038](0038-statements-to-the-patching-engine.md) (statements to the
  engine), [ADR-0040](0040-one-set-of-organizations.md) (one set of
  organizations), [ADR-0045](0045-importing-a-standalone-easypatch.md)
  (imports), [ADR-0047](0047-tokens-shown-again.md) (secrets shown again)
  and [ADR-0048](0048-the-engine-keeps-what-is-reached.md) (nothing left
  that nothing reaches).
* Amends: [ADR-0050](0050-removing-a-device.md): a removal report the server
  did not ask for marks the device instead of deleting it (see
  ***Uninstalled***). [ADR-0052](0052-the-host-updater.md): its offline rule
  delays the opening of offline alerts only (see **Restarts**), and its
  rollback says what it does to alerts already sent (see **Retention**).
* Part of [the feature plan](../feature-plan.md): F2 and feature 7. Where
  this ADR departs from the plan, the plan lists it.

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
  only; channels are server-wide. Their names are neither unique nor longer
  than 100 characters (`EasyPatchDbContext.cs`); recipients are checked
  with MimeKit (`NotificationEndpoints.IsEmail`).
  * **Deciding**: `AlertEngine` (worker task `alerts`, every 2 minutes)
    opens and resolves patching alerts and queues one delivery per channel
    and kind (opened, resolved, reminder) per run, with at most 25 alerts
    and a count of the rest, for every format, the generic one included.
    It sends only to a rule's channels that are enabled in its own table
    (`channels` and `targets` in `EvaluateAsync`). Some changes are silent:
    alerts whose rule is off or gone, whose organization is inactive or
    whose endpoint is gone are resolved without a message; one resolved
    less than an hour ago reopens, with the same ID, without a message; and
    resolutions are sent only when the rule's `NotifyOnResolve` is on.
  * **Sending**: `NotificationDispatcher` (task `notifications`, every 30
    seconds; each worker task runs under its own advisory lock) takes up to
    50 due deliveries a run within 25 seconds, retries from 1 minute
    doubling to an hour, and gives up after 24 hours (tests after 3
    attempts). One test per channel every 30 seconds
    (`NotificationEndpoints.TestInterval`, `429 test_rate_limited`); the
    test's text names the channel (`AlertEngine.TestMessage`). Webhook
    errors are its own sentences naming the host (`Cannot reach <host>
    (…).`, `<host> answered HTTP 500.`), never a response body; SMTP
    errors include the mail server's reply, clipped
    (`NotificationTransport.cs`).
  * **Generic webhooks** carry `X-EasyPatch-Event` and
    `X-EasyPatch-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256>` over
    `t.body`, keyed with the secret's text as UTF-8
    (`NotificationRenderer.Sign`). The secret is 32 random bytes in
    base64url without padding (`NotificationSecrets.NewSigningSecret`),
    shown once, and again only by replacing it.
  * **Addresses** (`WebhookAddressPolicy.cs`, `WebhookHttp` in
    `NotificationTransport.cs`): checked in the handler's `ConnectCallback`
    on the address actually connected to, with no proxy and no redirects.
    Loopback, link-local, multicast, reserved and documentation ranges are
    refused, and so is **every network of the machine's interfaces**
    (`LocalNetworks`). Every service of the deployment runs on host
    networking (`deploy/docker-compose.yml`), so those networks include the
    customer's LAN. Private addresses are one switch for every channel
    (`AllowPrivateNetworkWebhooks`), passed per request; one handler serves
    every channel and pools connections for 2 minutes, so the check does
    not run again for a request that reuses a connection.
  * **Secrets** (webhook URLs, signing secrets) are encrypted with ASP.NET
    Data Protection. A secret the key ring cannot decrypt fails with "enter
    the secret again if the keys were lost" (`NotificationSecrets.Unprotect`).
    The SMTP client can skip certificate validation but cannot trust a
    named certificate authority.
  * **Escaping**: HTML email is encoded, Slack's `&`, `<` and `>` are
    escaped, but Teams' `TextBlock`s are Markdown and only square brackets
    in link text are escaped: a host name with Markdown in it is formatted.
  * **Monthly reports** are emailed with their PDF through the same SMTP
    client (`MonthlyReportService.DeliverPendingAsync`; up to 15 MB, only
    over STARTTLS or TLS), which records the outcome on the report
    (`DeliveryStatus`, `SentAt`, `LastError`).
* **EasyRMM's mail server** is `EASYRMM_SMTP_*`, read at start
  (`server/internal/config/config.go`). `server/internal/mailer` sends plain
  text to one recipient, over STARTTLS or TLS with the system's roots,
  unencrypted only to loopback, and dials without `netguard`. Invitations
  and password resets use it; without it password reset is off
  (`auth.Service.ResetAvailable`). EasyRMM gives it to the engine **once
  per start** (`syncMail`, `server/internal/easypatch/engine.go`), so the
  engine's email and reports already go through it.
* **Audit forwarding** (ADR-0023, `server/internal/auditfwd`) is set up by
  super administrators, can trust a named certificate authority and keeps
  a client key sealed. It dials through `server/internal/netguard`, whose
  `Control` refuses link-local and two cloud metadata addresses and nothing
  else, because "an integration often runs on the same host or network as
  EasyRMM". It unmaps IPv4-mapped addresses only, and has no context: it
  cannot tell one caller's policy from another's.
* **Device alerts** (ADR-0019, `server/internal/monitoring`): policies at
  the shared, organization and site levels watch offline, processor,
  memory or disk, with severity warning or critical. `Evaluate` runs every
  minute in one transaction at platform scope under an advisory lock; it
  inserts alerts with `ON CONFLICT DO NOTHING`, resolves with `UPDATE`, and
  returns counts only (`Result{Opened, Resolved, Skipped}` from
  `RowsAffected`), not which alerts. People with `alert.manage` acknowledge
  an alert or resolve it by hand. Changing a policy's condition resolves
  its alerts (`policy_changed`, `reconcile` in `evaluate.go`, called from
  `UpdatePolicy`), and the next evaluation opens new ones with new IDs.
  Deleting a device deletes its alerts (`ON DELETE CASCADE`, migration
  00006); purging deletes resolved alerts after `EASYRMM_ALERT_RETENTION`
  (`Service.Purge`). A device is offline when neither its agent has
  reported within 3 minutes (`devices.AgentOnlineWindow`) nor MeshAgent is
  connected; offline policies are at least 3 minutes.
* **Devices have no tags.** They have an organization, a site, a device
  group, a platform and an operating system's description (migration
  00002). The agent describes Windows by its `ProductName`
  (`agent/host/system_windows.go`); MeshCentral's `osdesc` fills it for
  devices only MeshCentral knows (`server/internal/remote/service.go`), as
  in "Microsoft Windows Server …". The agent reads `InstallationType`
  (`WindowsInfo.Server`) but reports nothing of it. Free text from agents
  is clipped and stripped of control characters (`clean` in
  `server/internal/agents/service.go`: host names up to 255 runes,
  operating systems up to 500), but not of format characters such as
  bidirectional overrides.
* **The agent says nothing when it stops.** The Windows service accepts
  stop and shutdown and handles them alike
  (`agent/cmd/easyrmm-agent/service_windows.go`); on Linux, systemd stops
  it with SIGTERM, and its unit is ordered after `network-online.target`
  (`agent/host/service.go`). `easyrmm-agent uninstall` without `--removal`
  tells the server nothing. The removal report,
  `POST /api/agent/v1/removed` (ADR-0050), deletes the device whether or
  not a removal was asked for (`Service.Removed` in
  `server/internal/agents/removal.go` records `removalCanceled` when none
  is pending): an agent's key alone can make a device disappear.
* **Tenancy and secrets.** Tenant tables force row-level security on the
  `easyrmm.scope_*` settings ([database.md](../database.md)).
  `auth.DataScope` puts every organization-wide assignment's organization
  in `scope_orgs`, Read-Only included: row-level security bounds the
  organization, and the services check the permission.
  `rbac.Principal.Can` treats the nil UUID as "the platform".
  `server/internal/secrets` seals values with `EASYRMM_SECRET_KEY`
  (AES-256-GCM), bound to their row by associated data. Journals written by
  triggers in whatever transaction deletes something already exist
  (`easypatch_forgotten`, `easypatch_removals`, migration 00020: inserted
  from any scope, read only at platform scope).
* **The database pool** closes idle connections after 5 minutes
  (`server/internal/database/database.go`).
* **The bundle test** (`scripts/e2e/bundle.sh`) runs the deployment and a
  Debian machine with systemd on host networking, never a bridge, and
  checks that nothing but the edge listens beyond loopback. The import
  test seeds a standalone EasyPatch 1.10 with a webhook to
  `https://hooks.import.test/patching`, which does not resolve: it proves
  the keys came across by the error that follows decryption
  (`server/internal/easypatch/import_bundle_test.go`). The contract test
  (`scripts/contract/easypatch.sh`) starts the engine's API only, not its
  worker.
* **ADR-0052's offline rule**, as written ("count a device as seen no
  earlier than the moment the server began serving agents (its start, or
  the end of a hold) plus 5 minutes"), would resolve open offline alerts
  at every restart: `decide` (`server/internal/monitoring/evaluate.go`)
  resolves an offline alert as soon as its condition does not hold, and a
  device "seen" in the future does not meet it. With notifications, every
  device that was offline across an upgrade would send a false *resolved*
  and, minutes later, a second *opened*.

## Decision

### Channels, and who may use them
* **One list, EasyRMM's** (`notification_channels`), of four kinds:
  **email** (1 to 20 recipients), **webhook** (generic JSON, signed),
  **Slack** (incoming webhook) and **Microsoft Teams** (Workflows webhook,
  as the engine uses). Each has a name of at most 100 characters, unique
  per owner ignoring case, and can be turned off.
* **Owner**: the platform (super administrators) or one organization (its
  administrators). It never changes. An organization's channels and rules
  go with it.
* **Sharing** (the owner's decision): an organization's rules use its own
  channels, and a platform channel only once a super administrator has
  shared that channel with that organization
  (`notification_channel_shares`). Nothing is shared by default. Sharing
  and unsharing are audited; unsharing takes the channel out of that
  organization's rules, and a rule left without channels is marked. An
  organization's administrators see a shared channel's name and kind only.
* **The database enforces it.**
  * Channels and rules carry an owner key that is never NULL: the
    organization's ID, or the nil UUID for the platform, kept equal to
    `organization_id` by a `CHECK`. `organization_id` is never the nil UUID
    (`CHECK`), and `organizations` gains `CHECK (id <> nil)`, because
    `rbac.Principal.Can` reads the nil UUID as the platform.
  * A rule's link to a channel (`notification_rule_channels`) has
    `rule_owner` and `channel_owner` `NOT NULL`, composite foreign keys to
    `(rule id, owner)` and `(channel id, owner)`, and `share_org`, with a
    composite foreign key `(channel id, share_org)` to the shares. A
    `CHECK` allows either `channel_owner = rule_owner` with `share_org`
    NULL, or a platform channel in an organization's rule with
    `share_org = rule_owner`, so that the share must exist. The share key
    is the only one allowed to be NULL, and only where no share is needed.
  * A share's own composite foreign key to `(channel id, owner)` with
    `owner = nil` (`CHECK`) admits only platform channels.
  * A delivery carries its channel's owner by a composite key too, and the
    organizations it is about, which the planner derives from its items,
    with a `CHECK` that an organization's delivery is about that
    organization only. A platform channel's delivery (shared or not) is the
    platform's.
* **Row-level security**, forced:
  * channels: platform scope; an organization's own in its scope
    (`scope_orgs`); a platform channel also in the scope of an
    organization it is shared with.
  * Sealed values live apart, in `notification_channel_secrets`, read and
    written at platform scope or in the channel's own organization's scope,
    with no exception for platform rows: no organization's transaction can
    read a platform channel's URL or secret. Only the sender and *reveal*
    open them; reveal checks `notification.manage`, since `scope_orgs`
    includes Read-Only users' organizations.
  * Rules and deliveries: platform scope, or the owner's.
* **Deleting a channel** takes it out of every rule (device rules through
  the foreign keys; patching rules through the engine, see below) and drops
  its pending deliveries; the dialog names the rules it leaves. Turning one
  off drops its pending deliveries, recorded as not sent.

### The sender
* **The outbox** (`notification_deliveries`): owner, channel (none for a
  report), kind (alerts, site outage, notice, report, test), event, the
  message as data (JSON, no secrets), status (pending, sent, failed,
  dropped), attempts, next attempt, a lease, the last error, and when it
  was queued and ended. Deliveries are queued only by the transaction that
  plans them (**Nothing lost or queued twice**).
* **One worker per server, one sending.** The worker holds one connection
  taken from the pool for its whole life (the pool closes idle ones after
  5 minutes) and a session advisory lock on it. If the connection is lost,
  it stops sending and takes the lock again. Each delivery is also
  **leased**: an `UPDATE` sets `lease_until` (now plus the request's
  timeout plus a minute) only where no lease is current, so two servers
  during a failover never send the same delivery at once.
* **Fair share.** Webhooks have 8 slots and email 4, so a slow mail server
  never holds a webhook back. Slots go round-robin over owners, at most 2
  in flight per owner and 1 per channel, so one organization's slow
  receivers cannot take every slot.
* **Under the destination's scope**: each attempt reads its delivery,
  channel and sealed values in the channel owner's scope (`database.Scope`
  with that one organization, or platform scope), so an organization's
  delivery cannot open another's channel.
* **In order per channel, with limits.** A channel's later message waits
  while an earlier one is retried, so a ticket is never closed before it
  is opened, but only for **transient** failures: no connection, a TLS
  failure, a timeout, `408`, `425`, `429` (its `Retry-After` honoured, up to
  an hour) and `5xx`; for email, `4xx` replies.
  * **Permanent** answers fail the message at once: `400`, `401`, `403`,
    `404`, `410`, `413`, `422` and any other `4xx`; for email, a `5xx` reply
    (per recipient). `401`, `403`, `404` and `410` mark the channel failing
    at once; the others after 3 messages in a row.
  * **One message holds its channel for at most an hour.** After that,
    later messages pass, the channel is failing, and the held one keeps
    being retried behind them; items about an alert the held message
    carries are split off into a delivery that waits behind it, so order
    is still kept per alert.
  * A successful test retries the held message at once.
* **Retries**, as the engine's: from 1 minute, doubling to an hour; given
  up 24 hours after queueing. Tests give up after 3 attempts.
* **Tests** go at once, ahead of the channel's queue, at most one per
  channel every 30 seconds (`429 test_rate_limited`, as the engine
  answers). The text is fixed, EasyRMM's own: no channel name and nothing
  anyone typed.
* **The mail server's circuit**: after 5 failures in a row to connect or
  sign in, email pauses for 1 minute, doubling to 15, with one message
  tried at a time; attempts are not counted while paused (the 24 hours
  still run). Webhooks go on.
* **Quotas per organization**, changeable per organization by super
  administrators: 20 channels, 50 rules, 20 tests an hour and 600
  deliveries an hour. Deliveries over the hourly quota wait for the next
  hour, never dropped; reaching any quota raises a notice (below) to the
  organization's managers and to super administrators. The platform has
  none.
* **Errors** are EasyRMM's own sentences naming the host: never a URL's
  path or query (Slack and Teams URLs carry their secret there; Go's
  `*url.Error` prints the whole URL, so it is unwrapped to its cause) and
  never a webhook's response body. A response is read up to 64 KiB and
  discarded. The mail server's reply is kept apart and shown to super
  administrators only; an organization sees "the mail server refused the
  message".
* **At least once.** A delivery is queued exactly once, and sent at least
  once: a server that stops between the receiver's answer and recording it
  sends that message again. Webhooks carry `X-EasyRMM-Delivery`, the same
  on every attempt, and each email's `Message-ID` is made from the
  delivery's ID and the recipient, so a receiver or mail client can drop
  the copy.
* **The server held** (ADR-0052): while `hold` exists, neither the worker,
  the evaluator, the planner nor the engine's collector runs.

### Notices: a failing channel, and the platform's other problems
* **Notices** (`notices`) are what the console raises that is not a
  policy's condition on a device: a failing channel, a quota reached, a
  rule left without channels or with an emptied list, patching items
  refused or dropped, an event the planner quarantined, a maintenance
  window starting and ending, an agent removed without a request. Each
  has a kind, the platform or one organization, optionally a site and a
  device, when it opened, and when it was acknowledged or resolved.
* **A channel is failing** once a delivery to it has failed for 15 minutes
  without a success since, has been given up, or has a permanent answer
  as above; it recovers at its next success. Tests do not count.
* **Shown** on the Alerts page (a section of their own), on the dashboard,
  and as a banner on Settings → Notifications, to whoever manages what the
  notice is about; a notice about a device to whoever sees the device.
* **Sent** by rules like alerts (source *EasyRMM*): an organization's rule
  gets its own organization's notices, a platform rule any. A failing
  channel's notice is never sent to that channel. The one notice about a
  device, *agent removed without a request*, is a condition of device
  rules instead, with their filters.

### The address policy
For every destination an organization owns: its webhook, Slack and Teams
channels now, its syslog destinations with log forwarding later.

* **Checked on every connection dialled**: the dialer's `ControlContext`
  sees each address tried after name resolution, so a name that resolves,
  or re-resolves, to a refused address is refused. The policy and the
  channel's approved prefixes come from the request's context; without
  them the check refuses.
* **No connection serves two policies.** Each channel has its own
  `http.Transport`, built for its host and port, its policy, its
  approval's generation and its trusted authority; a change to any of them
  replaces it and closes the old one's idle connections
  (`CloseIdleConnections`). An organization's transports do not keep
  connections alive (`DisableKeepAlives`), so every request dials, and is
  checked, anew. A platform channel's connections are never reused by
  another channel, nor an approved one's by another organization.
* **Embedded IPv4** (IPv4-mapped, NAT64 `64:ff9b::/96`, 6to4 `2002::/16`,
  IPv4-compatible) is checked as both addresses, in both policies:
  `netguard` gains the normalisation it lacks.
* **Always refused**:
  * unspecified and "this network" (`0.0.0.0/8`, `::`), loopback,
    link-local, multicast, broadcast, reserved (`240.0.0.0/4`), IETF
    protocol assignments (`192.0.0.0/24`), documentation
    (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`,
    `2001:db8::/32`), benchmarking (`198.18.0.0/15`), discard
    (`100::/64`), the old site-local range (`fec0::/10`);
  * every cloud metadata address `netguard` lists (`fd00:ec2::254` and
    `100.100.100.200`, which lie inside ranges below and stay refused when
    those are approved);
  * **the server itself**: each address of its interfaces; the addresses
    in `EASYRMM_IP_ADDRESSES`; and the deployment's names
    (`EASYRMM_PUBLIC_URL`'s and `EASYRMM_MESH_PUBLIC_URL`'s hosts and the
    further names `validateExtraHostnames` checks), refused as a URL's host
    and by the addresses they resolve to. Behind NAT or a proxy, the
    server's public address is not on its interfaces; its names cover it.
    All of these are read again every minute.
* **Only once approved**: private addresses (`10.0.0.0/8`,
  `172.16.0.0/12`, `192.168.0.0/16`, CGNAT `100.64.0.0/10`, ULA
  `fc00::/7`) and **every network on the server's own interfaces**,
  whatever its kind: a public IPv4 subnet or a global IPv6 prefix on the
  server's LAN is no safer than a private one. Interfaces are read again
  every minute.
* **An approval** names one channel, its host and port, and one or more
  prefixes; proposed are the addresses the host resolves to when approval
  is asked, each as a single address, which the super administrator may
  widen. A delivery may dial such an address only inside its own
  channel's approved prefixes. Changing the URL's host or port clears the
  approval. Until approved, deliveries fail with "waiting for approval",
  the channel's notice says so, and super administrators see the request
  in the console. Approvals and their withdrawal are audited; withdrawal
  replaces the channel's transport at once.
* **HTTPS only**, TLS 1.2 or later, the host name always verified; **no
  redirects** (an answer of 3xx is a failure); **no proxy** (`Proxy: nil`;
  the environment's proxy settings are ignored); no cookies; 10 seconds to
  connect, 30 for the whole request.
* **A certificate authority to trust** (PEM) may be named per destination,
  for receivers with a private certificate; it is then the only trust
  anchor, as for audit forwarding. A self-signed certificate is given as
  its own authority. There is no "do not verify".
* **The platform's own destinations** (platform channels, the mail server,
  audit forwarding, the engine's connection) keep `netguard`'s rule:
  loopback, private addresses and the server's own are allowed,
  link-local and cloud metadata refused, now with embedded IPv4 checked.
  The mail server is dialled through it too.

### The signature
* **Header**: `X-EasyRMM-Signature: t=<unix seconds>,v1=<hex
  HMAC-SHA256(key, t + "." + body)>`, the engine's scheme under EasyRMM's
  name. The key is the secret's text as UTF-8, as the engine uses it, so a
  moved channel's secret verifies the same. With it come
  `X-EasyRMM-Event`, `X-EasyRMM-Delivery` and `Content-Type:
  application/json`. Every attempt is signed anew, with its own `t` and
  `sentAt`.
* **The secret**: 32 random bytes, base64url without padding, made by the
  server, as the engine's. Rotating it replaces it at once.
* **Receivers**, says the guide, compare in constant time and refuse a `t`
  more than 5 minutes from their clock.
* **Transition for receivers of `X-EasyPatch-Signature`**: a channel moved
  from the engine also sends `X-EasyPatch-Signature` and
  `X-EasyPatch-Event`, with the same values, until a super administrator
  turns them off on that channel; the switch can only be turned off, and
  new channels never send them. The headers' removal is announced in one
  release's CHANGELOG and done in the next (the owner's decision; no
  release is fixed now).
* **The body** keeps every field of the engine's generic body, with its
  meaning: `event`, `deliveryId`, `sentAt`, `subject`, `summary`,
  `alerts[]` (`id`, `severity` as `Info`, `Warning` or `Critical`, `title`,
  `organization`, `details`, `url`, `at`), `moreCount` (now always 0 for
  generic webhooks) and `consoleUrl`. It adds `source` (`devices`,
  `patching` or `easyrmm`), and for each alert `alertId`, `key`, `status`,
  `organizationId`, `site`, `siteId`, `device`, `deviceId`, `condition`,
  `openedAt`, `acknowledgedAt`, `resolvedAt` and `resolution`; `site` with
  the outage's ID for site events; `notice` for notices.
* **Events**: `alerts.opened`, `alerts.reminder`, `alerts.resolved` (the
  engine's names), `alerts.acknowledged` (the owner's decision, for PSA
  tools: generic webhooks only), `sites.offline`, `sites.online`,
  `notices.opened`, `notices.resolved` and `test`.

### Secrets
* **Sealed** with `EASYRMM_SECRET_KEY` in `notification_channel_secrets`
  and bound to the channel's ID and field: the URL of every webhook, Slack
  and Teams channel (Slack's and Teams' URLs are secrets in themselves) and
  the signing secret; the mail server's password in `mail_server`. Never in
  the audit log (the host is), in logs or in errors; a test feeds URLs with
  a path and a query through every failure and checks that neither logs
  nor `last_error` hold them.
* **Shown again** (as ADR-0047 does for tokens):
  `POST /api/v1/notifications/channels/{id}/reveal` answers the URL and the
  signing secret to whoever manages the channel, with `Cache-Control:
  no-store`, and is audited (`notification_channel.reveal`). Lists show the
  host only. A shared platform channel is never revealed to an
  organization.
* **The mail server's password** is write-only: nobody needs it back.
* Rotating `EASYRMM_SECRET_KEY` works as for other sealed values.

### The mail server in the console
* **Settings → Notifications → Mail server**, for super administrators:
  host, port, security (STARTTLS required, TLS from the first byte, or none
  only to loopback, as now), user name, password, sender's address and
  name. One row at platform scope (`mail_server`). It applies at once,
  without a restart, to notifications, invitations and password resets;
  `ResetAvailable` follows it.
* **`EASYRMM_SMTP_*` wins** (the owner's decision): when
  `EASYRMM_SMTP_HOST` is set, the deployment's mail server is used, and the
  console shows it read-only, says that it comes from `.env`, and still
  sends test messages. Removing it from `.env` hands the mail server to the
  console. One mail server is in force at a time, and the console says
  which.
* **The engine follows at once**: until slice 6 retires its email,
  `syncMail` gives the engine the mail server in force at start **and on
  every change**, not once per start.
* **A certificate authority to trust** is shown only once the engine no
  longer sends email (slice 6): the engine cannot trust a named
  authority, only skip verification, which EasyRMM never asks of it.
* **A test message** goes to an address the super administrator enters
  (their own by default), at most one every 30 seconds, and shows the mail
  server's answer.
* **Several recipients, each their own copy**: one SMTP session per
  delivery, one message per recipient with only that recipient in `To`,
  so recipients never see each other (a shared platform channel's
  recipients are not disclosed to anyone) and no header grows past the
  line limit. A recipient the server refuses is recorded and shown on the
  delivery and the channel; the others still receive it; all refused is a
  failure.
* **The mailer gains**: HTML with a plain-text alternative
  (`multipart/alternative`), attachments (monthly reports), the sender's
  name, the trusted authority, and the `Message-ID` above.

### Content
Values that come from agents (device and host names, operating systems)
or from people (names of policies, sites, organizations, channels) are
text, made safe for each format when the message is rendered:

* **Cleaned**: control characters (Cc) and format characters (Cf:
  bidirectional overrides, zero-width characters) are removed.
* **Clipped**: device and host names to 64 characters, operating systems
  to 100, other names to 100, with "…".
* **Never a link**: in email, Slack and Teams, a value that contains
  something a client would link (a scheme and `://`, a `www.` name, a
  dotted name ending in letters, an e-mail address) has it defanged:
  `.` becomes `[.]`, `@` becomes `[@]` and `://` becomes `[://]`. Generic
  webhooks get the values as they are, for programs, in JSON.
* **Per format**:
  * **email**: HTML through Go's `html/template`, which escapes by
    context; the plain-text part as above. The subject is EasyRMM's own
    words and at most one clipped, defanged name, one line, encoded.
  * **Slack**: Block Kit, with these values in `plain_text` objects; the
    notification's fallback `text` has `&`, `<` and `>` escaped, so a name
    can neither link nor mention (`<!channel>`).
  * **Teams**: an Adaptive Card with these values in `TextRun`s of a
    `RichTextBlock`, which Teams does not read as Markdown, unlike the
    engine's `TextBlock`s.
* **Size budgets**, under the limits Slack and Microsoft publish (50
  blocks a message and 3,000 characters a text for Slack; about 28 KB a
  card for Teams), checked against their documentation when slice 5 is
  built: at most 40 blocks, 2,500 characters a text and 24 KB a card, then
  "…and N more" with a link. Email shows 25 alerts. Generic webhooks split
  rather than truncate: at most 100 alerts and 1 MiB a delivery.

Links in a message are only EasyRMM's own pages, at its public address,
never taken from a value.

### Device alert rules
* **A rule** belongs to the platform or one organization and has a name,
  an on/off switch, filters, when it notifies, and 1 to 20 channels.
* **Filters**, each dimension in one of two modes, ***any*** or ***list***:
  organizations (platform rules only), sites, device groups, kind of
  device (servers, workstations), severity (warning, critical) and
  condition (offline, processor, memory, disk, *agent removed without a
  request*).
  * Lists are rows with composite foreign keys that cascade: sites as
    `(organization_id, site_id)` to `sites`, device groups as
    `(site_id, device_group_id)` to `device_groups`, as `device_groups`
    itself refers to its site (migration 00001). An organization's rule
    may list only its own organization's sites and groups (`CHECK` against
    the rule's owner) and matches only its own devices.
  * **A list emptied by deletions matches nothing**, never everything: the
    mode stays *list*, the rule is marked, and a notice tells its managers.
* **Instead of tags, device groups**: EasyRMM's devices have no tags. A
  tag filter comes when devices have tags.
* **Kind of device**, from its operating system as the plan says, made
  exact: the agent reports a `role` with its facts, on Windows from
  `InstallationType` (`Client` is a workstation; `Server`, `Server Core`
  and other server values are servers). Without it (an older agent, a
  device known only to MeshCentral) the server reads the operating
  system's description: one containing `Windows Server` anywhere (as
  MeshCentral's "Microsoft Windows Server …" does) is a server, other
  Windows a workstation; Linux is a server, macOS a workstation. Someone
  with `monitoring.manage` at the site can set a device's kind, which
  wins, is audited and shows on the device. A device whose kind is still
  unknown matches only *any*.
* **When**:
  * **On opening**: at once, or only once the alert has been open N
    minutes (0 to 1,440), on top of the policy's own minutes. An alert
    resolved or acknowledged before then sends nothing.
  * **On resolving**: on or off for email, Slack and Teams. A generic
    webhook told that an alert opened is always told that it resolved.
  * **On acknowledging**: generic webhooks told of the alert get
    `alerts.acknowledged`, with who and when.
  * **Reminders** every N hours (0 for never, up to 720) while the alert is
    open and not acknowledged. Acknowledging stops them.
  * **Once told, told to the end**: a channel told that an alert opened is
    told that it resolved even if the rule changed or was deleted since,
    with the resolution: cleared, by hand (and by whom), not covered,
    policy off, changed or deleted, agent uninstalled, or device removed.
    A deleted channel is told nothing more.
* **One incident across a policy change**: changing a policy's condition
  resolves its alerts and the next evaluation opens new ones with new IDs.
  The payload's `id` is the incident's: the alert's own ID, carried over to
  an alert that opens with the same `key` (policy and device) within 5
  minutes of a `policy_changed` resolution. The planner holds
  `policy_changed` resolutions for those 5 minutes; when a successor opens,
  neither is sent, and the incident goes on. `alertId` is the console's.
* **Maintenance windows, per site**:
  * weekly (days, a start in the site's time zone, a length of at most 24
    hours, across midnight allowed and belonging to the day it starts) or
    once (at most 7 days, starting within 90 days);
  * daylight saving: lengths are elapsed time; a start in an hour that is
    skipped begins when the gap ends; a start in an hour that repeats
    begins at its first occurrence;
  * during one, the site's devices still raise alerts in the console, but
    nothing new is sent about them by organizations' rules. When it ends,
    alerts still open and not acknowledged are sent, in one message; those
    resolved meanwhile are not. An alert told before the window began is
    still told when it resolves;
  * **platform rules** may ignore windows (a switch, off by default), so
    a site administrator cannot silence what the MSP watches;
  * creating, changing and deleting a window is audited, and each start
    and end is a notice that rules can send;
  * managed with `monitoring.manage` at the site, on the Alerts page
    beside the policies and on the site's page; Settings → Notifications
    lists them, read-only.
* **A site goes offline**: when offline alerts open on a site's devices
  and every device of that site that has an EasyRMM agent, is not
  uninstalled and is watched by an enabled offline policy is offline, and
  there are at least two, the site is down (`site_outages`).
  * Per channel, the outage folds only the alerts that channel's rules
    match: one item, "Site X: all 40 devices offline", instead of theirs.
    A folded alert counts as told to that channel. Alerts that open later
    during the outage are folded in.
  * It ends when any of those devices is online again: "Site X is back
    online: 38 of 40 devices", with the resolutions of folded alerts that
    resolved; the folded alerts still open are then sent as their own
    opened alerts.
  * Generic webhooks get `sites.offline` and `sites.online` with the
    outage's ID and the IDs of the alerts folded in. A rule may turn
    grouping off (on by default), to get every alert's own events instead.
  * A site whose UPS shuts its computers down cleanly sends shutdown
    notices: its outage waits for the restart grace, as each device's
    alert does.
* **Digests**: one message per channel per planner run. Email, Slack and
  Teams get sections (sites offline and back, new, resolved, still open)
  within the budgets above, a count of the rest and a link. Generic
  webhooks get one delivery per event, with every alert, split into
  deliveries of at most 100: a PSA tool opens a ticket per alert, and an
  alert left out of a count would never be ticketed.
* **For PSA tools**: `id` is stable from opened through reminders and
  acknowledgement to resolved, and across a policy change as above; `key`
  is the same for every alert of one condition on one device, so a tool
  can tell a recurrence; site events have the outage's ID.
* **Sources**: a rule is about device alerts or about notices. Patching
  alerts keep the engine's rules (below).

### Nothing lost or queued twice
* **A journal, written by the database** (`alert_events`): triggers append
  a row, in the same transaction, whenever an alert opens (`AFTER
  INSERT`), is acknowledged or resolved (`AFTER UPDATE` of its status),
  and, before a device is deleted, one `resolved` row per unresolved alert
  of it with the resolution `device_removed` and the device's name, site
  and organization (`BEFORE DELETE ON devices`, as
  `devices_easypatch_forget` reads the device before it goes, migration
  00020). Every path is covered: `Evaluate`, a person's acknowledge or
  resolve, a policy's change, an uninstall, every kind of device removal.
  Purging resolved alerts writes nothing, so it never reads as a removal.
  Row-level security as `easypatch_forgotten`: inserted from any scope,
  read and changed at platform scope only.
* **`Evaluate` is unchanged**: it gains no work that could fail, and needs
  no `RETURNING`; its own transaction commits the alerts and their journal
  together.
* **The planner** runs in its own transaction, at platform scope, under an
  advisory lock of its own, after each evaluation and every 15 seconds. It
  takes up to 1,000 unplanned rows in order, matches them against the
  rules, records per alert and channel what was sent and what is due
  (`alert_notifications`, with the alert as it was when it opened), queues
  the deliveries due now (those just decided, and those whose wait,
  window, reminder or outage came due), and marks the rows planned: all in
  one commit, so each row is planned exactly once.
* **A row that fails** is tried again on its own (a savepoint); failing
  again, it is quarantined with its error, a notice tells super
  administrators, and the planner goes on. A super administrator can
  retry or discard it.
* A person's change is therefore sent within 15 seconds, by the planner,
  not by that person's transaction, whose scope could not write the
  platform's deliveries.

### Restarts
* **The server's** (amending ADR-0052): its offline rule delays only the
  opening of offline alerts. None opens until the server has served agents
  for 5 minutes plus the policy's minutes. An open offline alert resolves
  only when its device is online again, never because the server
  restarted. The evaluator does not run while the server is held.
* **A device's planned restart**: before it stops, the agent sends
  `POST /api/agent/v1/stopping`, signed with its device key as every agent
  request, with `{"reason": "shutdown"}` or `{"reason": "stop"}`, waiting
  at most 5 seconds for an answer. The server stamps it with its own clock
  (`agent_stopping_at`), never the agent's.
  * **Windows**: the service also accepts pre-shutdown (`golang.org/x/sys`
    offers `svc.AcceptPreShutdown`), which Windows gives more time than
    shutdown, and sends `shutdown` on either; `stop` when only the service
    is stopped.
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

### *Uninstalled*, and removals nobody asked for
* **`easyrmm-agent uninstall`** without `--removal` (and so the removal of
  an agent package, feature 6) removes the service, then sends
  `POST /api/agent/v1/uninstalled` signed with the device key (best
  effort, 10 seconds), then removes its files. It says whether the server
  heard.
* **An agent's word is not enough to go quiet.** A device key can be used
  by whoever controls the computer, ransomware included. So the server
  marks the device *Uninstalled* (audited, `device.agent_uninstalled`,
  with the time and source address), resolves its policy alerts
  (resolution `uninstalled`), and **opens a notice, *agent removed without
  a request***, critical, which device rules send (the condition is ticked
  on every new rule). It stays open until someone removes the device in
  the console or its agent checks in again. Evaluation leaves the device
  out: the notice says more than an offline alert would.
* **Amending ADR-0050**: a removal report (`/removed`, `Removed: true`) when
  no removal requested in the console is pending is handled the same way:
  the device is marked *Uninstalled* and the notice opens, instead of the
  device being deleted. Only a removal someone asked for, still pending,
  deletes the device on the agent's report.
* Devices shows *Uninstalled*, with the date and a filter; removing such a
  device deletes it at once, as **Remove anyway** does (ADR-0050). A later
  check-in with its key (an agent restored from a backup) clears the mark
  and resolves the notice.

### The patching engine hands its notifications to EasyRMM
* **The engine keeps deciding when**: `AlertEngine`, its rules, reminders
  and reopening stay. Its rules now name **EasyRMM's channels**: the
  platform's, or, for a rule limited to one organization, that
  organization's or a platform channel shared with it. EasyRMM, the
  engine's only caller (ADR-0048), checks this when a rule is saved and
  again when it takes a notification over. The engine stops checking
  channel IDs against its own table, both when a rule is saved (`ApplyAsync`
  in `NotificationEndpoints.cs`) and when it sends (`channels` and
  `targets` in `AlertEngine.EvaluateAsync`).
* **An outbox in the engine, with every change**: where `AlertEngine`
  queued deliveries, it writes one item per rule and event per run, with
  the rule's channel IDs, its `NotifyOnResolve`, and every alert (no cap):
  what each says (title, details, severity, organization, endpoint, link,
  times), as plain text. It writes **every** change, the silent ones
  included: opened; reopened (same alert ID); resolved, with why (cleared,
  rule off or deleted, organization inactive, endpoint gone); reminders;
  acknowledged. A monthly report to email, scheduled or sent by hand, is an
  item too (the report's ID and its recipients).
* **EasyRMM decides who is told**, by its own records
  (`alert_notifications`, keyed by the engine's alert ID for patching):
  openings and reminders go to the rule's channels; resolutions go to
  people's channels when `NotifyOnResolve` is on, and always to every
  generic webhook told of the alert, whatever the rule says now or whether
  it exists; a reopening goes as `alerts.opened` again to the channels told
  of the resolution; acknowledgements go to generic webhooks told of the
  alert.
* **EasyRMM collects**: every 30 seconds it reads
  `GET /api/v1/notifications/outbox?after=<cursor>&limit=100` (in order of
  creation, paged), then acknowledges what it took with
  `POST /api/v1/notifications/outbox/acknowledge`. Each call carries a
  statement (ADR-0038) with subject `service`, role `SuperAdmin`, every
  organization, bound to its method and target; the engine refuses these
  routes to a statement naming a person. EasyRMM records the items' IDs
  (`engine_handoffs`, unique), maps the engine's organizations to its own
  (ADR-0040) and queues the deliveries in one transaction, then
  acknowledges. An acknowledgement lost on the way returns the items once
  more, and their IDs are already taken. The engine deletes acknowledged
  items, drops those not collected within 24 hours and says how many in
  each answer; EasyRMM raises a notice.
* **Checked, not trusted**: connections still go one way, EasyRMM to the
  engine, with no new key. What EasyRMM collects is data the engine wrote:
  an item naming a channel it may not use (another organization's, a
  platform channel not shared with the rule's organization), or an alert
  of another organization or of an engine organization linked to none, is
  refused for that channel, recorded, and raised as a notice to super
  administrators. An item naming a channel deleted since is dropped for
  that channel.
* **Rendering is EasyRMM's** for patching too: the formats, escaping,
  signature, budgets and digests above. Patching items have
  `source: patching`.
* **Monthly reports**: report deliveries are the platform's and have no
  channel, so they keep no channel's order. EasyRMM fetches the PDF as its
  console does (`Client.MonthlyReportPDF`) and mails it, up to 15 MB and
  only over STARTTLS or TLS, as the engine did, then writes the outcome
  back with a new `POST /api/v1/monthly-reports/{id}/delivery` (status,
  time, error), which sets the report's `DeliveryStatus`, `SentAt` and
  `LastError`.
* **Moving the channels**: in EasyRMM's reconcile pass, at start and after
  an import, EasyRMM asks `GET /api/v1/notifications/channels/export` (the
  same statement; the engine decrypts with its own key ring and answers
  `no-store`) for the channels still in the engine's table, and creates
  each as a **platform channel with the same ID**, so the engine's rules
  keep pointing at it, with the `X-EasyPatch-*` headers on, then
  `POST /api/v1/notifications/channels/moved` with their IDs, and the
  engine deletes them. Audited (`notification_channel.moved`), repeatable:
  an ID already moved is skipped. Not a SQL migration: the two databases
  are separate and the secrets are sealed with different keys.
  * **Names**: the engine's are neither unique nor over 100 characters;
    a clash gets " (2)", " (3)" and so on, the name clipped to keep within
    100.
  * **Recipients** MimeKit accepted that Go's `net/mail` refuses are not
    moved; the channel lists them as "not moved" and is marked until
    someone looks.
  * **A channel the engine cannot decrypt** moves turned off, with no
    URL, marked "enter the URL again" (the engine's own advice), so that
    it never holds the others back.
  * **Collection waits per channel**: an item is taken once every channel
    it names has moved; the others go on.
  * **Pending deliveries**: the engine's migration turns those still
    pending into outbox items whose ID is the delivery's, so a message
    sent again carries the engine's `deliveryId` and receivers drop it.
  * **History**: the engine's delivery log does not move; it goes with its
    table when that retires, and the CHANGELOG says so.
  * `AllowPrivateNetworkWebhooks` needs no successor: platform channels may
    reach private addresses.
* **Deleting an EasyRMM channel** that patching rules name: EasyRMM takes
  it out of them through the engine's `PUT /api/v1/alert-rules/{id}` in its
  reconcile pass, retried until done, as `syncMail` is; meanwhile items
  naming it are dropped for it. The engine's channel `DELETE` route
  retires.
* **The switch**: the release that carries slice 6. At its first start the
  engine's migration turns pending deliveries into outbox items and its
  dispatcher no longer exists; EasyRMM's reconcile pass moves the
  channels, then collects. The engine and EasyRMM ship in one bundle, so
  there is no mixed state to switch.
* **Retired, as ADR-0048 rules** (each test of living behaviour moved
  first; `NotificationRenderer.Sign`'s output is frozen as a golden vector
  in EasyRMM's tests before it goes):
  * in the engine: `NotificationDispatcher` and its task;
    `NotificationTransport` (its SMTP client and its webhook HTTP client);
    `WebhookAddressPolicy`; `NotificationRenderer`; the notification
    settings (SMTP and `AllowPrivateNetworkWebhooks`) and the deliveries
    table; the routes to list, create, change, delete, rotate and test
    channels and to list deliveries; emailing reports
    (`DeliverPendingAsync`); the worker's reading of the Data Protection
    keys.
  * in EasyRMM: `syncMail` and the engine's `Mail` option; the patching
    notification routes, `NotificationsView` and `SetNotificationSettings`;
    the console's Settings → Patching → Notifications.
* **What stays, because something reaches it**: the engine's alert rules
  and alerts, and Settings → Patching → Alert rules, which chooses among
  EasyRMM's channels; the outbox; and the engine's channel table with its
  export route, because an import (ADR-0045) brings channels from a
  standalone EasyPatch, which the move then picks up.

### Retention
| What | Kept |
|---|---|
| Deliveries | 30 days after they end |
| `alert_events` | Planned rows 7 days; quarantined ones until a super administrator retries or discards them |
| `alert_notifications` | Until its alert is resolved and the resolution told, or given up, or dropped (recorded as *resolution not delivered*; that channel is told nothing more), then 30 days |
| `site_outages`, notices | As alerts: `EASYRMM_ALERT_RETENTION` after they end |
| `engine_handoffs` | 7 days, longer than the engine's 24 hours |
| The engine's outbox | Until acknowledged; dropped and counted after 24 hours |

**A rollback** after a confirmed upgrade (ADR-0052) brings back the
database as it was: alerts opened since are gone without ever being
resolved to receivers, and alerts resolved since may be told again. The
rollback's dialog says so, with how many alerts were sent since, and that
tickets opened for them in PSA tools are to be closed by hand. Deliveries
pending in the copy may be sent again, with their IDs.

### Tables
All with row-level security forced, on the `easyrmm_scope_*` functions:

| Table | Holds | Read and written |
|---|---|---|
| `notification_channels` | Channels: owner, kind, name, recipients, host, port, trusted authority, the `X-EasyPatch-*` switch, `failing_since`, `last_error`, `last_success_at` | Platform scope; an organization's in its scope; a platform channel also in the scope of an organization it is shared with (read only) |
| `notification_channel_secrets` | Sealed URL and signing secret | Platform scope, or the channel's own organization's; no exception for platform rows |
| `notification_channel_shares` | Platform channels shared with organizations | Read in that organization's scope; written at platform scope only |
| `notification_channel_approvals` | Approved host, port and prefixes per channel, a generation, who asked, who approved | Read in the channel's scope; an organization's scope may only ask; approving and withdrawing at platform scope only |
| `notification_rules`, their list tables, `notification_rule_channels` | Rules, modes and lists, channels (the constraints above) | Platform scope, or the organization's; lists and links follow their rule |
| `notification_deliveries` | The outbox and the delivery log | Platform scope, or the owner's; an organization's scope inserts only its own tests |
| `notices` | Notices | Platform scope; an organization's in its scope; a device's also with the device's site |
| `alert_events` | The journal | Inserted from any scope (by triggers); read and changed at platform scope only |
| `alert_notifications` | Per alert and channel: what was told, what is due and when, the incident, the alert as it opened | Platform scope only |
| `site_maintenance_windows`, `site_outages` | Windows; outages and the alerts folded in | Read with their site; windows written in the site's scope, outages at platform scope only |
| `notification_quotas` | Each organization's quotas, when not the defaults | Platform scope only |
| `mail_server` | The console's mail server, one row, the password sealed | Platform scope only, as `audit_forwarding` |
| `engine_handoffs` | The engine's items taken | Platform scope only |

`devices` gains `role`, `role_set_by`, `agent_stopping_at`,
`agent_stopping_reason` and `agent_uninstalled_at`; `alerts.resolution`
gains `uninstalled`; `organizations` gains `CHECK (id <> nil)`; the grace
is a key of `settings`. Every migration goes into database.md.

### Who
| What | Who |
|---|---|
| An organization's channels and rules: change, test, reveal, the delivery log | `notification.manage` in that organization: Organization Administrators (a new permission, from organization-wide grants only; a site assignment never gives it), and super administrators |
| The platform's channels and rules; sharing; approving private destinations; quotas; the restart grace; quarantined events | Super administrators |
| The mail server | Super administrators (`settings.manage`) |
| Maintenance windows; a device's kind | `monitoring.manage` at the site (Site Administrators and above); read with `monitoring.view` |
| Patching alert rules | Super administrators, as now (`patch.configure` platform-wide) |
| Notices | Whoever manages what they are about; a device's, whoever sees the device, acknowledged with `alert.manage` |

Every change, test, reveal, share, approval and move is audited.

### The console
* **Settings → Notifications**, a part of its own for whoever holds
  `notification.manage` anywhere:
  * **Channels**: each with its state (sending, failing and why, waiting
    for approval), its last delivery, *Test*, *Show secret*, *Replace
    secret*; super administrators see every organization's, by
    organization, share platform channels and approve private
    destinations here.
  * **Rules**, with their filters, when they notify, and channels.
  * **Delivery log**: 30 days, by channel, status and event, with refused
    recipients.
  * **Maintenance windows**, read-only, by site.
  * **Mail server**, **quotas** and **planned restarts' grace** (super
    administrators).
* **Alerts** gains notices and links to Settings → Notifications; its
  policies gain maintenance windows beside them; a site's page shows its
  windows. **Devices** shows *restarting* and *Uninstalled*, and the
  device's kind. Settings → Patching loses its Notifications view; its
  Alert rules choose among EasyRMM's channels.

### Slices
Each merges, and is verified, on its own:

1. **The mailer and the mail server in the console**: HTML and text, one
   message per recipient, attachments, the console's settings and
   `.env`'s precedence, the test message; invitations and resets through
   it; `syncMail` on every change. No certificate authority field yet.
   *Verified*: a test message from the console arrives in Mailpit in the
   bundle test; the contract test shows the engine's mail settings
   following a change without a restart.
2. **Channels, the sender, notices and the address policy**, with email and
   generic webhooks: tables, sharing, row-level security and the
   constraints, the scheduler, quotas, retries, tests, reveal, approvals.
   *Verified*: tests to an organization's webhook in its own network
   namespace, refused until approved, then signed and received; an email
   channel's test in Mailpit.
3. **Device alert rules** (feature 7): rules and filters, the agent's
   `role`, the journal and the planner, when they notify, incidents,
   reminders, maintenance windows, site outages, digests, ADR-0052's
   offline rule as amended. *Verified*: a device goes offline, the signed
   webhook and the email arrive; it comes back, the resolutions arrive.
4. **Planned restarts, *Uninstalled* and unrequested removals**.
   *Verified*: a shutdown that outlasts the policy but not the grace sends
   nothing, where a stopped agent alerts; a local uninstall sends the
   resolution and the *agent removed without a request* notice.
5. **Slack and Teams**. *Verified* by hand on real ones.
6. **Patching through EasyRMM**: the engine's outbox with every change, the
   collector, moving the channels, report emails, the certificate
   authority field, everything retired. *Verified*: the contract and import
   tests; a patching alert reaches a webhook in the bundle test.

Until slice 6, patching's notifications still go out through the engine.

## Testing
* **Integration** (PostgreSQL, with the race detector and coverage
  floors for the new packages):
  * **the database**: an organization's rule refused a platform channel not
    shared with it, and a link left in place once unshared refused; an
    organization's delivery about another organization refused; a nil
    `organization_id` refused; each with the service's checks bypassed.
    Row-level security between two organizations: no organization scope
    reads a platform channel's secrets, shared or not; the worker in one
    organization's scope cannot read another's channel.
  * **the journal**: a row for each path (an evaluation, a person's
    acknowledge and resolve, a policy change, an uninstall, a removal from
    the console, **Remove anyway**, a device only MeshCentral knew), none for
    a purge; a failure injected after an evaluation's changes leaves
    neither alerts nor rows; a failure in the planner leaves alerts
    committed and rows unplanned; a row that cannot be planned is
    quarantined while the others go out; two servers planning at once
    queue each delivery once.
  * **rules**: each filter; deleting the last listed site, device group
    and organization of a rule, each making it match nothing; an
    organization's rule never matching another's devices; the kind from
    `role`, from an agent's and from MeshCentral's descriptions, and its
    override.
  * **timing**: a wait the alert outlives and one it does not,
    acknowledgement before the wait ends, reminders and their end, a rule
    deleted after an alert was sent and its resolution still sent; a
    policy change keeping the incident, and one whose successor never
    opens.
  * **maintenance windows**: weekly and once, the caps, a start in a
    skipped hour and in a repeated hour, a window across midnight, the
    message at the end; a platform rule ignoring them.
  * **site outages**: all down, one never enrolled, one uninstalled, one
    coming back first, a straggler, devices still offline when it ends,
    two channels whose rules match different alerts of the same site.
  * **the sender**: retries on a fake clock, giving up; transient and
    permanent answers; a message holding its channel for an hour, then the
    others passing with an alert's order kept; a test retrying a held
    message; leases with two workers; fair share (one organization's
    receiver that never answers delays no other organization); the mail
    circuit; quotas reached, and deliveries waiting rather than dropped.
  * **the address policy**: every range in both policies, embedded IPv4;
    the server's own addresses, `EASYRMM_IP_ADDRESSES` and the deployment's
    names; an interface list given to the policy with a public IPv4 subnet
    and a global IPv6 prefix, addresses in each refused until approved;
    an approval bound to its port; a host change clearing it; a name that
    resolves first to a public and then to a private address; **a
    platform channel and an organization's channel to the same host,
    platform first: the organization's request is refused**; an approval
    withdrawn closing the channel's connections.
  * **errors**: URLs with a path and a query through every failure, never
    in logs or `last_error`; the mail server's reply visible to super
    administrators only.
  * sealed values copied to another row do not open; every reveal is
    audited.
  * the offline rule after a restart: an open offline alert stays open, no
    new one opens early.
  * the engine's handover against `eptest`: paging, an item taken once, an
    acknowledgement lost, an organization not linked, a channel not
    shared, a silent resolution reaching the generic webhook told of it.
* **Rendering**: golden messages for each format and event, with values
  carrying HTML, Slack's `<!channel>`, Markdown, control characters,
  `https://evil.example`, `www.evil.example`, `a@evil.example` and U+202E;
  goldens at each budget; signatures checked against the vector frozen from
  the engine's `NotificationRenderer.Sign`.
* **Mail**: 20 recipients make 20 messages, each with one address in `To`;
  one refused, the others delivered and the refusal shown.
* **HTTP API and console**: permissions for each route; the console's
  tests for every view.
* **Agent**: the notices' reasons from systemd's state (Linux), from the
  service's controls (Windows unit tests), the uninstall's report; on CI's
  Windows runner, a service stop sends `stop`. Pre-shutdown on real Windows
  is checked by hand on the owner's computers, and marked unverified until
  then.
* **The bundle test**, in a job of its own reusing the images built once:
  * **Mailpit**, bound to `127.0.0.1` on host networking (nothing but the
    edge may listen beyond loopback, as the test checks), offering
    STARTTLS with a certificate from an authority made for the run.
  * **A webhook receiver** (a small HTTPS server written for the test,
    recording each request) in a **network namespace of its own**, joined
    to the host by a **veth pair**: no bridge and no Docker network. The
    script picks a /30 from `10.0.0.0/8` that the runner does not route,
    gives the host's end the first address and the namespace the second,
    and runs the receiver with `ip netns exec`, its certificate made for
    that address by the run's authority. The host's end is one of the
    server's own addresses, and the namespace's is on one of its networks.
  * **The story**: an organization's webhook to the receiver is refused
    (on the server's network, not approved) and its channel shows failing;
    a super administrator approves it; its test arrives, signed with the
    secret the console reveals. An organization's webhook to `127.0.0.1`
    and to the host's end of the pair is refused. A rule sends the
    organization's offline alerts (an offline policy of 3 minutes) to the
    webhook and an email channel; the machine's agent is stopped; the
    signed `alerts.opened` and the email arrive; it starts again; the
    resolutions arrive.
  * **With slice 4**, the grace set to 10 minutes: the machine is powered
    off through its systemd (`systemctl poweroff` inside it), so its
    container stops, and stays down 8 minutes, longer than the policy plus
    the 3-minute online window, shorter than the grace; nothing opens and
    nothing is sent; it starts again. The control: the same 8 minutes
    after `systemctl stop easyrmm-agent` open the alert and send it. Then,
    with an opened alert already sent to the webhook, the agent is
    uninstalled on the machine: the `uninstalled` resolution and the
    *agent removed without a request* notice arrive.
  * **With slice 6**: a patching alert from the engine arrives at the same
    receiver.
* **The contract test** starts the engine's worker beside its API: the
  engine's mail settings follow a change (slice 1); a patching alert on a
  rule naming an EasyRMM channel appears in the outbox, in pages; a
  silent resolution and a reopening appear too; acknowledged, items do not
  appear again; a report sent by hand appears as an item, and its outcome
  written back shows on the report; the export answers a channel with its
  secrets and forgets it once moved; the retired routes answer 404; a
  statement naming a person is refused on these routes; `eptest`'s
  answers are recorded from the real engine.
* **The import test**: the seeded standalone EasyPatch's webhook points at
  a receiver the test runs, on loopback (an imported channel becomes a
  platform channel, which may reach loopback), with a certificate from an
  authority made for the run; the test keeps the signing secret the 1.10
  server answered when the channel was made. After the import and the
  move, the authority is set on the moved channel through EasyRMM's API,
  and its test carries both signatures, each valid with the kept secret.
* **Slack and Teams** by hand: a real Slack workspace and a real Teams
  Workflows webhook, with a device whose name carries markup and a URL;
  the messages and the date recorded in IMPLEMENTATION_STATUS.

## Consequences
* An MSP sets up its email lists, Teams, Slack and PSA webhooks once, for
  device alerts, patching and EasyRMM's own problems, and shares the ones
  it chooses with customers; customers' administrators set up their own,
  for their organization only.
* There is one SMTP client and one HTTP client for notifications, one
  address policy, one renderer. Until slice 6, there are two senders.
* Webhooks are delivered at least once; receivers drop copies by
  `deliveryId`. Queueing is exactly once.
* Organizations' administrators can have the server make HTTPS requests:
  to public addresses off the server's own networks only, unless a super
  administrator approved a destination for that channel. The platform's
  destinations may reach loopback, private addresses and the server's own
  networks, as audit forwarding may today; the engine's webhooks never
  reached loopback or the server's own networks, and private addresses
  only with its switch.
* More secrets rest on `EASYRMM_SECRET_KEY`: channels' URLs and signing
  secrets, and the mail server's password when it is set in the console.
* Receivers of the engine's webhooks keep working through the transition;
  they get every alert instead of 25 and a count, silent resolutions and
  reopenings they were not told of before, and new fields. Teams messages
  no longer format names as Markdown, and no format links a device's name.
* Offline alerts no longer resolve and open again across a restart of the
  server; a restarting device does not alert within the grace, and a
  local administrator who shuts a computer down delays its offline alert
  by the grace once. An agent can no longer make its device disappear or
  go quiet by its own report.
* Rules cannot filter by tag until devices have tags.
* The engine keeps a channel table and its export route for imports;
  everything else of its notification sending goes, and its delivery
  history with it.
* `alerts.resolution` gains `uninstalled`; devices gain their kind and
  their *Uninstalled* and *restarting* states; database.md, the guide,
  rbac.md, IMPLEMENTATION_STATUS, ROADMAP and the CHANGELOG change with
  each slice.

## Risks
* **The server as a way into a customer's network.** An organization's
  administrator can make the server send HTTPS requests. Every connection
  is checked, none is shared between channels, the server's networks and
  private ranges need a super administrator's approval for that channel
  alone, and the server itself, loopback and cloud metadata are never
  reached; no redirect, proxy or response body gets back to the person who
  set the channel up.
* **Messages between tenants.** A platform channel reaches an
  organization's rules only once shared with it, and its secrets never
  reach an organization's transaction.
* **The MSP's mail relay abused**: quotas, fixed test text, values clipped
  and defanged, one recipient per message. Recipients are not asked to
  confirm: what a message can carry is EasyRMM's own words and short,
  defanged names.
* **A storm**: a power cut at a large site, or EasyRMM's own outage. Site
  outages, digests, ADR-0052's offline rule and the restart grace keep it
  to a few messages per channel, and fair share keeps one organization's
  storm from delaying another's.
* **One bad receiver** holds its channel for an hour at most, and its
  messages about other alerts not at all after that.
* **A message sent twice** after a crash or a rollback: receivers drop it
  by its delivery ID; the guide says so.
* **A mail server set wrong in the console** stops notifications,
  invitations and password resets at once. The test message comes first in
  the form, the notice says the mail server is the problem, and
  `EASYRMM_SMTP_*` in `.env` takes over when set.
* **Planning stops**: a row that cannot be planned is quarantined and
  raised, and alerting goes on; an evaluation never fails because of
  notifications.
* **Windows' pre-shutdown** is unverified until it is checked on real
  Windows; until then a restarting Windows computer may alert as a plain
  stop would.
* **Slice 6 changes two products at once.** The engine and EasyRMM ship in
  one bundle; pending deliveries become outbox items with their IDs, each
  item waits only for its own channels, and a channel that cannot be
  decrypted moves turned off rather than blocking the rest.
