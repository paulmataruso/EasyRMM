# ADR-0053: One notification sender, and notifications for device alerts

* Status: Proposed (2026-11-21). Not implemented.
* Revised after two independent reviews (2026-11-21), with the owner's
  decisions on sharing platform channels, `alerts.acknowledged`, `.env`'s
  mail server and the old signature headers.
* Builds on: [ADR-0019](0019-monitoring-and-alerts.md) (monitoring and
  alerts), [ADR-0023](0023-audit-forwarding.md) (audit forwarding and the
  address rule of the platform's integrations),
  [ADR-0038](0038-statements-to-the-patching-engine.md) (statements to the
  engine), [ADR-0040](0040-one-set-of-organizations.md) (one set of
  organizations), [ADR-0045](0045-importing-a-standalone-easypatch.md)
  (imports), [ADR-0047](0047-tokens-shown-again.md) (secrets shown again),
  [ADR-0048](0048-the-engine-keeps-what-is-reached.md) (nothing left that
  nothing reaches) and [ADR-0052](0052-the-host-updater.md) with its offline
  rule as pull request #51 amends and builds it (openings only).
* Amends: [ADR-0050](0050-removing-a-device.md): a removal report that
  answers no instruction the server issued marks the device instead of
  deleting it, and cancelling a removal already sent keeps its record (see
  ***Uninstalled***). ADR-0052: its rollback says what it does to alerts
  already sent (see **Retention**).
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
    It clips titles to 300 characters and details to 2,000. It sends only
    to a rule's channels that are enabled in its own table (`channels` and
    `targets` in `EvaluateAsync`). Some changes are silent: alerts whose
    rule is off or gone, whose organization is inactive or whose endpoint
    is gone are resolved without a message; one resolved less than an hour
    ago reopens, with the same ID, without a message; and resolutions are
    sent only when the rule's `NotifyOnResolve` is on.
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
    (`DeliveryStatus`, `SentAt`, `LastError`). Sending one by hand
    (`POST /api/v1/monthly-reports/{id}/send`, `MonthlyReportEndpoints.cs`)
    checks the engine's own SMTP settings first; the route group needs only
    `Policies.Viewer`.
* **EasyRMM's mail server** is `EASYRMM_SMTP_*`, read at start
  (`server/internal/config/config.go`). `server/internal/mailer` sends plain
  text to one recipient, over STARTTLS or TLS trusting the system's roots
  only (its `tls.Config` names no roots), unencrypted only to loopback, and
  dials without `netguard`. Invitations and password resets use it;
  without it password reset is off (`auth.Service.ResetAvailable`). EasyRMM
  gives it to the engine **once per start** (`syncMail`,
  `server/internal/easypatch/engine.go`), so the engine's email and reports
  already go through it.
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
  an alert or resolve it by hand. Changing a policy's condition, its kind
  included, resolves its alerts (`policy_changed`, `reconcile` in
  `evaluate.go`, called from `UpdatePolicy`), and the next evaluation opens
  new ones with new IDs. Deleting a device deletes its alerts (`ON DELETE
  CASCADE`, migration 00006), and so does the heartbeat's merge of a
  device MeshCentral discovered into the enrolled one
  (`server/internal/agents/heartbeat.go`); purging deletes resolved alerts
  after `EASYRMM_ALERT_RETENTION` (`Service.Purge`).
* **Offline means both agents are silent**: a device is online while its
  agent has reported within 3 minutes (`devices.AgentOnlineWindow`) **or**
  MeshAgent is connected (`d.remote_online OR …` in `loadFacts`); offline
  policies are at least 3 minutes. The bundle test's machine runs both
  `easyrmm-agent` and `easyrmm-meshagent` (`web/e2e-bundle/bundle.spec.ts`).
* **ADR-0052's offline rule**, as first written ("count a device as seen no
  earlier than the moment the server began serving agents (its start, or
  the end of a hold) plus 5 minutes"), would have resolved open offline
  alerts at every restart. Pull request #51 (open) amends ADR-0052 and
  builds the rule so that it only holds back openings: `decide` takes a
  floor, and an alert already open stays open until its device checks in.
  This ADR relies on that rule as #51 states it, and does not change it.
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
  tells the server nothing.
* **Removal reports** (ADR-0050): `POST /api/agent/v1/removed` with
  `Removed: true` deletes the device whether or not a removal is pending
  (`Service.Removed` in `server/internal/agents/removal.go` records
  `removalCanceled` when none is): an agent's key alone can make a device
  disappear. ADR-0050 makes a *removed* report "the confirmation, even of a
  removal cancelled meanwhile", and `CancelRemoval` deletes the
  `device_removals` row, the instruction's ID included, even after the
  instruction was sent (`sent_at`); an instruction is valid for 10 minutes
  (`UninstallValid`).
* **Tenancy and secrets.** Tenant tables force row-level security on the
  `easyrmm.scope_*` settings ([database.md](../database.md)).
  `auth.DataScope` puts every organization-wide assignment's organization
  in `scope_orgs`, Read-Only included: row-level security bounds the
  organization, and the services check the permission.
  `rbac.Principal.Can` treats the nil UUID as "the platform".
  `server/internal/secrets` seals values with `EASYRMM_SECRET_KEY`
  (AES-256-GCM), bound to their row by associated data. Journals written by
  triggers in whatever transaction deletes something already exist
  (`easypatch_forgotten`, `easypatch_removals`, migration 00020), and the
  audit log is appended only through a `SECURITY DEFINER` function owned by
  `easyrmm_owner` (`easyrmm_audit_append`, migration 00001).
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
    platform's, and is **charged** to the organization whose rule produced
    it (below).
* **Two tables, two read rules.** `notification_channels` holds only what
  an organization may see of a shared channel: owner, kind, name, on or
  off. Everything else (recipients, host and port, trusted authority,
  sealed URL and signing secret, failing state and last error, the
  `X-EasyPatch-*` switch) is in `notification_channel_details`, which has
  its own `owner` column, a composite foreign key `(channel id, owner)`
  that cascades, and a policy on its own `owner` alone: platform scope, or
  `owner = ANY (scope_orgs)`; never an `EXISTS` on channels, never an
  exception for platform rows.
* **Row-level security**, forced:
  * channels: platform scope; an organization's own in its scope
    (`scope_orgs`); a platform channel also, read-only, in the scope of an
    organization it is shared with.
  * details: as above. No organization's transaction can read a platform
    channel's recipients, host, errors, URL or secret. Only the sender and
    *reveal* open sealed values; reveal checks `notification.manage`,
    since `scope_orgs` includes Read-Only users' organizations.
  * rules and deliveries: platform scope, or the owner's.
* **Deleting a channel** takes it out of every rule (device rules through
  the foreign keys; patching rules through the engine, see below) and drops
  its pending deliveries; the dialog names the rules it leaves. Turning one
  off drops its pending deliveries, recorded as not sent.

### The sender
* **The outbox** (`notification_deliveries`): owner, the organization
  charged, channel (none for a report), kind (digest, event, report,
  test), event, the subjects it carries (each alert's incident or notice,
  below), the message as data (JSON, no secrets), status (pending, sent,
  failed, dropped), attempts, next attempt, a lease, the last error, and
  when it was queued and ended. Email deliveries record each recipient's
  outcome (`notification_delivery_recipients`): a retry goes only to the
  recipients not yet accepted. Deliveries are queued only by the planner's
  transaction (**Nothing lost or queued twice**).
* **One worker per server, one sending.** The worker holds one connection
  taken from the pool for its whole life (the pool closes idle ones after
  5 minutes) and a session advisory lock on it. If the connection is lost,
  it stops sending and takes the lock again. Each delivery is also
  **leased**: an `UPDATE` sets `lease_until` (now plus the request's
  timeout plus a minute) only where no lease is current, so two servers
  during a failover never send the same delivery at once.
* **A lock per channel.** The planner, before it queues or merges into a
  channel's deliveries, and the sender, while it chooses and leases a
  channel's next delivery, lock that channel's row; the planner locks all
  it needs at once, in order of channel ID. Neither holds the lock across
  the network.
* **Fair share.** Webhooks and email are separate classes, so a slow mail
  server never holds a webhook back. Each class goes round-robin over the
  organizations charged and the platform, with at most 2 deliveries in
  flight per organization and 4 for the platform's own, per class, and 1
  per channel; in all, 8 webhooks and 4 email sessions at once.
* **Under the destination's scope**: each attempt reads its delivery,
  channel and details in the channel owner's scope (`database.Scope` with
  that one organization, or platform scope), so an organization's
  delivery cannot open another's channel.
* **Order per channel, and per subject.** A channel's deliveries go in the
  order they were queued while its earliest unsent one is retried for a
  **transient** failure: no connection, a TLS failure, a timeout, `408`,
  `425`, `429` (its `Retry-After` honoured, up to an hour) and `5xx`; for
  email, `4xx` replies.
  * **Permanent** answers fail the message at once: `401`, `403`, `404`,
    `410`, `422` and any other `4xx` but `413`; for email, a `5xx` reply
    (per recipient). `413` splits a generic webhook's delivery in two,
    once; a half answered `413` again fails. `401`, `403`, `404` and `410`
    mark the channel failing at once; the others after 3 messages in a row.
  * **After an hour**, a later delivery may go before the earliest unsent
    one, but only if it carries no subject that any earlier unsent
    delivery on that channel carries: nothing about an alert ever arrives
    before what was queued earlier about it. Nothing is split at send time.
  * A successful test retries the earliest unsent delivery at once.
* **Retries**, as the engine's: from 1 minute, doubling to an hour; given
  up 24 hours after queueing, waits for a quota included. Tests give up
  after 3 attempts. A given-up or dropped delivery raises a notice: "N
  messages to channel X were not sent".
* **Nothing piles up.**
  * A channel read by people (email, Slack, Teams) has **at most one
    unsent digest**, besides one being sent: what the planner queues for it
    merges into the waiting digest, which renders the state when it is
    sent. An alert opened and resolved before it went is left out.
  * A generic webhook's deliveries are events and do not merge, but an
    `alerts.opened` never sent is dropped with the `alerts.resolved` that
    follows it (the receiver never heard of the alert), and an unsent
    reminder is dropped when a newer event about the same alert is queued.
  * At most 2,000 unsent deliveries per organization charged; past that,
    new events to its webhooks are dropped and counted, with a notice.
* **Tests** go at once, ahead of the channel's queue, at most one per
  channel every 30 seconds (`429 test_rate_limited`, as the engine
  answers). The text is fixed, EasyRMM's own: no channel name and nothing
  anyone typed.
* **Quotas, in messages**: one webhook delivery is one message; one email
  delivery is one message per recipient. Per organization, changeable per
  organization by super administrators: 20 channels, 50 rules, 20 tests an
  hour, 600 messages an hour. Messages over the hourly quota wait for room
  (up to the 24 hours above). Deliveries on a shared platform channel count
  against the organization whose rule produced them. Reaching a quota
  raises a notice to the organization's managers and to super
  administrators. The platform's own rules have none.
* **The mail server's limits**: super administrators set a platform-wide
  rate of messages a minute and a day (by default 30 and 9,000, below the
  sending limits large hosted services publish; they set their relay's).
  Messages are shared round-robin among the organizations charged and the
  platform. **Account mail goes first**: invitations, password resets and
  other mail to people's own accounts are never queued behind
  notifications, and notifications stop at 90% of the day's budget, so the
  rest is always there for them.
* **The mail server's circuit**: after 5 failures in a row to connect or
  sign in, notification email pauses for 1 minute, doubling to 15, with one
  message tried at a time; attempts are not counted while paused (the 24
  hours still run). Webhooks go on.
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
  policy's condition on a device: a failing channel, messages not sent, a
  quota reached, a rule left without channels or with an emptied list,
  patching items refused or dropped, a journal row quarantined, a
  maintenance window starting and ending, most devices silent at once, and
  an agent removed without a request. Each has a kind, the platform or one
  organization, optionally a site and a device, when it opened, and when it
  was acknowledged or resolved.
* **Only the server opens and resolves them**, at platform scope (the
  sender, the planner, the collector, the agents' service); people
  acknowledge them in their own scope. They are journaled and planned
  exactly as alerts are (**Nothing lost or queued twice**).
* **A channel is failing** once a delivery to it has failed for 15 minutes
  without a success since, has been given up, or has a permanent answer
  as above; it recovers at its next success. Tests do not count.
* **Shown** on the Alerts page (a section of their own), on the dashboard,
  and as a banner on Settings → Notifications, to whoever manages what the
  notice is about; a notice about a device to whoever sees the device.
* **Sent** by rules, with the same timing as alerts (a wait, on resolving,
  on acknowledging, reminders until acknowledged, once told told to the
  end): an organization's rule gets its own organization's notices, a
  platform rule any (source *EasyRMM*). A failing channel's notice is
  never sent to that channel. The one notice about a device, *agent
  removed without a request*, is a condition of device rules instead, with
  their filters.

### The address policy
For every destination an organization owns: its webhook, Slack and Teams
channels now, its syslog destinations with log forwarding later.

* **Checked on every connection dialled**: the dialer's `Control` function
  sees each address tried after name resolution, so a name that resolves,
  or re-resolves, to a refused address is refused.
* **No connection serves two policies.** Each channel has its own
  `http.Transport`, made when first needed and keyed by the channel and a
  generation that any change of its host, port, approval, trusted
  authority or policy increases. Its dialer's `Control` is a closure bound
  to that policy and those approved prefixes, nothing looked up at dial
  time. A transport is closed and dropped (`CloseIdleConnections`) when
  its generation changes, its channel is deleted or turned off, or after
  10 minutes unused. An organization's transports do not keep connections
  alive (`DisableKeepAlives`), so every request dials, and is checked,
  anew; a platform channel's keep at most one (`MaxConnsPerHost` 1,
  `IdleConnTimeout` 90 seconds), never shared with another channel.
* **Embedded IPv4** (IPv4-mapped, NAT64 `64:ff9b::/96`, 6to4 `2002::/16`,
  IPv4-compatible) is checked as both addresses, in both policies:
  `netguard` gains the normalisation it lacks. The network's own NAT64
  prefix, found the way RFC 7050 gives (the resolver's answer for
  `ipv4only.arpa`), is read as embedding IPv4 too when it is a /96, and
  refused otherwise.
* **Always refused**:
  * unspecified and "this network" (`0.0.0.0/8`, `::`), loopback,
    link-local, multicast, broadcast, reserved (`240.0.0.0/4`), IETF
    protocol assignments (`192.0.0.0/24`), documentation
    (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`,
    `2001:db8::/32`), benchmarking (`198.18.0.0/15`), discard
    (`100::/64`), the old site-local range (`fec0::/10`), local-use NAT64
    (`64:ff9b:1::/48`) and Teredo (`2001::/32`);
  * every cloud metadata address `netguard` lists (`fd00:ec2::254` and
    `100.100.100.200`, which lie inside ranges below and stay refused when
    those are approved);
  * **the server itself**: each address of its interfaces; the addresses
    in `EASYRMM_IP_ADDRESSES`; and the deployment's names
    (`EASYRMM_PUBLIC_URL`'s and `EASYRMM_MESH_PUBLIC_URL`'s hosts and the
    further names `validateExtraHostnames` checks), refused as a URL's host
    and by the addresses they resolve to. Behind NAT or a proxy, the
    server's public address is not on its interfaces; its names cover it.
* **Only once approved**: private addresses (`10.0.0.0/8`,
  `172.16.0.0/12`, `192.168.0.0/16`, CGNAT `100.64.0.0/10`, ULA
  `fc00::/7`), **every network on the server's own interfaces**, whatever
  its kind (a public IPv4 subnet or a global IPv6 prefix on the server's
  LAN is no safer than a private one), and **every destination the server
  routes other than by its default route** (a VPN, a static route to
  another site).
* The interfaces, the routes, the NAT64 prefix and the deployment's names
  are read again every minute.
* **An approval** names one channel, its host and port, and one or more
  prefixes; proposed are the addresses the host resolves to when approval
  is asked, each as a single address, which the super administrator may
  widen. A delivery may dial such an address only inside its own
  channel's approved prefixes. Changing the URL's host or port clears the
  approval. Until approved, deliveries fail with "waiting for approval",
  the channel's notice says so, and super administrators see the request
  in the console. Approvals and their withdrawal are audited; withdrawal
  raises the channel's generation, which closes its transport at once.
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
  `notices.opened`, `notices.acknowledged`, `notices.resolved` and `test`.
* **Resolutions**: `cleared`, `manual`, `not_covered`, `policy_off`,
  `policy_changed`, `policy_deleted`, `uninstalled` (stored on the alert),
  and `device_removed` and `merged` (the alert was deleted with its
  device, or with a discovered device merged into an enrolled one).

### Secrets
* **Sealed** with `EASYRMM_SECRET_KEY` in `notification_channel_details`
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
  name, and the rate limits above. One row at platform scope
  (`mail_server`). It applies at once, without a restart, to
  notifications, invitations and password resets; `ResetAvailable`
  follows it.
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
  line limit. Each recipient's outcome is recorded; one refused is shown on
  the delivery and the channel, the others still receive it, and all
  refused is a failure.
* **The mailer gains**: HTML with a plain-text alternative
  (`multipart/alternative`), attachments (monthly reports), the sender's
  name, the trusted authority, the `Message-ID` above, and the rate limits.

### Content
Values that come from agents (device and host names, operating systems)
or from people (names of policies, sites, organizations, channels) are
text, made safe for each format when the message is rendered, in this
order:

1. **Cleaned**: normalised to NFKC, with the ideographic full stop
   (U+3002, which NFKC also makes of U+FF61) read as a dot, as NFKC makes
   of U+FF0E; control (Cc), format (Cf: bidirectional overrides,
   zero-width characters), line separator (Zl) and paragraph separator (Zp)
   characters removed.
2. **Clipped**: device and host names to 64 characters, operating systems
   to 100, other names to 100, with "…". An item's text from the engine is
   capped at 4 KB on receipt.
3. **Never a link**: in email, Slack and Teams, a value that contains
   something a client would link (a scheme and `://`, a `www.` name, a
   dotted name ending in letters, an e-mail address) has it defanged:
   `.` becomes `[.]`, `@` becomes `[@]` and `://` becomes `[://]`. Generic
   webhooks get the cleaned and clipped values as they are, for programs,
   in JSON.

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
* **Size budgets**, measured on the encoded bytes sent, under the limits
  Slack and Microsoft publish (50 blocks a message and 3,000 characters a
  text for Slack; about 28 KB a card for Teams), checked against their
  documentation when slice 5 is built: at most 40 blocks, 2,500 bytes a
  text and 24 KB a card, then "…and N more" with a link. Email shows 25
  alerts. Generic webhooks split rather than truncate: at most 100 alerts
  and 1 MiB a delivery.

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
    mode stays *list*, and the planner marks the rule and raises a notice
    to its managers.
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
    with the resolution. A deleted channel is told nothing more.
* **One incident across a policy change**: changing a policy's condition
  resolves its alerts and the next evaluation opens new ones with new IDs.
  The payload's `id` is the **incident's**: the alert's own ID, carried
  over to an alert that opens on the same policy and device, **with the
  same kind**, within 5 minutes of a `policy_changed` resolution, or, after
  a restart, before ADR-0052's start delay for that policy has passed,
  whichever is later. The planner holds `policy_changed` resolutions that
  long; when a successor opens, neither is sent, and the incident goes on:
  its waits and reminders count from the incident's start, and an
  acknowledgement carries over (`Evaluate`'s only change: a new alert
  copies the acknowledgement of the one it succeeds). `alertId` is the
  console's.
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
  * **never held by a window**: *agent removed without a request*;
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
* **Digests**: one unsent digest per channel read by people, as above,
  with sections (sites offline and back, new, resolved, still open) within
  the budgets above, a count of the rest and a link. Generic webhooks get
  one delivery per event, with every alert, split into deliveries of at
  most 100: a PSA tool opens a ticket per alert, and an alert left out of
  a count would never be ticketed.
* **For PSA tools**: `id` is stable from opened through reminders and
  acknowledgement to resolved, and across a policy change as above; `key`
  is the same for every alert of one condition on one device, so a tool
  can tell a recurrence; site events have the outage's ID.
* **Sources**: a rule is about device alerts or about notices. Patching
  alerts keep the engine's rules (below).

### Nothing lost or queued twice
* **A journal, written by the database** (`notification_events`):
  * on `alerts`: `AFTER INSERT`; `AFTER UPDATE … WHEN (OLD.status IS
    DISTINCT FROM NEW.status OR OLD.acknowledged_at IS DISTINCT FROM
    NEW.acknowledged_at)`; and `AFTER DELETE … WHEN (OLD.status <>
    'resolved')`, which records the deletion's reason from a
    transaction-local setting (`merged`, set by the heartbeat's merge
    before it deletes the discovered device) or else `device_removed`;
  * on `notices`: `AFTER INSERT` and `AFTER UPDATE` of their status or
    acknowledgement, the same way;
  * on `engine_handoffs`: `AFTER INSERT`, for the patching engine's items.
  * The triggers copy `OLD` and `NEW` and that setting only; they read no
    other table, and the journal has no foreign key, `CHECK` or unique
    index that a copied row could fail, so a trigger never rejects the
    change it records. The device's name, site and organization come from
    what the planner recorded when the alert opened.
  * The trigger function is `SECURITY DEFINER`, owned by `easyrmm_owner`
    with its `search_path` set, as `easyrmm_audit_append` is; `easyrmm_app`
    may read and update the journal at platform scope, but has no `INSERT`
    on it, so application code cannot forge a row.
  * Every path is covered, in the transaction that makes the change:
    `Evaluate`, a person's acknowledge or resolve, a policy's change, an
    uninstall, every kind of device removal and merge, every notice, every
    patching item taken. Purging resolved alerts writes nothing, so it never reads as a removal.
* **The planner** runs in its own transaction, at platform scope, under an
  advisory lock of its own, after each evaluation and every 15 seconds. It
  never locks `alerts` or `notices`: it reads them, so `Evaluate` and
  people's actions never wait on it. It takes up to 1,000 unplanned rows in
  order, matches them against the rules, records per subject and channel
  what was sent and what is due (`alert_notifications`, keyed by the
  incident or the notice, with no foreign key to `alerts`, `notices` or
  `devices`, so a deletion cannot take the record with it), locks the
  channels it queues to, queues or merges the deliveries due now (those
  just decided, and those whose wait, window, reminder or outage came due),
  and marks the rows planned: all in one commit, so each row is planned
  exactly once. A second resolution of a subject already resolved (a
  device deleted while `Evaluate` resolved its alert) is marked planned
  and sends nothing.
* **A row that fails**:
  * A transient error (serialization failure, deadlock, lock or statement
    timeout, a lost connection) only rolls the run back; the next run tries
    again.
  * Any other error rolls the batch back, and the planner plans that
    batch's rows one per transaction, so the bad row is found without
    savepoints. A row that fails so in 3 runs is **quarantined**: a minimal
    update of its status and its error, clipped, which nothing can refuse,
    and a notice to super administrators.
  * **Per subject**: the rows after a quarantined one about the same
    alert's incident or notice wait unplanned, so nothing about it is sent
    out of order. **Retry** replays them in order; **Discard** marks them
    all planned and plans the subject's current state as one row: channels
    told of it get that state (a resolution, say), others nothing. Every
    other subject goes on.
* A person's change is therefore sent within 15 seconds, by the planner,
  not by that person's transaction, whose scope could not write the
  platform's deliveries.

### Restarts, and EasyRMM itself unreachable
* **The server's**: ADR-0052's offline rule as pull request #51 builds it
  holds back the opening of offline alerts until the server has served
  agents for 5 minutes plus the policy's minutes; an open offline alert
  stays open until its device checks in, so a restart neither resolves nor
  reopens it. The evaluator does not run while the server is held.
* **Most devices silent at once**: a restart is covered, but EasyRMM can be
  unreachable while it runs (its name, its certificate, a firewall). When
  at least half of the devices with an EasyRMM agent, and at least 20,
  have stopped checking in within the same 5 minutes, new offline alerts
  are held, and one notice, *most devices stopped checking in*, goes to
  super administrators through platform rules. The hold ends when fewer
  than half are silent, or after 30 minutes, whichever is first; after it,
  offline alerts open as usual, grouped by site outages.
* **A device's planned restart**: before it stops, the agent sends
  `POST /api/agent/v1/stopping`, signed with its device key as every agent
  request, with `{"reason": "shutdown"}` or `{"reason": "stop"}`, waiting
  at most 5 seconds for an answer. The server stamps it with its own clock
  (`agent_stopping_at`), never the agent's. Only the EasyRMM agent sends
  it; MeshAgent says nothing, and a device stays online while MeshAgent is
  connected.
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
  on every new rule) and no maintenance window holds. It stays open until
  someone removes the device in the console or its agent checks in again.
  Evaluation leaves the device out: the notice says more than an offline
  alert would.
* **Amending ADR-0050: a report confirms only an instruction the server
  issued.**
  * A removal report (`/removed`, `Removed: true`) deletes the device only
    when its `ID` matches a removal instruction the server sent for that
    device. That includes a removal cancelled after its instruction was
    sent, as ADR-0050 says ("the confirmation, even of a removal cancelled
    meanwhile").
  * So `CancelRemoval` no longer deletes a `device_removals` row whose
    instruction was sent: it marks it cancelled (`cancelled_at`), and no
    heartbeat sends a cancelled instruction again. The row is kept for the
    instruction's validity (`UninstallValid`) plus an hour, for the report
    to arrive, then deleted. A removal cancelled before anything was sent
    is deleted as now.
  * A report that matches no instruction is handled as `/uninstalled`: the
    device is marked, not deleted, and the notice opens.
* Devices shows *Uninstalled*, with the date and a filter; removing such a
  device deletes it at once, as **Remove anyway** does (ADR-0050). A later
  check-in with its key (an agent restored from a backup) clears the mark
  and resolves the notice.
* **Re-enrolled**: a computer installed again enrols as a new device. When
  a device enrols at the same site with the same host name (ignoring case)
  as a device marked *Uninstalled*, the notice resolves with "enrolled
  again as <device>", and the old device is offered for removal.

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
  routes to a statement naming a person. EasyRMM maps the engine's
  organizations to its own (ADR-0040) and records each item, by its ID
  (unique) and with its content, in `engine_handoffs`, whose trigger
  journals it as the triggers on `alerts` do, all in one transaction, then
  acknowledges; the planner plans the items like the rest.
  An acknowledgement lost on the way returns the items once more, and their
  IDs are already taken. The engine deletes acknowledged items, drops those
  not collected within 24 hours and says how many in each answer; EasyRMM
  raises a notice.
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
  channel, so they keep no channel's order; they count against the mail
  server's limits. EasyRMM fetches the PDF as its console does
  (`Client.MonthlyReportPDF`) and mails it, up to 15 MB and only over
  STARTTLS or TLS, as the engine did, then writes the outcome back with a
  new `POST /api/v1/monthly-reports/{id}/delivery` (the outbox item's ID,
  status, time, error). That route takes a `service` statement with role
  `SuperAdmin` only, although its group needs only `Policies.Viewer`; it
  is idempotent per item and never replaces an outcome recorded at a later
  time. It sets the report's `DeliveryStatus`, `SentAt` and `LastError`.
* **Sending a report by hand**: EasyRMM checks the mail server in force
  (set, encrypted, the report's size) before it asks the engine's
  `/send`, which in slice 6 stops reading its own SMTP settings and keeps
  only its checks of recipients and size; `smtp_not_configured` and its
  mapping in EasyRMM retire.
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
    (`DeliverPendingAsync`) and `/send`'s SMTP checks; the worker's reading
    of the Data Protection keys.
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
| Deliveries and their recipients | 30 days after they end |
| `notification_events` | Planned rows 7 days; quarantined ones, and the rows waiting behind them, until a super administrator retries or discards them |
| `alert_notifications` | Until its subject is resolved and the resolution told, or given up, or dropped (recorded as *resolution not delivered*; that channel is told nothing more), then 30 days |
| `site_outages`, notices | As alerts: `EASYRMM_ALERT_RETENTION` after they end |
| `engine_handoffs` | 7 days, longer than the engine's 24 hours |
| `device_removals` cancelled after sending | `UninstallValid` plus an hour |
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
| `notification_channels` | Owner, kind, name, on or off | Platform scope; an organization's in its scope; a platform channel also, read-only, in the scope of an organization it is shared with |
| `notification_channel_details` | Recipients, host, port, trusted authority, sealed URL and signing secret, the `X-EasyPatch-*` switch, `failing_since`, `last_error`, `last_success_at`, the transport's generation | By its own `owner`: platform scope, or that organization's; no exception for platform rows |
| `notification_channel_shares` | Platform channels shared with organizations | Read in that organization's scope; written at platform scope only |
| `notification_channel_approvals` | Approved host, port and prefixes per channel, who asked, who approved | Read in the channel's scope; an organization's scope may only ask; approving and withdrawing at platform scope only |
| `notification_rules`, their list tables, `notification_rule_channels` | Rules, modes and lists, channels (the constraints above) | Platform scope, or the organization's; lists and links follow their rule |
| `notification_deliveries`, `notification_delivery_recipients` | The outbox, the delivery log, each recipient's outcome | Platform scope, or the owner's; an organization's scope inserts only its own tests |
| `notices` | Notices | Opened and resolved at platform scope; read, and acknowledged, in an organization's scope for its own, and with the device's site for a device's |
| `notification_events` | The journal | Inserted only by the triggers' `SECURITY DEFINER` function; read and changed at platform scope only |
| `alert_notifications` | Per subject and channel: what was told, what is due and when, the incident, the alert as it opened | Platform scope only |
| `site_maintenance_windows`, `site_outages` | Windows; outages and the alerts folded in | Read with their site; windows written in the site's scope, outages at platform scope only |
| `notification_quotas` | Each organization's quotas, when not the defaults | Platform scope only |
| `mail_server` | The console's mail server and its rate limits, one row, the password sealed | Platform scope only, as `audit_forwarding` |
| `engine_handoffs` | The engine's items taken, with their content | Platform scope only |

`devices` gains `role`, `role_set_by`, `agent_stopping_at`,
`agent_stopping_reason` and `agent_uninstalled_at`; `device_removals`
gains `cancelled_at`; `organizations` gains `CHECK (id <> nil)`; the grace
is a key of `settings`. `alerts.resolution` gains `uninstalled`: the new
`CHECK` is added `NOT VALID`, then validated (`VALIDATE CONSTRAINT`), and
only then is the old one dropped, so the table is not locked while rows
are checked. Every migration goes into database.md.

### Who
| What | Who |
|---|---|
| An organization's channels and rules: change, test, reveal, the delivery log | `notification.manage` in that organization: Organization Administrators (a new permission, from organization-wide grants only; a site assignment never gives it), and super administrators |
| The platform's channels and rules; sharing; approving private destinations; quotas; the mail server's limits; the restart grace; quarantined journal rows | Super administrators |
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
  * **Delivery log**: 30 days, by channel, status and event, with each
    recipient's outcome.
  * **Maintenance windows**, read-only, by site.
  * **Mail server**, its **limits**, **quotas**, **planned restarts'
    grace** and **quarantined rows** (super administrators).
* **Alerts** gains notices and links to Settings → Notifications; its
  policies gain maintenance windows beside them; a site's page shows its
  windows. **Devices** shows *restarting* and *Uninstalled*, and the
  device's kind. Settings → Patching loses its Notifications view; its
  Alert rules choose among EasyRMM's channels.

### Slices
Each merges, and is verified, on its own:

1. **The mailer and the mail server in the console**: HTML and text, one
   message per recipient, attachments, the console's settings and
   `.env`'s precedence, the limits with account mail first, the test
   message; invitations and resets through it; `syncMail` on every change.
   No certificate authority field yet. *Verified*: a test message from the
   console arrives in Mailpit in the bundle test, over plain SMTP on
   loopback (the mailer trusts only the system's roots until the field
   comes); the contract test shows the engine's mail settings following a
   change without a restart.
2. **Channels, the sender, notices, the journal for notices, and the
   address policy**, with email and generic webhooks: tables, sharing,
   row-level security and the constraints, the scheduler, quotas,
   retries, tests, reveal, approvals. *Verified*: tests to an
   organization's webhook in its own network namespace, refused until
   approved, then signed and received; an email channel's test in Mailpit.
3. **Device alert rules** (feature 7): rules and filters, the agent's
   `role`, the journal for alerts and the planner, when they notify,
   incidents, reminders, maintenance windows, site outages, digests, the
   fleet-wide hold. *Verified*: a device goes offline, the signed webhook
   and the email arrive; it comes back, the resolutions arrive.
4. **Planned restarts, *Uninstalled* and removal reports**. *Verified*: a
   shutdown that outlasts the policy but not the grace sends nothing,
   where stopped agents alert; a local uninstall sends the resolution and
   the *agent removed without a request* notice.
5. **Slack and Teams**. *Verified* by hand on real ones.
6. **Patching through EasyRMM**: the engine's outbox with every change, the
   collector, moving the channels, report emails and their outcome route,
   the certificate authority field, everything retired. *Verified*: the
   contract and import tests; a patching alert reaches a webhook in the
   bundle test; Mailpit now over STARTTLS with the run's authority set in
   the console.

Until slice 6, patching's notifications still go out through the engine.

## Testing
* **Integration** (PostgreSQL, with the race detector and coverage
  floors for the new packages):
  * **the database**: an organization's rule refused a platform channel not
    shared with it, and a link left in place once unshared refused; an
    organization's delivery about another organization refused; a nil
    `organization_id` refused; each with the service's checks bypassed.
    Row-level security between two organizations: no organization scope,
    a Read-Only user's included, reads a platform channel's details,
    shared or not; the worker in one organization's scope cannot read
    another's channel.
  * **the journal**: a row for each path (an evaluation, a person's
    acknowledge and resolve, a policy change, an uninstall, a removal from
    the console, **Remove anyway**, a device only MeshCentral knew, a
    heartbeat's merge as `merged`, each kind of notice), none for a purge
    or for an update that changes neither status nor acknowledgement;
    `easyrmm_app` refused an `INSERT` into it; a failure injected after an
    evaluation's changes leaves neither alerts nor rows; a failure in the
    planner leaves alerts committed and rows unplanned; a transient error
    retried on the next run; a bad row quarantined after 3 runs while the
    others go out, the rows about its subject held behind it, then retry
    and discard each doing what they say; a device deleted while
    `Evaluate` resolves its alert sending one resolution; two servers
    planning at once queue each delivery once.
  * **rules**: each filter; deleting the last listed site, device group
    and organization of a rule, each making it match nothing; an
    organization's rule never matching another's devices; the kind from
    `role`, from an agent's and from MeshCentral's descriptions, and its
    override.
  * **timing**: a wait the alert outlives and one it does not,
    acknowledgement before the wait ends, reminders and their end, a rule
    deleted after an alert was sent and its resolution still sent; a
    policy change keeping the incident and its acknowledgement, one
    changing the kind and starting a new incident, one whose successor
    never opens, and one followed by a restart.
  * **maintenance windows**: weekly and once, the caps, a start in a
    skipped hour and in a repeated hour, a window across midnight, the
    message at the end; a platform rule ignoring them; *agent removed
    without a request* sent during one.
  * **site outages** and the fleet-wide hold: all down, one never enrolled,
    one uninstalled, one coming back first, a straggler, devices still
    offline when it ends, two channels whose rules match different alerts
    of the same site; half the devices silent at once, then the hold's
    end both ways.
  * **the sender**: retries on a fake clock, giving up; transient and
    permanent answers; `413` splitting once; a delivery holding its
    channel for an hour, then later ones passing **except those about the
    same alert**, with a `resolved` never ahead of its `opened`; a test
    retrying a held delivery; leases with two workers; the planner and the
    sender on the same channel at once; fair share (one organization's
    receiver that never answers delays no other organization, and a shared
    channel's deliveries counted against the organization charged); one
    unsent digest per people channel; an opened and resolved pair dropped
    unsent; the pending cap; quotas counted in messages; the mail limits
    with account mail first; a retry sending only to recipients not yet
    accepted; the mail circuit.
  * **the address policy**: every range in both policies, embedded IPv4,
    a NAT64 prefix found through `ipv4only.arpa`; the server's own
    addresses, `EASYRMM_IP_ADDRESSES` and the deployment's names; an
    interface and route list given to the policy with a public IPv4
    subnet, a global IPv6 prefix and a static route, addresses in each
    refused until approved; an approval bound to its port; a host change
    clearing it; a name that resolves first to a public and then to a
    private address; **a platform channel and an organization's channel to
    the same host, platform first: the organization's request is
    refused**; an approval withdrawn closing the channel's connections; a
    transport dropped after 10 minutes unused.
  * **errors**: URLs with a path and a query through every failure, never
    in logs or `last_error`; the mail server's reply visible to super
    administrators only.
  * **removal reports**: a report matching a sent instruction deletes the
    device, also after the removal was cancelled; one matching nothing
    marks it and opens the notice; a re-enrolment with the same host name
    resolves the notice.
  * sealed values copied to another row do not open; every reveal is
    audited.
  * the offline rule after a restart: an open offline alert stays open, no
    new one opens early.
  * the engine's handover against `eptest`: paging, an item taken once, an
    acknowledgement lost, an organization not linked, a channel not
    shared, a silent resolution reaching the generic webhook told of it,
    a report's outcome written back once and not overwritten by an older
    one.
* **Rendering**: golden messages for each format and event, with values
  carrying HTML, Slack's `<!channel>`, Markdown, control characters,
  `https://evil.example`, `www.evil.example`, `a@evil.example`, the same
  with U+3002 and U+FF0E for dots, U+202E and U+2028; goldens at each
  budget, measured in encoded bytes; signatures checked against the vector
  frozen from the engine's `NotificationRenderer.Sign`.
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
    edge may listen beyond loopback, as the test checks): plain SMTP on
    loopback until slice 6, then STARTTLS with a certificate from an
    authority made for the run, which the console's mail server names.
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
    webhook and an email channel. On the machine, **both** `easyrmm-agent`
    and `easyrmm-meshagent` are stopped (a device is online while either
    reports); the signed `alerts.opened` and the email arrive; both start
    again; the resolutions arrive.
  * **With slice 4**, the grace set to 10 minutes: the machine is powered
    off through its systemd (`systemctl poweroff` inside it), so its
    container stops with both agents, and stays down 8 minutes, longer
    than the policy plus the 3-minute online window, shorter than the
    grace; nothing opens and nothing is sent; it starts again. The control:
    the same 8 minutes after `systemctl stop easyrmm-agent
    easyrmm-meshagent` open the alert and send it. Then, with an opened
    alert already sent to the webhook, the agent is uninstalled on the
    machine: the `uninstalled` resolution and the *agent removed without a
    request* notice arrive.
  * **With slice 6**: a patching alert from the engine arrives at the same
    receiver.
* **The contract test** starts the engine's worker beside its API: the
  engine's mail settings follow a change (slice 1); a patching alert on a
  rule naming an EasyRMM channel appears in the outbox, in pages; a
  silent resolution and a reopening appear too; acknowledged, items do not
  appear again; a report sent by hand appears as an item, its outcome
  route refuses a statement naming a person, and the outcome written back
  shows on the report; the export answers a channel with its secrets and
  forgets it once moved; the retired routes answer 404; a statement
  naming a person is refused on the outbox and export routes; `eptest`'s
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
  `deliveryId`. Queueing is exactly once, and nothing about an alert
  arrives before what was queued earlier about it.
* Organizations' administrators can have the server make HTTPS requests:
  to public addresses the server reaches by its default route only,
  unless a super administrator approved a destination for that channel.
  The platform's destinations may reach loopback, private addresses and
  the server's own networks, as audit forwarding may today; the engine's
  webhooks never reached loopback or the server's own networks, and
  private addresses only with its switch.
* More secrets rest on `EASYRMM_SECRET_KEY`: channels' URLs and signing
  secrets, and the mail server's password when it is set in the console.
* The MSP's mail relay sends at most what its super administrators allow,
  and account mail always gets through.
* Receivers of the engine's webhooks keep working through the transition;
  they get every alert instead of 25 and a count, silent resolutions and
  reopenings they were not told of before, and new fields. Teams messages
  no longer format names as Markdown, and no format links a device's name.
* A restarting device does not alert within the grace, and a local
  administrator who shuts a computer down delays its offline alert by the
  grace once. An agent can no longer make its device disappear or go quiet
  by its own report.
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
  is checked, none is shared between channels, private ranges, the
  server's networks and anything not on its default route need a super
  administrator's approval for that channel alone, and the server itself,
  loopback and cloud metadata are never reached; no redirect, proxy or
  response body gets back to the person who set the channel up.
* **Messages between tenants.** A platform channel reaches an
  organization's rules only once shared with it, and its details never
  reach an organization's transaction.
* **The MSP's mail relay abused or blocked**: quotas in messages, the
  platform's own limits a minute and a day, account mail first, fixed
  test text, values clipped and defanged, one recipient per message.
  Recipients are not asked to confirm: what a message can carry is
  EasyRMM's own words and short, defanged names.
* **A storm**: a power cut at a large site, or EasyRMM unreachable. Site
  outages, digests merged while unsent, ADR-0052's offline rule for
  restarts, the fleet-wide hold for an EasyRMM nobody can reach, and the
  restart grace keep it to a few messages per channel, and fair share keeps
  one organization's storm from delaying another's.
* **One bad receiver** holds its channel for an hour at most, and after
  that only its messages about the same alerts.
* **A message sent twice** after a crash or a rollback: receivers drop it
  by its delivery ID; the guide says so.
* **A mail server set wrong in the console** stops notifications,
  invitations and password resets at once. The test message comes first in
  the form, the notice says the mail server is the problem, and
  `EASYRMM_SMTP_*` in `.env` takes over when set.
* **Planning stops**: a row that cannot be planned is quarantined and
  raised, its subject waits, and alerting goes on; an evaluation never
  fails because of notifications.
* **Windows' pre-shutdown** is unverified until it is checked on real
  Windows; until then a restarting Windows computer may alert as a plain
  stop would.
* **Slice 6 changes two products at once.** The engine and EasyRMM ship in
  one bundle; pending deliveries become outbox items with their IDs, each
  item waits only for its own channels, and a channel that cannot be
  decrypted moves turned off rather than blocking the rest.
