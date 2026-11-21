# Threat model

EasyRMM can run code as SYSTEM or root on every computer it manages, and
open their screens, terminals and files. Whoever controls it controls those
computers. This page lists what EasyRMM protects, from whom, and where each
boundary is enforced. The decisions behind each control are in the
[architecture decision records](../architecture/adr/README.md).

## What is protected

* **Control of managed computers**: scripts and software actions as
  SYSTEM or root, remote desktop, terminal, files and RDP.
* **Customers' data**: inventory, software lists, metrics, alerts, reports,
  and which computers belong to whom.
* **The audit log**: the record of who did what.
* **Secrets held by the server**: the job-signing key, MeshCentral's
  service account, the audit-forwarding client key, the internal
  certificate authority and active deployment and approval tokens
  (ADR-0047), all sealed in the database under `EASYRMM_SECRET_KEY`; and the key that signs EasyRMM's statements to the
  patching engine (`EASYRMM_PATCHING_KEY`, in `.env`).
* **Accounts**: technicians' passwords, authenticators and security keys.

## Who is guarded against

| Actor | Can | Must not be able to |
|---|---|---|
| Anyone on the internet | Reach the sign-in page, the agent API, and MeshCentral's agent routes | Sign in without a password and second factor, enroll without a deployment token or approval, or reach MeshCentral as a user |
| A technician, by role | Act on the sites and session types their roles grant | Act on another site or organization, or do more on a device than their grant allows |
| An organization's administrator | Manage their organization's sites and users | Grant roles above their own, see other organizations, or learn their names |
| A managed computer's agent, even if compromised | Report its own facts and inventory, take its own jobs | Act as another device, see other devices' work, change what runs elsewhere, or exhaust the server |
| A standard user on a managed computer | Use the computer | Change what the agent runs as SYSTEM or root, or read its key or deployment token |
| A network attacker between agent and server | Delay or drop traffic | Read or change it, or impersonate either side |

Trusted: the operator with access to the server host, its environment and
its database, and Super Administrators, who hold every permission
everywhere. MeshCentral and the patching engine are trusted to enforce
their own rights, and EasyRMM narrows what reaches them.

## Boundaries and their controls

**Browser to server** ([ADR-0006](../architecture/adr/0006-sessions-and-mfa.md), [ADR-0032](../architecture/adr/0032-webauthn-passkeys.md), [Signing in](sign-in.md))
* Opaque session cookies. A second factor is required for every account
  (`EASYRMM_REQUIRE_MFA`, on unless the operator turns it off).
* CSRF tokens bound to the session, plus Origin and Fetch Metadata checks.
* Rate limits and lockouts on passwords and second factors.
* Re-entering the password for sensitive changes.

**Between tenants** ([ADR-0002](../architecture/adr/0002-postgresql-rls-tenant-isolation.md), [Roles and permissions](rbac.md))
* Every tenant table has forced row-level security under the caller's
  scope.
* Above it, every action checks the permission against the organization
  and site stored in the row.
* Granting is limited by rank and scope.

**Agent to server** ([ADR-0015](../architecture/adr/0015-enrollment-and-meshagent-delivery.md), [ADR-0024](../architecture/adr/0024-enrollment-approval.md))
* Enrollment needs a deployment token, or approval in the console.
* After enrollment, each request is signed with the device's own Ed25519
  key: method, target, time, nonce and body. Nonces are used once.
* The header is checked before the body is read, and each device has
  rate limits.

**Server to agent** ([ADR-0017](../architecture/adr/0017-scripts-and-jobs.md), [ADR-0027](../architecture/adr/0027-agent-updates.md), [ADR-0031](../architecture/adr/0031-easypatch-agent-install.md))
* Jobs, agent updates and EasyPatch agent installs are instructions signed
  with the server's job key. The agent pins that key at enrollment.
* Each instruction is bound to one device and expires.
* Updates are checked by hash and size before they run, and rolled back
  if the new build fails.
* TLS is verified against public authorities, a given authority, or the
  server's own authority. The install command fetches that authority over
  a connection pinned to the server's key.

**On the managed computer** ([ADR-0020](../architecture/adr/0020-windows-agent.md), [ADR-0028](../architecture/adr/0028-software-deployment.md))
* The agent's state (key, configuration, job journal) can be changed only
  by SYSTEM or administrators on Windows, and by root on Linux.
* On Windows, where any user may create folders under ProgramData, the
  agent checks its state folder before any command reads it and before
  the service opens its log. It moves aside a folder, or a file it reads
  or writes there, that someone else made, that others could change, or
  that is a link. It never reads what it moved aside. "Others" is anyone
  but the system, administrators and TrustedInstaller with a right to
  write, delete, or change the access list or owner; an access list that
  differs but gives no one else such a right is set back.
* Package managers' programs are run only if only administrators can
  change them.
* cmd arguments that could break out of their quotes are refused.

**Browser to MeshCentral** ([ADR-0004](../architecture/adr/0004-meshcentral-dedicated-origin.md), [ADR-0005](../architecture/adr/0005-meshcentral-identity-and-sessions.md), [ADR-0014](../architecture/adr/0014-remote-access-gateway-and-device-discovery.md), [ADR-0022](../architecture/adr/0022-gateway-relay-restrictions.md), [ADR-0033](../architecture/adr/0033-relays-bound-to-grants.md))
* MeshCentral is reachable only through EasyRMM's gateway, on an origin
  of its own.
* Each technician has a MeshCentral account with the fewest rights the
  role needs.
* Each session is a grant for one device and one session type, and is
  audited.
* The gateway passes only what the grant covers:
  * relays of that type to that device;
  * tunnel requests bound to the grant;
  * device messages that belong to the session type.
* No TCP or UDP routing.
* The agent path carries no user credentials.

**EasyRMM to the patching engine** ([ADR-0038](../architecture/adr/0038-statements-to-the-patching-engine.md), [ADR-0046](../architecture/adr/0046-what-one-product-retires.md))
* The engine's API listens on loopback only. People reach patching through
  EasyRMM's console and API; the engine has no console or sign-in of its
  own.
* EasyRMM checks its own permissions first, then signs one statement per
  call: HS256 with a key only the two programs read, valid for 30 seconds,
  for one method and request target, naming the person, the role that call
  needs and the organizations it concerns.
* The engine checks the signature before reading anything, refuses a
  statement for another request, an expired one, or any when it has no key,
  and applies its own role and organization checks to what the statement
  says: the second of two independent checks.
* The edge strips the statement header, cookies and `Forwarded` from what
  it passes to the engine's agent paths, the only engine paths it serves.
* A statement can be replayed for the same request within its 30 seconds
  by someone who can read loopback traffic; such a person could read the
  key too.

**EasyPatch agent to the patching engine** ([ADR-0031](../architecture/adr/0031-easypatch-agent-install.md), [ADR-0039](../architecture/adr/0039-agents-on-easyrmms-name.md), [Patching engine](../architecture/patching-engine.md#agent-protocol))
* EasyRMM enrolls each EasyPatch agent with a single-use token, valid for
  an hour, made for that one install and passed to the agent off the
  command line. The engine stores only its hash, and has no other way to
  enroll: no codes, approvals or install scripts
  ([ADR-0048](../architecture/adr/0048-the-engine-keeps-what-is-reached.md)).
* The agent makes its own ECDSA P-256 key and keeps the private half on
  the computer: DPAPI in a folder only SYSTEM and administrators can open,
  or root-only files on Linux, encrypted with `systemd-creds` where
  available. Credentials expire after a year, are rotated before, and are
  revoked with their endpoint.
* Each request is signed over method, target, time, nonce, body hash and
  credential; nonces are used once, and the endpoint comes from the
  credential, never from the body.
* EasyRMM's edge forwards only the agents' API and package downloads to
  the engine.
* The agent runs no commands. It installs only what its own scan found
  from the sources the computer is configured for, upgrades of approved
  winget applications already installed, or a signed agent package. The
  engine cannot name a package, version, repository or installer
  argument. Restart and message jobs carry only a mode, range-checked
  durations or a preset message. Windows Update changes are limited to
  listed values, never the WSUS server, and are restored when removed.
* The tray reaches the service over a local pipe that refuses network
  logons and session 0, and accepts only an answer to the current restart
  request and three status requests without parameters.

**EasyPatch agent packages** ([Agent release signing](../architecture/patching-engine.md#agent-release-signing))
* An EasyPatch agent updates only to a package signed with a release key
  built into it, newer than itself, with the signed size and SHA-256. The
  release workflow signs; the engine relays packages and signatures and
  cannot supply keys.
* The agent installs winget only from files whose sizes and SHA-256 are
  built into it.

**The patching engine to the internet** ([Patching engine](../architecture/patching-engine.md#alerts-and-notifications))
* Only the engine's worker connects out: to fixed vulnerability-feed hosts
  over HTTPS without redirects, to GitHub for winget, to the mail server
  and to webhooks. Feed data is parsed as data with size limits and can
  change only what is shown and whether a rollout delay is skipped.
* Webhooks are `https://` only, follow no redirects and use no proxy.
  Every address connected to is checked: loopback, link-local and cloud
  metadata, multicast and the server's own networks are always refused,
  private ranges unless a super administrator allows them.
* Webhook addresses, signing keys and the SMTP password are encrypted with
  the engine's own keys and never returned.

**Authentik, when chosen** ([ADR-0044](../architecture/adr/0044-authentik-when-chosen.md))
* Authentik listens on loopback only, with metrics, update checks,
  analytics and error reports off. EasyRMM's edge serves its name and
  passes it to loopback.
* Its groups never grant roles in EasyRMM: roles are granted in EasyRMM
  only, so whoever edits groups in Authentik cannot make anyone an
  administrator.
* EasyRMM's provider for it is set by the deployment and cannot be changed
  in the console. EasyRMM reaches Authentik through its own edge on
  loopback, verifying TLS, with no redirects followed.
* When single sign-on is down, `easyrmm-server recover`, run on the server,
  prints a link for a super administrator that works once, for 15 minutes,
  and is stored only as a hash.

**Server to integrations** ([ADR-0023](../architecture/adr/0023-audit-forwarding.md))
* Only Super Administrators configure audit forwarding.
* Its secrets are sealed and never shown again.
* TLS is verified.
* Link-local and cloud metadata addresses are refused.

**The record** ([ADR-0007](../architecture/adr/0007-hash-chained-audit-log.md))
* The application's database role can only append to the audit log, and
  edits are rejected even for the owner.
* Records are hash-chained so that changes can be detected. Retention
  deletes only records past the configured period (at least 30 days).
* The log can be forwarded off the server as it is written.

## Known limits

* Super Administrators and the server's operator are fully trusted: they
  can run anything on every managed computer.
* A computer that trusts the internal certificate authority would trust
  a certificate signed with its key for any site
  ([ADR-0016](../architecture/adr/0016-ip-address-access.md)).
* Remote sessions depend on MeshCentral and MeshAgent enforcing their own
  rights, which EasyRMM narrows but does not replace.
* A compromised patching engine can choose which signed, newer EasyPatch
  agent release an agent updates to, and when, but nothing unsigned or
  older.
* The engine's nonce cache is in memory, so a deployment runs one engine
  API instance.
* The engine's encryption keys, like the database, are unencrypted on the
  host; root there can read the webhook secrets.
* What the [security review](security-review.md) did not cover.
