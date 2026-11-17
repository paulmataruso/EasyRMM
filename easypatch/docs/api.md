# EasyPatch REST API

Administrator and agent routes are versioned under `/api/v1`. JSON uses camelCase, enums are
serialized as strings, and timestamps are ISO-8601 in UTC.

The live OpenAPI document is served at `/api/openapi/v1.json`, with Swagger UI at
`/api/docs`. Both require a signed-in session (any role).

## Conventions

| Topic | Rule |
|---|---|
| Authentication | Admin routes use the session cookie `__Host-easypatch-session`, or an [API token](#api-tokens-apiv1api-tokens-superadmin) sent as `Authorization: Bearer ept_…`. A request with a session cookie is authenticated by the session and any bearer token is ignored. Agent routes use signed requests ([security.md](security.md#agent-request-signing)). |
| CSRF | Unsafe admin methods (POST, PUT, PATCH, DELETE) must send `X-XSRF-TOKEN` with the value of the `XSRF-TOKEN` cookie. `POST /auth/login` and `POST /auth/password/reset` are exempt, as are requests authenticated with an API token (browsers never send one on their own). A missing or wrong header returns `403` with `code=csrf_failed`. |
| Correlation | `X-Correlation-ID` is accepted (max 64 characters of `[A-Za-z0-9-_.]`) or generated. It is returned on every response and included in error bodies and logs. |
| Pagination | Paged routes take `?page=1&pageSize=50` (maximum 200) and return `{ items, page, pageSize, totalCount }`. Organizations, sites, users, tokens, deployment codes and the per-endpoint update lists are returned as plain arrays. |
| Sorting | `GET /endpoints` and `GET /updates` accept `?sort=<field>&dir=asc|desc`; the fields are listed below. Unknown fields fall back to the default order. |
| Errors | RFC 9457 `application/problem+json` with the extensions `code` (machine-readable) and `correlationId`. Validation errors (`400`, `code=validation_failed`) add `errors` (field → messages). Some errors carry extra members, such as `existingJobId` on `409 duplicate_job`. |
| Rate limits | Login and other password/MFA operations: 20/min per IP. Enrollment: 30/min per IP. Agent routes: 120/min per credential. Downloads: 60/min per IP. All other admin routes: 600/min per user or API token. Exceeding a limit returns `429` with `code=rate_limited` and `Retry-After`. The limits can be changed with the `RateLimits:*` settings. |
| Roles | **Viewer** = any role (ReadOnly, Admin, SuperAdmin). **Operator** = Admin or SuperAdmin. **SuperAdmin** = SuperAdmin only. Users and API tokens restricted to some organizations only see those organizations; anything outside them answers `404`. API tokens are ReadOnly or Admin, never SuperAdmin, and cannot use the `/auth` routes. |

## Agent protocol (`/api/v1/agents`)

| Method | Route | Auth | Purpose |
|---|---|---|---|
| POST | `/enroll` | none (token or deployment code in the body) | Register a public key. Linux and macOS agents add `platform`, `osId` and `osVersion` to the device description. Returns `Active` (with `endpointId`, `credentialId` = `c_…`, `config`) or `PendingApproval` (with `credentialId` = `r_…`). |
| POST | `/enrollment/status` | signed with `r_…` | Poll a pending enrollment: `PendingApproval`, `Active` (with the new `c_…` credential), `Rejected` or `Expired`. This is the only route an `r_…` credential may call. |
| POST | `/check-in` | signed | Combined heartbeat and job poll. Request: agent version, boot time, reboot state and reasons, IDs of jobs the agent holds, current activity, capabilities, signed-in user and tray counts, the Windows Update policy status (only when it changed, and at least daily), and for self-update the package architecture (`agentArchitecture`, `x64` or `arm64`), the package format (`agentPackageFormat`: `msi`, `deb`, `rpm` or `pkg`; absent before 1.3.0 means `msi`; an agent is only offered packages of a format that belongs to its platform) the IDs of the release keys built into the agent (`releaseKeyIds`) and, from 1.7.0, the winget status (`winget`: `version`, `installedByAgent`, `setupError`, `checkedAt`). Response: server time, config (including the tray and notification settings, the effective Windows Update settings and, while application updates are on, `applications`: `{enabled, approvedApps}`), jobs to run (at most one newly leased job, up to five messages, plus re-deliveries), IDs of jobs to cancel, `rotateCredential`, latest available agent version. |
| POST | `/inventory` | signed | OS and hardware inventory. Linux agents also send `platform` (`Linux`; absent means `Windows`), `osId` and `osVersion` from `/etc/os-release`, the kernel version, the package manager and how the private key is protected. The experimental macOS agent sends `platform` `macOS`, `osId` `macos`, `osVersion` and `osBuildVersion` from `sw_vers`, the Darwin kernel version, `softwareupdate` as the package manager and `file-permissions` as the key protection. `204`. |
| POST | `/updates/scan-results` | signed | Full scan snapshot (missing and installed updates, update source). Linux updates carry a `package` object: name, architecture, installed and new version, repository, `security`, severity and advisories. Application updates (agent 1.4.0, Windows) carry an `application` object (`id`, `version`, `installedVersion`, `source`), and the report has an `applications` section with the result of the winget check (`succeeded`, `errorCode`, `errorMessage`, `wingetVersion`, `checked`); it is absent when application updates are off. Idempotent by `scanId`. `204`. |
| POST | `/updates/history` | signed | Windows Update history entries, deduplicated on the server. `204`. |
| POST | `/jobs/{jobId}/ack` | signed | Confirm receipt of a delivered job. `409` with `code=job_cancelled` if it was cancelled or already finished. |
| POST | `/jobs/{jobId}/status` | signed | Progress, per-update results and final status. Each report carries a per-job `sequence`; stale or repeated reports are ignored. `204`. An impossible transition returns `409 invalid_transition`. |
| POST | `/credentials/rotate` | signed (current key) | Register a new public key and return the new `credentialId`. Idempotent per key. The old credential stays valid for one hour. |
| POST | `/unenroll` | signed | Called when the agent is uninstalled (best effort). Marks the endpoint decommissioned and revokes its credentials. `204`. |

Agent authentication failures return `401` with one of these codes: `invalid_signature`,
`clock_skew` (the body includes `serverTime`), `replayed_nonce`, `unknown_credential`,
`credential_revoked`, `credential_expired`, `endpoint_revoked`. An `r_…` credential calling
any route other than `/enrollment/status` gets `403 enrollment_invalid`.

The original spec had separate routes for heartbeat, job polling and install results. These
are merged: heartbeat and job polling are `/check-in`, and install results are part of
`/jobs/{jobId}/status`. This avoids redundant traffic, and every report about a job flows
through one sequence-numbered channel.

## Downloads (anonymous)

| Method | Route | Purpose |
|---|---|---|
| GET | `/downloads/agent/{fileName}` | Agent package (MSI, `.deb` or `.rpm`) from the package directory. Agents download updates here too. |
| GET | `/downloads/winget/{fileName}` | One of the three files of the pinned winget release, for Windows agents (1.7.0 and later) that cannot download it from GitHub. Other names return `404`. Served only after the server has verified the file's size and SHA-256; range requests are supported. When the server has no verified copy yet it returns `503` with `Retry-After: 900` and problem code `winget_not_ready`, and the worker downloads the release from GitHub. |
| GET | `/downloads/install/{deploymentCode}.ps1` | The tokenless install script for a deployment code (`?requireSignature=true` adds an Authenticode check). Returns `404` for an unknown, expired or revoked code and `503` when no agent package is available; both bodies are a PowerShell `throw`, so a piped one-liner fails loudly. |
| GET | `/downloads/install/{deploymentCode}.sh` | The tokenless Linux install script (POSIX `sh`) for a deployment code, with the newest `.deb` and `.rpm` package for each architecture and their SHA-256. `404` for an unknown, expired or revoked code and `503` when no Linux package is available; both bodies are shell that prints the error and exits with status 1. |
| GET | `/downloads/install/macos/{deploymentCode}.sh` | The tokenless install script (POSIX `sh`) for the experimental macOS agent, with the newest `.pkg` package for each architecture and their SHA-256. `404` for an unknown, expired or revoked code and `503` when no macOS package is available, as for Linux. |

These routes are outside `/api/v1`, need no session and are limited to 60 requests per
minute per IP. The install scripts contain no secret: endpoints installed with it wait for
administrator approval.

## Administrator API

### Authentication (`/api/v1/auth`)

| Method | Route | Notes |
|---|---|---|
| POST | `/login` | `{email, password}` → `{mfaRequired, mfaSetupRequired, user}`. The email address is the only sign-in name (case does not matter). Sets the session and `XSRF-TOKEN` cookies. A wrong address or password, an inactive or a locked account all answer `401 invalid_credentials`. |
| POST | `/mfa/verify` | `{code}` (TOTP or recovery code) completes the sign-in; for a security key see `/mfa/webauthn` below |
| POST | `/logout` | Revokes the current session |
| GET | `/me` | Current user, role and MFA state. Also refreshes the `XSRF-TOKEN` cookie. |
| POST | `/mfa/setup` | Returns the secret, the `otpauth` URI and a QR code as a PNG data URI |
| POST | `/mfa/enable` | `{code}` → 10 recovery codes, shown once |
| POST | `/mfa/disable` | `{password, code}` removes the authenticator app. While the `RequireMfa` server setting is on, refused (`409 mfa_required`) unless a security key or passkey remains. |
| POST | `/mfa/recovery-codes` | `{password}` → a new set of recovery codes |
| GET | `/webauthn` | Anonymous. `{available, rpId, reason, message}`: whether passkeys and security keys work here. `reason` is `ip_address`, `not_https` or `invalid_public_url` when not. |
| POST | `/webauthn/register/options` | `{passkey, password?}` → `PublicKeyCredentialCreationOptions` JSON (binary members base64url). `passkey: true` asks for a discoverable credential with user verification. The password is needed when the account already has a second factor and the sign-in is more than 10 minutes old (`400 invalid_password`). |
| POST | `/webauthn/register` | `{name?, credential}` (the browser's `PublicKeyCredential` as JSON) → `{credential, recoveryCodes}`. Recovery codes are returned once, for the account's first second factor. `400 webauthn_failed` when verification fails. |
| GET | `/webauthn/credentials` | Your passkeys and security keys: `{id, name, isPasskey, isSynced, transports, createdAt, lastUsedAt}` |
| PUT | `/webauthn/credentials/{id}` | `{name}` renames one |
| POST | `/webauthn/credentials/{id}/remove` | `{password?}` (as for registration). The last second factor cannot be removed while MFA is required (`409 mfa_required`). |
| POST | `/mfa/webauthn/options` | During sign-in, after the password: `PublicKeyCredentialRequestOptions` JSON for the account's keys |
| POST | `/mfa/webauthn` | `{credential}` completes the sign-in with a security key or passkey (`401 invalid_security_key` otherwise) |
| POST | `/passkey/options` | Anonymous. Starts a passkey sign-in: request options with an empty allow list and user verification required. Sets a short-lived `__Host-easypatch-webauthn` cookie that binds the sign-in to this browser. |
| POST | `/passkey` | Anonymous. `{credential}` → `{mfaRequired: false, mfaSetupRequired: false, user}` and the session cookies, like `/login`. `401 invalid_passkey` when the passkey is unknown or does not verify. |
| POST | `/passkey-prompt/dismiss` | "Not now" to the offer to create a passkey; `user.passkeyPrompt` is false for 30 days |

Every WebAuthn route answers `409 webauthn_unavailable` when the console's public URL is an IP
address or not HTTPS, and `400 webauthn_challenge_expired` when the challenge is older than 5
minutes, was already answered, or (passkey sign-in) belongs to another browser. `/me` and the
sign-in responses include `totpEnabled`, `securityKeyCount`, `passkeyCount`, `passkeyPrompt` and
`hasPassword` (false for an account created by single sign-on); `mfaEnabled` is true for either
kind of second factor. For an account without a password, `/mfa/disable`, `/mfa/recovery-codes`
and the WebAuthn routes that take a password accept a sign-in within the last 10 minutes instead
(otherwise `403 reauthentication_required`).

### Single sign-on (OpenID Connect)

Browser routes under `/api/v1/auth/sso` (anonymous, sign-in rate limit). See
[single-sign-on.md](single-sign-on.md).

| Method | Route | Notes |
|---|---|---|
| GET | `/providers` | Enabled providers for the sign-in page: `[{id, displayName}]` |
| GET | `/{id}/start?returnTo=` | Redirects (302) to the provider's authorization endpoint and sets the `__Host-easypatch-sso` binding cookie. `returnTo` must be a console path. On error, redirects to `/login?sso_error=unavailable` |
| GET | `/callback?code=&state=` | The redirect URI. Signs in and redirects to `returnTo` (the console then asks for MFA if needed), or to `/login?sso_error=` with `expired`, `denied`, `no_account`, `unavailable` or `failed` |

Provider settings (`/api/v1/sso/providers`, SuperAdmin):

| Method | Route | Notes |
|---|---|---|
| GET | `/` | `{redirectUri, providers[]}`. A provider has `clientSecretConfigured`, never the secret, and `linkedUsers` |
| POST | `/` | `{displayName, issuer, clientId, clientSecret, scopes, enabled, trustEmailClaim, providerEnforcesMfa, autoProvision, defaultRole, allowedDomains[]}` → `201`. `defaultRole` cannot be `SuperAdmin`; `autoProvision` needs at least one domain; `scopes` must include `openid` |
| PUT | `/{id}` | As POST. `clientSecret: null` keeps the stored secret, `""` removes it |
| DELETE | `/{id}` | Removes the provider and its links to users |
| POST | `/probe` | `{issuer}` → `{ok, issuer, authorizationEndpoint, tokenEndpoint, signingKeys, message}` after reading the discovery document and key set |
| POST | `/password/change` | `{currentPassword, newPassword}`. Revokes your other sessions. |
| POST | `/email/change` | `{currentPassword, newEmail}` → `204`. Changes your own email address, the one you sign in with (stored lower-case). `400 invalid_password`, `400 validation_failed` for an invalid address, `409 email_in_use` when another user has it. An account without a password (created by single sign-on) sends no password and needs a sign-in within the last 10 minutes (`403 reauthentication_required` otherwise). Your sessions stay signed in, and linked single sign-on accounts stay linked; the change is in the audit log (`auth.email_changed`). |
| POST | `/password/reset` | `{token, newPassword}`. Anonymous; the token comes from an administrator-issued link. |
| GET | `/sessions` | Your active sessions |
| DELETE | `/sessions/{id}` | Revoke one of your sessions |

Until a user has completed every sign-in step, other routes answer `403` with
`code=mfa_required`, `mfa_setup_required` or `password_change_required`.

### Users (`/api/v1/users`, SuperAdmin)

`GET /`, `POST /` (`{username, email, role, password, organizationIds}`; without a password
the response contains a one-time set-password link), `GET /{id}`, `PUT /{id}` (`email`, `role`,
`isActive`), `POST /{id}/reset-link`,
`POST /{id}/mfa/reset` (removes the authenticator app, passkeys, security keys and recovery
codes), `POST /{id}/sessions/revoke`, `GET /{id}/external-logins` (linked single sign-on
accounts), `DELETE /{id}/external-logins/{linkId}`, `PUT /{id}/organizations`
(`{organizationIds[]}`; an empty list means all organizations). An email address that another
user has (ignoring case) answers `409 email_in_use`, a taken username `409 username_in_use`,
and an address that is not a plain `name@domain` `400 validation_failed`.

### API tokens (`/api/v1/api-tokens`, SuperAdmin)

Bearer credentials for scripts and integrations. Only super administrators signed in to the
console manage them; a token cannot create, list or revoke tokens.

| Method | Route | Notes |
|---|---|---|
| GET | `/` | Every token, active first: name, display prefix, role, organizations, expiry, last use (time and address), creator, revocation, `status` (Active, Expired, Revoked). The secret is never returned. |
| POST | `/` | `{name, role, organizationIds[], expiresInDays}` → `201 {token, secret}`. `role` is `ReadOnly` or `Admin`; an empty `organizationIds` means every organization; `expiresInDays` is 1 to 365; `name` (up to 50 characters) must be unique among tokens that are not revoked (`409 name_taken`). The `secret` (`ept_…`) is shown once; the server keeps only its SHA-256 hash. |
| POST | `/{id}/revoke` | Revokes the token immediately. Revoking twice is harmless. |

A token acts with its role in its organizations, like a user with the same role and
organization access: a ReadOnly token gets the Viewer routes, an Admin token also gets the
Operator routes. SuperAdmin routes answer `403`, and the `/auth` routes (your account, MFA,
sessions) answer `401`. A missing, unknown, expired or revoked token answers `401` with
`code=unauthenticated`. Actions are audited with the user name `token:<name>`.

```bash
curl -H "Authorization: Bearer $EASYPATCH_TOKEN" https://patch.example.com/api/v1/endpoints
```

### Organizations, sites and policy

Reads are Viewer; writes are Operator. Creating an organization requires a user who is not
restricted to specific organizations.

| Method | Route |
|---|---|
| GET/POST | `/organizations` (`?search=&includeArchived=`; each item includes endpoint, online, offline and missing counts and compliance) |
| GET/PUT/DELETE | `/organizations/{id}` (DELETE returns `409 has_endpoints` while the organization has endpoints) |
| POST | `/organizations/{id}/archive`, `/organizations/{id}/restore` |
| GET/POST | `/organizations/{id}/sites` (each site includes `endpointCount` and `rebootPendingCount`, its active endpoints that report a pending restart) |
| GET | `/organizations/{id}/endpoints` (same filters as `/endpoints`) |
| GET/PUT/DELETE | `/organizations/{id}/policy` |
| GET/PUT/DELETE | `/sites/{id}` |
| POST | `/sites/{id}/archive`, `/sites/{id}/restore` |
| GET | `/organizations/{id}/restart-pending?siteId=` | Viewer. The active endpoints of the organization (or of one of its sites) whose operating system reports a pending restart: `{total, endpoints[]}`, each `{id, hostname, siteId, siteName, platform, operatingSystem, isServer, isOnline, rebootPendingSince, canRestart}`, sorted by hostname, at most 1000. `isServer`: Windows Server or a domain controller; `canRestart`: the agent supports restart jobs. `404` for a site of another organization |
| POST | `/organizations/{id}/restart-pending` | Operator. "Restart all that need it": `{siteId?, endpointIds[], restart: {…as for /endpoints/{id}/restart}}` with the endpoints the administrator confirmed (1 to 1000). Each endpoint that is still an active endpoint of the organization (and of `siteId`, when given) and still reports a pending restart gets a restart job; the condition is always `OnlyIfPending`. Per-endpoint outcome as for bulk jobs; skipped endpoints have `errorCode` `out_of_scope` (no host name is returned) or `no_restart_pending` |
| GET/PUT/DELETE | `/sites/{id}/policy` |
| GET/PUT/DELETE | `/endpoints/{id}/policy` (an endpoint override; GET returns an empty policy when there is none; `maxConcurrentInstallsPerSite` cannot be set here) |
| GET/PUT | `/policies/global` (PUT is SuperAdmin) |

A policy body has nullable fields; `null` inherits from the level above. Besides the install
and schedule fields it has `trayIconEnabled`, `installNotificationsEnabled`,
`agentAutoUpdateEnabled` (*Agent updates*: `true` Automatic, `false` Manual; the global default
is `true`), `restartSchedule` (`{enabled, days[0-6], time "HH:mm", condition, mode, countdownMinutes,
deadlineMinutes, expiryMinutes}`) and `windowsUpdate`. `windowsUpdate` has one entry per group
(`automaticUpdates`, `featureUpdates`, `qualityUpdates`, `restartBehavior`), each `null`
(inherit), `{managed: false}` (*Not configured*) or `{managed: true, value: {…}}`.
`securityInstallDelayDays` (0 to 90) and `installDelayDays` (0 to 365) set the rollout delay;
`knownExploitedSkipsDelay` (default `true`) lets updates that fix a CISA known-exploited vulnerability skip it.
`preDownloadHours` (0 to 24, default `0` = off) downloads updates up to that many hours before the maintenance window
opens, with automatic installation (see [architecture.md](architecture.md#downloading-before-the-maintenance-window));
the effective policy returns it too.
`applicationUpdates` (`{enabled, approvedApps[]}`, at most 100 winget package IDs such as
`Mozilla.Firefox`) turns on [application updates](application-updates.md); it replaces the
inherited value as a whole, and IDs are trimmed and de-duplicated. `allowedCategories` cannot
contain `Application`: applications are approved by ID instead.
Invalid values return `400 validation_failed`.

### Tags

| Method | Route | Notes |
|---|---|---|
| GET | `/tags` | Viewer. Every tag (`id, name, color, description, priority, endpointCount, hasPolicy, siteCount, organizationCount`). `endpointCount` counts endpoints with the tag directly or through their site or organization. Organization-restricted users get only the tags on their endpoints, sites and organizations, with the counts 0. |
| POST | `/tags` | SuperAdmin. `{name (1-40), color, description?, priority (0-1000)}`. `color`: `gray, blue, green, amber, red, purple, teal, pink`. `409 tag_exists` for a duplicate name (case-insensitive). |
| PUT/DELETE | `/tags/{id}` | SuperAdmin. DELETE removes the tag from every endpoint, site and organization and deletes its policy. |
| GET/PUT/DELETE | `/tags/{id}/policy` | SuperAdmin. A policy body as above; `maxConcurrentInstallsPerSite` cannot be set. |
| PUT | `/endpoints/{id}/tags` | `{tagIds[]}` replaces the endpoint's own tags (at most 20). Operator without organization restrictions. |
| PUT | `/organizations/{id}/tags`, `/sites/{id}/tags` | `{tagIds[]}` replaces the tags of an organization or site (at most 20). Every endpoint of the organization or site has these tags, and their tag policies apply to it. Operator without organization restrictions. Organization and site responses include their `tags`. |
| POST | `/endpoints/tags/bulk` | `{endpointIds[], addTagIds[]?, removeTagIds[]?}` → `{changed}`. At most 1000 endpoints. Operator without organization restrictions. |
| GET | `/endpoints/{id}/tag-policies` | Viewer. The tag policies that apply to the endpoint, in resolution order (`{tag, priority, policy}`). |

### Alerts and notifications

| Method | Route | Notes |
|---|---|---|
| GET | `/alerts` | Viewer, filtered to the user's organizations. `?status=unresolved` (default) `\|open\|acknowledged\|resolved\|all`, `severity` (`Critical, Warning, Info`), `organizationId`, `endpointId`, `ruleType`, `search` (title), paging. Unresolved first, then by severity and newest. Each item: rule, type, severity, status, title, details, organization, endpoint and host name, opened/last seen/resolved/acknowledged times and who acknowledged. |
| GET | `/alerts/summary` | Viewer. `{open, acknowledged, critical, warning, info}` over unresolved alerts the user can see (`open` excludes acknowledged ones). |
| POST | `/alerts/acknowledge` | Operator. `{alertIds[]}` (1-500) → `{acknowledged}`. Only open alerts the user can see are acknowledged; acknowledged alerts get no reminders. |
| GET | `/alert-rules/types` | SuperAdmin. Per rule type: threshold unit, minimum, maximum, default, and whether a tag filter is allowed. |
| GET/POST | `/alert-rules` | SuperAdmin. `{name, type, enabled, severity, threshold?, organizationId?, tagId?, channelIds[]?, notifyOnResolve, renotifyHours (0-720)}`. Types and thresholds: `EndpointOffline` (hours, 1-720), `InstallFailed`, `SecurityUpdateMissing` (days after the update became required, 0-365), `ScanStale`, `RestartPending` (days, 1-90), `EnrollmentPending` (no tag), `OsUnsupported` (days before end of support, 0-365), `KnownExploitedMissing`, `UpdateHeld` (no tag; one alert per organization). At most 20 channels. GET items add `thresholdUnit` and `unresolvedAlerts`. |
| PUT/DELETE | `/alert-rules/{id}` | SuperAdmin. Changing the type, threshold, organization or tag, disabling the rule or deleting it closes its unresolved alerts without notifications. |
| GET/PUT | `/notifications/settings` | SuperAdmin. `{smtpHost, smtpPort, smtpSecurity (StartTls, SslOnConnect, None), smtpSkipCertificateValidation, smtpUsername, smtpPassword, fromAddress, fromName, allowPrivateNetworkWebhooks}`. `smtpSkipCertificateValidation` (default `false`) accepts any certificate from the SMTP server; it is stored as `false` when `smtpSecurity` is `None`. `smtpPassword`: `null` keeps the stored password, `""` removes it. GET never returns the password, only `smtpPasswordConfigured`. |
| GET/POST | `/notifications/channels` | SuperAdmin. `{name, type (Email, Webhook), enabled, emailRecipients[] (1-20 plain addresses), webhookFormat (Generic, Slack, Teams), webhookUrl (https)}`. Responses are `{channel, signingSecret}`; `signingSecret` is set only when a generic webhook is created (shown once). Channels show `webhookHost` and `hasSigningSecret`, never the URL or the secret, plus the last delivery. |
| PUT/DELETE | `/notifications/channels/{id}` | SuperAdmin. PUT with `webhookUrl: null` keeps the stored URL. DELETE removes the channel from every rule and discards its queued notifications. |
| POST | `/notifications/channels/{id}/rotate-secret` | SuperAdmin. Generic webhooks: a new signing secret (shown once); the old one stops working. |
| POST | `/notifications/channels/{id}/test` | SuperAdmin. Queues a test notification → `202` with the delivery. `429 test_rate_limited` within 30 seconds of the previous test of the same channel. |
| GET | `/notifications/deliveries` | SuperAdmin. `?channelId=&status=` (`Pending, Sent, Failed`), paging. Subject, kind, status, attempts, last error (sanitized), times. |

### Endpoints

| Method | Route | Notes |
|---|---|---|
| GET | `/endpoints` | Filters: `organizationId, siteId, search, compliance, online, os, rebootPending, outdatedAgent, status, tagId, knownExploited`. Each item includes `tags` (with `inheritedFrom`: `null` for the endpoint's own tags, `Site` or `Organization` for tags it has through its site or organization; `tagId` matches all three), `missingDeferredCount` (updates inside their rollout delay) and `knownExploitedMissingCount` (outstanding allowed updates that fix a CISA known-exploited vulnerability). Sort: `hostname` (default), `organization, site, os, missing, knownExploited, lastCheckIn, compliance, agentVersion`. |
| GET/PUT/DELETE | `/endpoints/{id}` | GET includes `platform` (`Windows`, `Linux` or `macOS`) and, for Linux, `linux`: `osId`, `osVersion`, `kernelVersion`, `packageManager`, `keyProtection`; for macOS (experimental), `macOS`: `osId`, `osVersion`, `osBuild`, `kernelVersion`, `packageManager`, `keyProtection`. For Windows, `applications` describes application updates: `enabled` (effective policy), `supported` (agent 1.4.0 or newer), `approvedApps` (count), `wingetVersion`, `lastCheckAt`, `lastError`, `wingetSetupError` (why the agent could not install winget, 1.7.0 and later) and `serverCopyError` (why the server could not download its own copy, shown with a setup error). PUT: `siteId`, `notes`, `esuOverride`. DELETE revokes the credentials and removes the record. |
| POST | `/endpoints/{id}/revoke` | `{reason?}`. Revokes all credentials; the agent can no longer call the server. |
| GET | `/endpoints/{id}/updates` | `?state=&category=&requiredOnly=`. Missing, failed, pending-reboot, pending-verification, reoffered and excluded updates, with the live state of an active job overlaid (`activeJob`; its `jobType` is `InstallUpdates` or `UninstallUpdate`). `deferredUntil` is set while an update is inside its rollout delay; `holdReason` while a missing or failed update is on hold. `cveIds`, `knownExploited` and `kevDueDate` (the earliest CISA due date) describe the vulnerabilities the update fixes on this endpoint; known-exploited updates are listed first within each state. Linux updates include `package` (name, architecture, version, the endpoint's installed version, repository, advisories). Application updates (category `Application`) include `package` with the winget package ID as the name, the target and installed versions and `winget` as the repository. |
| GET | `/endpoints/{id}/installed-updates` | Updates confirmed installed by a scan, with an active removal job overlaid (`activeJob`) |
| GET | `/endpoints/{id}/update-history` | Windows Update history, or for macOS endpoints `softwareupdate --history` (`?search=&page=&pageSize=`). Always empty for Linux endpoints |
| GET | `/endpoints/{id}/events` | Agent and server activity (`?severity=&page=&pageSize=`) |
| GET | `/endpoints/{id}/jobs` | Job history (`?page=&pageSize=`) |
| GET | `/endpoints/{id}/effective-policy` | Resolved policy and where each value came from (`sources`; for values from a tag policy, `sourceTags` names the tag), including the restart schedule, the Windows Update settings per group and the exact registry values the agent will set |
| GET | `/endpoints/{id}/install-preview` | `?mode=all|selected&updateGuids=<comma-separated>`. What would be installed, what would be skipped and why, total size, reboot implications and warnings. |
| POST | `/endpoints/{id}/install-updates` | `{mode: "AllEligible"|"Selected", updateGuids?, force}` → `202` with the job. `409 duplicate_job` (with `existingJobId`) unless `force`; `409 nothing_to_install` when none of the selected updates can be installed. |
| POST | `/endpoints/{id}/scan` | Queue an `UpdateScan` job (`202`) |
| POST | `/endpoints/{id}/inventory-refresh` | Queue an `InventoryRefresh` job (`202`) |
| POST | `/endpoints/{id}/exclusions` | `{updateGuid, reason?}`. Exclude an update on this endpoint. |
| DELETE | `/endpoints/{id}/exclusions/{updateGuid}` | Remove the exclusion |
| POST | `/endpoints/{id}/updates/{updateGuid}/uninstall` | `{block, reason?}` → `202` with an `UninstallUpdate` job that removes this installed Windows update (see [architecture.md](architecture.md#update-removal-jobs)). `block` (default `true`) also excludes the update on the endpoint, with `reason` (or "Removed with EasyPatch"). `409 update_not_installed` unless the endpoint reports the update `Installed` or `PendingReboot`, `409 not_supported_for_applications`, `409 agent_upgrade_required` (agent older than 1.8.0), `409 not_supported_on_linux`, `409 not_supported_on_macos`, `409 duplicate_job`. |
| POST | `/endpoints/{id}/restart` | `{mode, condition, countdownMinutes?, deadlineMinutes?, scheduledAt?, expiresAfterMinutes?, force}` → `202` with the job. `mode`: `Immediate`, `Countdown`, `PromptWithDeadline`, `PromptNoDeadline`; `condition`: `Always`, `OnlyIfPending`. `scheduledAt` is at most 31 days ahead; `expiresAfterMinutes` (15 to 1440, default 120) is how long an offline computer may take to pick it up. `409 duplicate_job` while another restart is active, `409 agent_upgrade_required` for agents without restart support. |
| POST | `/endpoints/{id}/notify` | `{preset, restartAt?}` → `202` with the job. `restartAt` is required for `RestartScheduled`. `409 agent_upgrade_required` for agents without message support, `409 not_supported_on_linux` for Linux and `409 not_supported_on_macos` for macOS endpoints. |
| POST | `/endpoints/{id}/agent-update` | `{version?}` (send `{}` for the newest) → `202` with an `AgentUpdate` job for the newest signed package for the agent's architecture and package format, or the given version. `409` with `agent_upgrade_required` (agent older than 1.2.0 or built without a release key), `no_agent_package`, `agent_up_to_date` (also for older versions: agents are never downgraded), `package_not_signed`, `release_key_not_trusted` or `duplicate_job`. |
| POST | `/endpoints/{id}/uninstall-agent` | → `202` with an `UninstallAgent` job. The agent removes its own package, which unenrolls it; the job completes when the unenrollment arrives and the endpoint becomes `Decommissioned`. `409 agent_upgrade_required` for agents older than 1.6.0 (or not installed from their package), `409 duplicate_job`, `409 endpoint_not_active`. |
| POST | `/endpoints/bulk/scan`, `/endpoints/bulk/install-updates` | `{endpointIds[], force}`. Returns a per-endpoint outcome. |
| POST | `/endpoints/bulk/restart` | `{endpointIds[], restart: {…as above}}`. Per-endpoint outcome. To restart every endpoint of an organization or site that needs it, see `/organizations/{id}/restart-pending`. |
| POST | `/endpoints/bulk/notify` | `{endpointIds[], message: {preset, restartAt?}}`. Per-endpoint outcome. |
| POST | `/endpoints/bulk/agent-update` | `{endpointIds[], version?}`. Per-endpoint outcome with the codes above. |
| GET | `/user-messages` | Viewer. The preset messages with their title and text (`{time}` marks where the restart time goes) |

All POST, PUT and DELETE routes above are Operator. Bulk routes accept at most 1000
endpoints.

### Fleet updates

`GET /updates` aggregates updates across endpoints with missing, failed, installed and
pending-reboot counts, `cveCount` and `knownExploited`. Filters: `organizationId, siteId, category, state, search, knownExploited`.
Sort: by default updates that fix a known-exploited vulnerability come first, then by missing + failed;
`missing` (missing + failed), `failed`, `installed`. Without `state`, only updates that
are missing, failed or pending a restart somewhere are listed; `search` matches the title and KB
numbers (Linux update titles contain the package name). Linux updates include `package`. Also `GET /updates/{updateGuid}`
(`?organizationId=&siteId=`; includes `vulnerabilities`: the CVEs the update fixes on the endpoints in scope, with
MSRC title, severity and CVSS where available and the CISA KEV fields `kev`, `kevDateAdded`, `kevDueDate`,
`kevRansomware`), `GET /updates/{updateGuid}/endpoints`
(`?state=&organizationId=&siteId=&page=&pageSize=`) and
`POST /updates/{updateGuid}/install` (Operator; `{organizationId?, siteId?, endpointIds?}`
creates a `Selected` install job on each affected endpoint, at most 1000).
`POST /updates/{updateGuid}/uninstall` (Operator; `{organizationId?, siteId?, endpointIds?, block, reason?, hold}`)
creates an `UninstallUpdate` job on each endpoint in scope that reports the update `Installed` or
`PendingReboot` (at most 1000), with the same per-endpoint outcome and error codes as the endpoint route.
`hold: true` also puts the update on hold for `organizationId`, or for every organization when it is
omitted (SuperAdmin only, otherwise `403`), even when no endpoint had it installed.

### Update holds

An update on hold is not installed automatically (see
[architecture.md](architecture.md#update-holds-and-the-rollout-guard)). `GET /updates` items and
`GET /updates/{updateGuid}` add `onHold` (a hold for every organization, or for the organization in
scope or any organization you can access); `GET /updates/{updateGuid}` adds `holds`, the active
holds you can see. `GET /endpoints/{id}/updates` adds `holdReason` to missing and failed updates
on hold for the endpoint's organization. The install preview skips held updates with reason `Held`
unless they are selected, and then adds a warning.

| Method | Route | Notes |
|---|---|---|
| GET | `/update-holds` | Viewer. `?updateGuid=&active=` (`active` defaults to `true`; `false` includes released holds). Holds for every organization and for organizations you can access, newest first, at most 500: `{id, updateGuid, title, kbNumber, organizationId, organizationName, source (Automatic, Manual), reason, failedEndpoints, attemptedEndpoints, createdAt, createdBy, releasedAt, releasedBy, canRelease}`. `organizationId` is `null` for a hold for every organization. Automatic holds come from the rollout guard and carry the failure counts. |
| POST | `/updates/{updateGuid}/holds` | Operator. `{organizationId?, reason}` (reason 1-500 characters) → `201` with the hold. Without `organizationId` the update is held for every organization (SuperAdmin only, otherwise `403`). `404` for an unknown update or an organization you cannot access, `409 already_held`. |
| POST | `/update-holds/{id}/release` | Operator with access to the hold's organization; SuperAdmin for a hold for every organization (otherwise `403`). Returns the released hold. |

### Jobs

| Method | Route | Notes |
|---|---|---|
| GET | `/jobs` | Filters: `endpointId, organizationId, status, type, trigger, active, from, to, page, pageSize`. Types: `UpdateScan`, `InstallUpdates`, `InventoryRefresh`, `Restart`, `NotifyUser`, `AgentUpdate`, `UninstallAgent`, `UninstallUpdate`, `DownloadUpdates` |
| GET | `/jobs/{id}` | Includes per-update results and the job's events |
| POST | `/jobs/{id}/cancel` | Operator. Immediate when the job is queued, delivered or waiting for a reboot; otherwise the agent is asked to stop after the current update. A restart that is waiting for users is cancelled at the agent's next check-in, which also aborts a Windows restart that is still in its warning period. |
| DELETE | `/jobs/{id}` | Same as `POST /jobs/{id}/cancel` |
| POST | `/jobs/{id}/retry` | Operator. Creates a new job with the same parameters (`202`); only for finished jobs. `DownloadUpdates` jobs are not retried (`409 not_retryable`). |

### Agent management (Operator)

| Method | Route | Notes |
|---|---|---|
| GET/POST | `/enrollment-tokens` | GET: `?organizationId=&includeInactive=`. POST `{organizationId, siteId?, description?, expiresInHours, maxUses, count}` returns each plaintext token **once**, with a ready-made `msiexec` command and `linuxEnrollCommand` (pipes the token into `easypatch-agent enroll --token-file -`) and, when the server has a macOS package, `macEnrollCommand` for the experimental macOS agent (the same, with `/usr/local/bin/easypatch-agent`; otherwise null). |
| POST | `/enrollment-tokens/{id}/revoke` | |
| GET/POST | `/deployment-codes` | POST `{organizationId, siteId?, name, expiresInDays?, allowedSourceCidrs?, maxPendingRequests?}` → `201`. Each code includes the PowerShell one-liner, the Linux one-liner (`linuxOneLiner`, `linuxScriptUrl`) and, when the server has a macOS package, the experimental macOS one-liner (`macOneLiner`, `macScriptUrl`; otherwise null). |
| POST | `/deployment-codes/{id}/revoke` | |
| GET | `/deployment-codes/{id}/install-script` | `?package=&requireSignature=&platform=`. The full PowerShell script, the one-liner, and the package name, version and SHA-256. `platform=linux` returns the Linux shell script and one-liner, with the package names and SHA-256 values comma-separated; `platform=macOS` the same for the experimental macOS agent. |
| GET | `/enrollment-requests` | `?status=Pending&organizationId=&page=&pageSize=` |
| POST | `/enrollment-requests/{id}/approve` | `{organizationId?, siteId?}` (optionally assign elsewhere) |
| POST | `/enrollment-requests/{id}/reject` | `{reason?}` |
| POST | `/enrollment-requests/bulk-approve` | `{ids[]}` |
| GET | `/agent-packages` | Viewer. Packages in the package directory with `format` (`msi`, `deb`, `rpm`), version, size, SHA-256 and, when a valid `.sig` file is next to the package, its `releaseKeyId`. `signatureProblem` says why a `.sig` file was ignored. |
| GET | `/agent-versions` | Viewer. Agent version distribution (`?organizationId=`) |

### Dashboard, reports, audit, settings

| Method | Route | Role |
|---|---|---|
| GET | `/dashboard/summary` | Viewer |
| GET | `/dashboard/activity` (`limit, organizationId, severity`) | Viewer |
| GET | `/reports/compliance` (`organizationId, siteId, endpointId, os, compliance`) and `/reports/compliance.csv` | Viewer |
| GET | `/reports/compliance/trend` (`organizationId, from, to`) | Viewer |
| GET | `/reports/installations` (`from, to, organizationId, siteId, endpointId, category, result, page, pageSize`) and `/reports/installations.csv` | Viewer |
| GET | `/audit-logs` (`userId, organizationId, action` (prefix), `from, to, page, pageSize`) | Operator. Users restricted to some organizations only see entries for those organizations. |
| GET/PUT | `/settings` | GET Viewer, PUT SuperAdmin. Includes the rollout guard: `rolloutGuardEnabled` (default `true`), `rolloutGuardMinFailedEndpoints` (1-1000, default 3), `rolloutGuardFailurePercent` (1-100, default 20) and `rolloutGuardWindowDays` (1-90, default 7). |
| GET | `/server-info` (version, public URL, server time) | Viewer |
| GET | `/vulnerability-feeds` (state of the `kev`, `msrc` and `debian` downloads: last attempt and success, sanitized error, version, entries) | Viewer |
| GET/POST, PUT/DELETE | `/lifecycle`, `/lifecycle/{id}` (OS lifecycle table) | GET Viewer, writes SuperAdmin |

CSV exports are UTF-8 with a byte-order mark. Text values that start with `=`, `+`, `-`, `@`,
tab or carriage return are prefixed with `'` so spreadsheets do not evaluate them as formulas.

### Monthly reports

| Method | Route | Role |
|---|---|---|
| GET | `/organizations/{id}/report-schedule` (`enabled, recipients[], dayOfMonth, includeEndpointList, enabledAt, lastScheduledPeriod, nextReportDate, nextReportPeriod, timeZone`) | Viewer |
| PUT | `/organizations/{id}/report-schedule` `{enabled, recipients[], dayOfMonth, includeEndpointList}`: up to 20 plain addresses (at least one when enabled), day 1-28 | Operator |
| GET | `/monthly-reports` (`organizationId, page, pageSize`): newest first, without the PDF | Viewer |
| POST | `/monthly-reports` `{organizationId, year, month, includeEndpointList?}`: generates and stores the PDF (201). `includeEndpointList` defaults to the schedule's setting. `invalid_period` for months that have not started or are more than 10 years old | Operator |
| GET | `/monthly-reports/{id}` and `/monthly-reports/{id}/pdf` (`application/pdf` attachment) | Viewer |
| POST | `/monthly-reports/{id}/send` `{recipients?}`: queues an email with the PDF; recipients default to the schedule's. 409 `smtp_not_configured`, `smtp_not_encrypted` (SMTP security *None*) or `report_too_large` (over 15 MB) | Operator |
| DELETE | `/monthly-reports/{id}` | Operator |

`deliveryStatus` is `null` (not emailed), `Pending`, `Sent` or `Failed`, with `attempts`,
`queuedAt`, `sentAt` and `lastError`. The audit log records `report_schedule.update`,
`report.generate`, `report.send` and `report.delete`. Server settings add `retentionReportsMonths`
(1-120, default 24) and `reportBrandName` (up to 100 characters, or `null`).

### Health

`GET /health/live` reports that the process is up. `GET /health/ready` reports that the
database is reachable. Neither requires authentication. The worker has its own `/health` on
port 8081 inside its container (database plus maintenance-loop heartbeat); it is not exposed
through Caddy.
