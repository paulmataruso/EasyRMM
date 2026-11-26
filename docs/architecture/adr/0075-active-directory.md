# ADR-0075: Managing Active Directory from the console

* Status: Accepted (2026-11-26, after an independent review). Design only; no code is changed by this ADR.
* Asked for by the owner (2026-11-26): "Basic AD detection and logic. If we
  detect a server as being an active directory server, we should allow basic
  task like adding/removing/changie users/groups etc. Password resets,
  account disable." Those words are the only owner decisions here.
  Everything marked *decided in review* is the writer's call and the owner
  can overturn it.
* Builds on: [ADR-0073](0073-windows-management-modules.md) (the framework:
  the `winmod` job kind, `params` on standard input, the pinned script
  catalogue and its AST check, `roles` in Facts, toggles, permissions, the
  AD protected-target guard, snapshots, alert kinds and default policies,
  step-up, `devscope`), which this ADR follows exactly except where
  *Amendments to ADR-0073* says otherwise;
  [ADR-0074](0074-defender-management.md) (accepted; the model for structure:
  tiers, catalogue, alerts, slices);
  [ADR-0055](0055-lets-encrypt-in-one-step.md) section *Step-up
  authentication* (the one definition, 5 minutes);
  [ADR-0072](0072-what-each-page-shows.md) (where the tab and the card go);
  [ADR-0060](0060-collecting-logs.md) (proposed: Windows event collection and
  its detections) and feature 12 of `docs/architecture/feature-plan-msp.md`
  (AD health), which this ADR folds in (section 8).
* Amends: ADR-0073 (six points, below), ADR-0060 (its sealing list, section 2 *Passwords*) and feature 12 (its carrier and its
  slices, section 8).

## Context

The owner wants the console to notice that a server is a domain controller
and then offer the everyday directory tasks: users and groups created,
changed and removed, passwords reset, accounts disabled.

What ADR-0073 already fixes, and this ADR does not reopen:

* The agent reports `ad_ds` in `roles` when the `NTDS` service runs and
  `ProductType` is `LanmanNT` (a domain controller). A server that is only a
  domain member, or a former controller, is not offered the module.
* Every action is a fixed PowerShell script embedded in the server, pinned by
  hash, run through the `winmod` kind with its parameters as JSON on standard
  input, never joined into script text, with a typed result.
* The permissions are `ad.view`, `ad.manage`, `ad.reset_password` and
  `ad.view_sensitive`. Technicians hold `ad.view` but no AD management; Site
  Administrators add `ad.view_sensitive`; **every `ad.manage` write needs
  Organization Administrator** (review: `ad.helpdesk` is added for
  ordinary-user help-desk work, section 6). The directory is not scoped to a site: a
  write through one controller changes the whole domain and replicates
  forest-wide.
* Passwords travel only as sealed `winmod_job_secrets`, never in `jobs.args`,
  audit, logs or output. Password resets, account disabling and every
  destructive action need step-up and (destructive ones) a typed
  confirmation.
* A protected-target guard runs twice, on the computer and on the server, and
  no action adds anyone to a protected group.

What nothing knows yet: which controller does the work when a domain has
several, which accounts count as protected beyond those four groups, what the
catalogue holds, how big directories are read, and what alerts and tests the
module brings. This ADR decides those.

## Decision

### In short

1. The module is `active_directory`, offered on a device whose `roles` holds
   `ad_ds` (and not as a read-only controller for writes), by toggle and by
   `ad.view`. It adds no framework (ADR-0073, *How ADR-0074 to 0077 plug in*).
2. The work for a domain runs on **one controller per domain**, chosen per
   request by a fixed rule (section 3). Writes go to it and only to it.
3. A catalogue of about thirty `winmod` actions with four tiers (section 2).
   Reads page and cache; the directory is never mirrored into EasyRMM.
4. A **protected-target guard** refuses the powerful accounts and groups, and
   asks more of service accounts (section 4).
5. Three alert kinds (lockouts, privileged group changes, replication
   failure) with default policies that stay quiet (section 7).
6. The first slice answers one question that decides the whole design: **what
   the agent can do to the directory when it runs as SYSTEM on a controller**
   (section 3, *Which identity*).
7. Tests use a separate Windows Server VM promoted to a test controller on an
   isolated network. The owner's two test servers are never promoted
   (section 9).

### 1. Detection and what the module needs

* **Role.** `ad_ds` from ADR-0073 section 1, unchanged. A new optional
  `detail` object on the role (an amendment, same pattern as ADR-0074's
  `defender.detail`): `{domain, readOnly}`. `domain` is the primary DNS
  suffix, read from the registry value `Domain` under
  `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters` (*to confirm on
  the test controller*); `readOnly` is true on a read-only domain controller
  (RODC), whose marker is *to confirm* (the first slice reads it from
  `Get-ADDomainController`, and until then `ad.status` reports it). The
  authoritative identity of a domain is its **domain SID**, which `ad.status`
  reads; the server regroups controllers by SID once known and uses the DNS
  name only until then.
* **The PowerShell module.** Scripts run in Windows PowerShell 5.1
  ([ADR-0064](0064-remote-powershell-management.md)) and import
  `ActiveDirectory` by name. On a controller with the AD DS tools it is
  there. On Server Core or a controller installed without the tools it may
  not be (to verify): the script returns `module_missing`, the tab says
  "install the RSAT-AD-PowerShell feature on this controller", and EasyRMM
  does not install it (nothing here changes the controller's features).
* **A read-only controller** (RODC) is offered for reads and the health
  checks only. Every write action returns `read_only_dc` and the server never
  picks an RODC as the write target.
* **Domain membership is not enough**, as ADR-0073 says. A server that merely
  has the AD tools installed is not offered the tab.

### 2. Actions

Every action is `{Module: active_directory, Name, Version, Script, Params
schema, Result schema, Tier, Permission, Sensitive, Destructive,
GuardsProtected, Timeout}` per ADR-0073 section 4. The tiers:

| Tier | Meaning | Permission | Confirmation | Step-up (ADR-0055, 5 min) | Audit |
|---|---|---|---|---|---|
| 0 Read | no change | `ad.view` (`ad.view_sensitive` for sensitive fields) | none | none | compact, one row per query |
| 1 Routine | reversible and restores access | `ad.manage` | none | none | `winmod.active_directory.<action>` with parameters |
| 2 Change | changes the directory, reversible by another action | `ad.manage` | `confirm: "<action>:<subject>"` | none | as tier 1, plus old and new value of each attribute |
| 3 Credential or destructive | sets a credential, removes access, or cannot be undone | `ad.manage` (`ad.reset_password` for passwords) | typed confirmation naming the subject and the effect | **required** | as tier 2; the password is never in it |

Which actions are tier 3 follows ADR-0073: password resets, account disabling
and every destructive action need step-up. Review adds `user_enable` and
`group_add_members` (access is granted by both). The step-up is ADR-0055's,
**5 minutes**, in every place this ADR mentions it. Creating a user is tier 3
because it sets an initial password.

All user values are typed and validated on the server before they reach the
script: a **user or group is named by its SID or object GUID**, which the
server took from an earlier read (a value that was not in a read of this
domain within the last hour is refused), never by free text; an **OU is named
by a distinguished name that appears in the last OU tree read** of the
domain; attribute values are length-bounded and from a character class; a
password is 8 to 128 characters, any printable character, handled only as a
secret. No script uses `-Filter`, `-LDAPFilter` or a filter built from a
value (ADR-0073); scripts use `-Identity` with a SID or GUID, `-SearchBase`
with a validated DN, and fixed literal filters such as `-Filter '*'`.

#### Catalogue

| Action | Does | Parameters | Tier | Timeout |
|---|---|---|---|---|
| `status` | Domain, forest, functional levels, domain SID, whether the Recycle Bin is enabled, the PDC emulator, the controller's own name, writability, the default domain password and lockout policy | none | 0 | 60 s |
| `ou_tree` | Organizational units and the built-in containers, one level under a node, with whether each is protected from accidental deletion. **Read-only: no OU is created, changed or deleted.** | `parent`: a DN from a previous tree read or empty for the root | 0 | 60 s |
| `user_list` | Users under a container, a page at a time (section 5) | `container` (DN), `scope` (`one_level`, `subtree`), `match` (a name, sAMAccountName or UPN prefix, compared in memory), `state` (all, disabled, locked, password_expired, never_logged_on, stale_over_days with a number), `cursor`, `pageSize` (at most 200) | 0 | 120 s |
| `user_get` | One user's attributes, flags and (sensitive) last logon, direct groups | `id` (SID or GUID) | 0 | 60 s |
| `group_list` | Groups under a container, a page at a time | as `user_list`, with `kind` (security, distribution) | 0 | 120 s |
| `group_members` | Direct members of a group (users, groups, computers), a page at a time | `id`, `cursor` | 0 | 60 s |
| `privileged_members` | Members, nested, of the protected groups (section 4), as SIDs with names | none | 0, **sensitive** | 120 s |
| `computer_list` | Computer accounts under a container, a page at a time, with operating system and enabled state | as `user_list` | 0 | 120 s |
| `user_unlock` | `Unlock-ADAccount` | `id` | 1 (`ad.helpdesk`) | 60 s |
| `user_enable` | `Enable-ADAccount`; refused when the account would be enabled with no password ever set | `id` | 3 | 60 s |
| `user_disable` | `Disable-ADAccount` | `id` | 3 | 60 s |
| `user_set` | `Set-ADUser` with the allowed attributes only | `id`, a map of attribute to value (at most 8) | 2 (3 for `userPrincipalName`, which changes how the person signs in, and for `accountExpirationDate`) | 60 s |
| `user_move` | `Move-ADObject` to a validated OU | `id`, `targetOu` | 2 | 60 s |
| `user_create` | `New-ADUser` in a validated OU, enabled only when a password is set; optional must-change | `ou`, `sam` (1 to 20 characters from `A-Za-z0-9._-`), `upn`, `givenName`, `sn`, `displayName`, `password` (secret), `mustChange` | 3 | 2 min |
| `user_reset_password` | `Set-ADAccountPassword -Reset`, then `-ChangePasswordAtLogon` when asked; optionally unlock | `id`, `password` (secret, typed or generated), `mustChange`, `unlock` | 3 | 2 min |
| `user_delete` | `Remove-ADUser` | `id` | 3, **destructive** | 2 min |
| `group_create` | `New-ADGroup` | `ou`, `name`, `scope` (domain local, global, universal), `category` (security, distribution), `description` | 2 | 60 s |
| `group_add_members`, `group_remove_members` | `Add-`/`Remove-ADGroupMember` | `id`, `members` (SIDs or GUIDs, at most 50) | add 3, remove 2 | 2 min |
| `group_delete` | `Remove-ADGroup` | `id` | 3, **destructive** | 2 min |
| `computer_disable` | `Disable-ADAccount` on a computer account; never a domain controller | `id` | 3 | 60 s |
| `health_read` | the read-only checks of section 8 | `checks` (a list from a fixed set) | 0 | 5 min |

Each script returns `{ok, version, data, error}` as ADR-0073 specifies, with
typed errors: `protected_target`, `service_account_confirmation_required`,
`read_only_dc`, `module_missing`, `access_denied`, `not_found`,
`password_policy` (with the policy's minimum length), `adws_unavailable`, `conflict`,
`too_many`, `partial` and `not_enabled`.

**What is not in the catalogue**, on purpose: creating, moving, renaming or
deleting OUs (the tree is read-only); changing `sAMAccountName`; writing
`userAccountControl` flags, service principal names, delegation, `sIDHistory`,
`adminCount` or any permission (security descriptor); clearing a
protected-from-accidental-deletion flag; group policy; trusts; schema;
FSMO transfer; DNS and DHCP (ADR-0076); anything that takes a filter or
script text. An administrator who needs them uses the directory's own tools
or ADR-0064's script runner, audited as a script.

**Allowed attributes of `user_set`** (*decided in review*): `givenName`, `sn`,
`displayName`, `description`, `mail`, `telephoneNumber`, `title`,
`department`, `company`, `physicalDeliveryOfficeName`, `manager` (a user's GUID
from a read), `userPrincipalName` and `accountExpirationDate`. A value can be
cleared. `mail`, `telephoneNumber` and the other personal fields are returned
only to `ad.view_sensitive` holders (section 6).

#### Passwords

* **Typed or generated.** The console asks for one of two things.
  *Typed*: the operator enters the password in the dialog. *Generated*: the
  **server** makes it (20 characters from a cryptographic source with an
  upper, a lower, a digit and a symbol class, no look-alike characters) when
  it accepts the request.
* **The path is ADR-0073's.** The server seals the password into
  `winmod_job_secrets`, unseals it at delivery into the signed `params`, and
  deletes the row at delivery or expiry. Neither the typed nor the generated
  password is in `jobs.args`, `jobs.body`, audit, logs or output. The script
  returns `{ok, mustChange, unlocked}` only.
* **A generated password is shown once.** It is in the response to the
  operator's own request (over TLS, `Cache-Control: no-store`) and nowhere
  else; the console shows it with a copy button and clears it when the dialog
  closes. The server keeps no copy. A page reload does not show it again:
  the operator resets again. Showing it needs `ad.reset_password` and the
  step-up the request already needed.
* **Must change at next sign-in** is on by default and is a separate setting
  from the password. It is refused (`conflict`) on an account that cannot
  change its password or whose password never expires, and the dialog says
  why; the script never changes those flags.
* **The two cmdlets are not one transaction.** If the reset succeeds and
  `-ChangePasswordAtLogon` fails, the result is `{ok: false, partial: true,
  passwordReset: true}` and the console says so in those words: the password
  *was* changed, the must-change flag was *not*; the operator repeats the
  flag step or resets again.
* **The domain's policy decides.** A password the domain refuses (length,
  complexity, history) returns `password_policy` with the minimum length from
  `status`; for a generated password the server may retry once with a longer
  one, never more.
* **Where it applies.** The reset lands on the chosen controller and
  replicates (section 3). The console says "other controllers may take a few
  moments to learn it" rather than promising a time.

**What the script does with the password, and PowerShell logging.** ADR-0060
collects the PowerShell script block and module logs (4104 and 4103), and
module logging records parameter values. So the script reads the password
from the stdin `params` into a variable and passes **that variable** straight
to `ConvertTo-SecureString -AsPlainText -Force`; **a password is never a
literal in script text and never part of a string built by the script**, and
the AST check (section 9) fails a script that breaks this. Even so, a 4103
record can hold the converted value's name or, with transcription, the
parameters. **ADR-0060 is amended by name:** its sealing list (the fields it
keeps out of stored events) must cover the parameter values of 4103 and the
script text of 4104 for every `winmod` run (identified by the signed job's
script hash), so the collector never stores or forwards them; this ADR's
real-controller step 7 checks it.

#### Deleting

`user_delete` and `group_delete` need the typed confirmation
`delete:<sam or name>` and step-up. If the domain's AD Recycle Bin is enabled
(from `status`), the dialog says the object can be restored with the
directory's own tools; if not, it says the object is **permanently gone**
once the controllers have replicated. An object protected from accidental
deletion is refused with `not_enabled`: the script does not clear that flag.

### 3. Running it: one controller per domain

**The unit is the domain**, identified by its SID. A forest with several
domains has one chosen controller per domain, each in its own request. This
ADR serves the domains whose controllers are enrolled; a domain with no
enrolled controller has no module.

**Which identity.** The agent runs jobs as SYSTEM. SYSTEM on a domain
controller holds the `SY` security identifier, which the default security
descriptors of directory objects grant full control. **Reads and writes are
therefore expected to work under the agent's own SYSTEM account, with no
stored credential. To confirm at R1** (the first real-controller step of
slice A1, a go or no-go for every write action), not asserted here: whether
a given cmdlet reaches the directory as the computer account or as `SY`
decides what it may do, and R1 records it per action.

* **It works (expected).** Writes run as SYSTEM. In the directory's own audit
  (4720, 4724, 4728 and the rest) the subject is the controller's computer
  account (for example `DC01$`), **not the technician**; EasyRMM's audit row
  (`winmod.active_directory.<action>`: the actor, the target, the changed
  attributes) is the only record of who asked. The console says so.
* **Fallback, designed now: a per-request credential.** Used **only if R1
  shows SYSTEM cannot write some action, or if an organization wants its
  changes attributed to a named administrator** (an organization setting,
  default off). The operator types a domain administrator's user name and
  password in the step-up dialog of that request; both travel as a sealed
  secret exactly like a new password (ADR-0073: `winmod_job_secrets`, only
  in `params`, deleted at delivery, in no log, audit, output or job row) and
  are used for that one job through `-Credential`. **They are never stored,
  never reused for another request, and never shown back.** The credential
  must belong to an account that holds the rights the action needs, which is
  the directory's own check; the protected-target guard still applies, since
  a named administrator can reach more than the guard allows. The directory's
  audit then names that administrator. The script builds the credential from
  the params variable and never as a literal (same rule as passwords). A
  stored, delegated service account is **not** built.

**Choosing the controller** (*decided in review*), per request, among the
domain's enrolled controllers that are `ad_ds`-present, online (a heartbeat in
the last 2 minutes), not read-only for a write, and **that the caller may act
on** (the access check is made on the controller's site, as every device
call is; an Organization Administrator, who all writes need, sees all):

1. The controller the operator **pinned** for the domain
   (`ad_domains.preferred_device_id`, set by `ad.manage` on the domain's
   card), if it qualifies.
2. Otherwise the one that holds the **PDC emulator** role (from the last
   `status`), if enrolled and qualifying: it is where urgent changes such as
   password changes and lockouts converge and the one the directory's own
   tools prefer (Microsoft's documentation of this behaviour was *not
   re-read*; the choice is harmless if it is wrong).
3. Otherwise the qualifying controller with the **most recent heartbeat**,
   then the lowest device id, so the choice is stable.

"Qualifying" includes **directory health** (review), read by the hourly
`health_read` and held with its age: **no failures** for that controller from
`Get-ADReplicationFailure`, **replication lag within a threshold** (default 15
minutes inside a site; the value is a constant to measure) from
`Get-ADReplicationPartnerMetadata` (last successful replication per partner),
and the **Active Directory Web Services service (ADWS) running**, which the
module's cmdlets need. A controller whose health is unknown is chosen only
when no healthy one qualifies, and the console says so. If ADWS is stopped,
the script returns the typed error `adws_unavailable` (not a generic failure),
and the console says "Active Directory Web Services is not running on this
controller"; a write is never retried on another controller after it was
sent (below).

If none qualifies, the request is refused with the reason (all offline, only
read-only controllers) and nothing is queued, as ADR-0073 says for offline
computers.

**Writes go to the chosen controller and are never retried elsewhere.** The
scripts address the controller they run on explicitly
(`-Server` with its own name taken inside the script from the computer's
name, not from parameters), because the module otherwise picks any
controller it finds and the write could land elsewhere. A job that was sent
and whose answer was lost is **not** re-sent to another controller; the
operator reads the state and decides (a `user_create` repeated on a second
controller could create a duplicate).

**Replication.** A write is committed on the chosen controller; the others
learn it by directory replication (normally within moments inside a site and
on the site-link schedule between sites; Microsoft's figures were not
re-read, so the console states no number). Consequences the design accepts:

* **Reads after a write use the same controller**, so the operator sees their
  own change at once. Every snapshot records the controller that produced it,
  and the tab shows "from DC1, as of 14:02". When a later read is served by a
  different controller than the last write (the pin changed, the first one
  went offline) the tab says "this may not show a change made a moment ago on
  another controller".
* **Two operators on two controllers at once is avoided**, not resolved:
  one controller per domain means one writer from EasyRMM. Changes made by
  other tools on other controllers are the directory's own conflict rules.
* **A user who tries a new password at another controller at once may be
  refused** until it replicates (the console says so in the reset dialog).
* **Failover is for the next request**, not within one. If the chosen
  controller went offline since the last read, the next write picks the next
  one and the tab shows the change of source.

**Reads and many controllers.** Reads (lists, tree) may be served from any
qualifying controller, stale by at most replication delay; writes follow the
rule above. A domain with more than 50 enrolled controllers is an edge the
first real step does not cover (to verify); the selection is a query, not a
loop, so it has no per-controller cost.

### 4. The protected targets

ADR-0073 fixes the principle: a protected target is refused, the guard runs
on the computer and on the server, and no action adds anyone to a protected
group. This section defines the lists, which are **decided in review** where
the owner's own list is extended, and how each class is treated.

**Hard-protected: refused, no console path.** Every write action (and, for
group actions, adding or removing members of it) returns `protected_target`
for:

* the groups **Domain Admins** (RID 512 under the *local* domain's SID),
  **Enterprise Admins** (RID 519) and **Schema Admins** (RID 518), whose SIDs
  are built on the **forest-root domain's SID**, not the local domain's
  (in a child domain, `<child SID>-519` is not Enterprise Admins), and
  **Administrators** (`S-1-5-32-544`), and
  every **member of them, directly or nested**, plus any account whose
  **primary group** is one of them (primary group membership is not in the
  `member` attribute and is checked by `primaryGroupID`);
* **any group nested inside those groups**: membership of such a group is
  administrator power, so adding a member to it is refused too;
* **`krbtgt`** (RID 502) and **the built-in Administrator** (RID 500);
* every object with **`adminCount` = 1**. Microsoft's list of protected
  accounts and groups (Account Operators, Administrator, Administrators,
  Backup Operators, Domain Admins, Domain Controllers, Enterprise Admins,
  Enterprise Key Admins, Key Admins, Krbtgt, Print Operators, Read-only
  Domain Controllers, Replicator, Schema Admins, Server Operators) is the set
  the directory's SDProp process keeps under the `AdminSDHolder` template,
  every 60 minutes by default on the PDC emulator. Whether the attribute is
  cleared again when an account leaves such a group was *not re-read*; where
  it is not, the account is refused though it is no longer privileged, and
  the console says "adminCount is set (this can be left over from a past
  membership)"; clearing it is done in the directory's own tools;
* **domain controllers' computer accounts**, and the computer account of the
  controller running the job;
* the groups **DnsAdmins** and **Group Policy Creator Owners** (a member of
  either can usually reach administrator power; *decided in review*) and
  **Account Operators, Server Operators, Backup Operators, Print Operators**
  (also covered by `adminCount`, listed so the server's check does not depend
  on it).

**Matching is by SID and RID, never by name, and the forest root decides
519 and 518.** The forest-root domain SID comes from `status` (read from the
forest root through the Global Catalog); the server's table builds 519 and 518
from it and 500, 502, 512 from the local domain's.

**Membership is resolved through the Global Catalog.** Members of the
protected groups can be users of other domains of the forest (as
foreign security principals), universal groups from other domains, and
groups nested across domains. The script walks `member` breadth first
through the **Global Catalog** (a GC server, `-Server` on port 3268), resolves
every foreign security principal by SID, and follows universal groups across
domains. **If any member cannot be resolved (a domain with no reachable GC,
an unresolved foreign principal, a cap exceeded), the request is refused**:
the guard fails closed. The check runs **in the pinned script on the agent at
execution time**, as the second check; the server's RID table is only the
first and cheaper one, and a result of `protected_target` is a failure. A built-in Administrator
renamed to something else is still RID 500. The **server's check** is a
fixed table of RIDs and well-known SIDs applied to the SID the request
carries (domain SID plus 500, 502, 512, 518, 519; `S-1-5-32-544` and the
other built-in SIDs), plus a refusal of any result of `protected_target`. The
**script's check** is the full one, run before any change, on the computer:
it builds the protected set by walking `member` of the protected groups
breadth first (no filter; capped at 5,000 objects, **and exceeding the cap
refuses the request, failing closed**), then checks the target's SID, its
`primaryGroupID`, its `adminCount`, and its own membership in that set.

**The Domain Controllers OU and everything under it** is refused as the `ou`
of `user_create` and `group_create`, as the `targetOu` of `user_move`
and of any move, and as a source of one: nothing is created in, moved into or
moved out of it. The script compares the validated DN with the domain's
`OU=Domain Controllers` (found by its well-known GUID container, not its
name) and any DN under it.

**Soft-protected: service accounts. Allowed with a second confirmation.** A
service account is, *decided in review*, an account that is a **managed
service account or group managed service account** (object class
`msDS-ManagedServiceAccount` or `msDS-GroupManagedServiceAccount`), or has
**any service principal name**, or has **"password never expires" set**
together with **no interactive sign-in in 180 days** (the last clause is a
heuristic and marked as such in the console). The rules:

* **gMSA and MSA**: every write is refused with `protected_target` (the
  directory manages their passwords, and a reset or a disable is never what
  an administrator wants from this console). Reads show them.
* **Other service accounts**: disable, password reset, delete and move are
  allowed only with an **extra typed confirmation** (`service-account:<sam>`),
  on top of the step-up they need, after the dialog states "this looks like a
  service account (it has a service principal name); changing it can stop the
  services that run as it". The script returns
  `service_account_confirmation_required` when the request lacks it, so a
  missing confirmation cannot be skipped by a handcrafted request. Editing
  descriptive attributes needs no extra confirmation.
* The classification is recomputed by the script at write time, not trusted
  from the earlier read.

**How the console shows it.** Lists carry a `protection` field
(`none`, `service`, `protected`, with the reason) computed by the read
action. Protected rows show a lock and no write buttons; the tooltip names
the reason. The list's protection flag is a convenience; the enforcement is
at write time on both sides. A refusal is audited
(`winmod.active_directory.<action>.refused` with the reason) and is a result,
not a server error. Group membership of the privileged groups is a sensitive
read (`ad.view_sensitive`), as ADR-0073 section 3 says.

**What this means in practice.** An Organization Administrator cannot reset
the domain administrator's password from EasyRMM, cannot disable a member of
Domain Admins, and cannot put anyone into one; that is deliberate. The
module's purpose is the help-desk and onboarding work on ordinary accounts.

### 5. Reading, caching and large directories

* **Everything is read on demand and cached as ADR-0073 section 5 says**
  (`windows_module_snapshots`, one row per action and parameters, replaced on
  refresh, 5 minutes fresh, 1 minute for a list the operator just changed,
  sensitive snapshots 15 minutes, the controller and `taken_at` recorded).
  EasyRMM never copies the directory into its own tables: no per-user table,
  no sync. This keeps personal data out of the database and keeps the cache
  small.
* **A list is a page, from a resumable paged search.** The result limit is
  64 KiB (ADR-0073); a page is at most 200 rows with a handful of columns
  (about 30 KiB), returned with an opaque `cursor`. Review replaces
  re-running `Get-ADUser -ResultPageSize` for every page, which re-reads the
  whole scope each time: the script uses a **paged LDAP search**
  (`System.DirectoryServices.Protocols`, a `SearchRequest` with a
  `PageResultRequestControl`) whose **cookie** resumes the query on the
  controller. The `cursor` carries the cookie, sealed (the server cannot
  forge or read it), valid **only on the connection's controller and for 10
  minutes**, because a cookie does not survive a new connection or another
  controller. A page request after that restarts the walk from the last
  name returned (a value compared in memory, never in a filter). For
  **snapshots of a large directory** the server walks pages in sequence
  within one job family on one controller, so each page costs one page of
  directory work. The search's base is the validated `-SearchBase` DN; the
  attribute list is fixed; the search filter is a **literal** chosen from
  a fixed set (users, groups, computers), never built from a value.
  Ordering is the directory's, not alphabetical, and the console sorts the
  page it holds.
* **Search is in memory and never a filter.** A name prefix is applied with
  `.StartsWith(..., 'OrdinalIgnoreCase')` on already-read objects; the state
  filters (disabled, locked, expired) are fixed literal tests on read
  properties. This is what keeps ADR-0073's "no filter from a user value"
  without losing search.
* **The bound.** One request scans at most **20,000 objects**. If a
  container has more, the result is `too_many` with the count reached and the
  console asks the operator to narrow to an OU (the tree is browsable one
  level at a time, so every OU of a large domain is reachable) or to add a
  name prefix, which does not reduce the scan but trims the pages. The
  20,000 and the page size are **constants to measure**, not claims: the
  real-controller step generates a large test directory and records the time
  and memory of a full page walk (section 9); the bound is lowered or the
  design changed if a controller takes too long.
* **`lastLogonTimestamp` lags.** The attribute the console uses for "stale"
  is replicated lazily (feature 12 records 9 to 14 days); the column is
  labelled "approximately" and the stale filter never says "inactive for
  N days" more precisely than that.
* **Counts.** The Overview card (below) shows counts (users, disabled,
  locked, privileged) from the last snapshots of `status` and a
  count-only variant of the list read, never from a job sent to draw a card
  (ADR-0073's rule for cards). The counts come with their age.
* **Offline controllers.** The last snapshot is shown with its age and the
  write actions are disabled with the reason (ADR-0073).

### 6. Permissions and what each caller sees

ADR-0073 section 3 stands; restated for this module:

| Permission | Holds | Gives |
|---|---|---|
| `ad.view` | Technician and above | users, groups, computers and OUs with basic columns: name, sAMAccountName, enabled, locked out, OU, protection |
| `ad.view_sensitive` | Site Administrator and above | mail, telephone, title, department, last logon, group membership of privileged groups, `privileged_members`, `user_get` detail |
| `ad.helpdesk` | Technician and above (**new**, review) | `user_unlock`, `user_reset_password`, `user_enable`, `user_disable`, **on non-protected users only** (never service accounts: those need `ad.manage`) |
| `ad.manage` | Organization Administrator and above | create, delete, edit attributes, move, group membership, group create and delete, computer disable (and everything `ad.helpdesk` allows, on service accounts with their extra confirmation) |
| `ad.reset_password` | Organization Administrator and above | the password in `user_create`, and reset of **service accounts** |

A Technician can therefore do the help-desk work (unlock, reset, enable,
disable an ordinary user, each with step-up where the table says so) and
sees names and flags but not personal fields; a Site Administrator reads
more; only an Organization Administrator creates, deletes, edits, moves and
changes group membership. `ad.helpdesk` never reaches a protected target:
the guard (section 4) runs before the permission is consulted for that
target, and a service account needs `ad.manage`. ADR-0073's plain
statement applies: a technician with `ad.view` at one site sees the domain's
users from every site through that site's controller, because the directory
is not scoped by site. Per-row visibility is not attempted here. (See
*Owner decisions*.)

`ad.helpdesk` is added to ADR-0073's four (see the amendments), to `AllPermissions` and to the Technician union by the same small additive edit in `rbac.go`.

### 7. Alerts

Registered with the monitoring package as ADR-0073 section 6 describes. Three
kinds belong to the module (`ad_account_locked_out` and `ad_replication_failed`
are named by ADR-0073; `ad_privileged_group_changed` is added). All obey
`modules.Allowed` and so `devscope.Allowed(org)`: nothing is evaluated for an
organization that is not allowed, a module that is off, or a role that is not
detected, and open alerts resolve with the reasons ADR-0073 gives (`module
off`, `role removed`).

**Subject and content.** One alert per **domain**, at organization scope,
not one per controller: the same event is logged on several controllers and
the same replication failure is seen from both ends. This needs the alert
subject that feature 12 already asks for (an alert whose subject is a domain,
visible by organization rather than by a device's site); this ADR depends on
that mechanism and, until it exists, opens the alert on the **chosen
controller's device** with the domain named in its text. **An alert names the
domain, the count and the times, never an account or a member**, since alerts
are visible to everyone who sees the subject; the account is in the linked
events, behind `log.view` (ADR-0060's rule, feature 12's rule). For a
privileged group change the alert names the **group** (not personal data) and
not the member.

#### Events (Microsoft documentation read on 2026-11-26)

| Event | Meaning | Where logged | Audit subcategory | Source |
|---|---|---|---|---|
| 4740 | A user account was locked out | the Security log; generated on domain controllers, member servers and workstations (the controller that processed the lockout, for a domain account) | Audit User Account Management | [4740(S)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4740) |
| 4728 | A member was added to a security-enabled **global** group | the Security log; "generates only for domain groups" | Audit Security Group Management | [Audit Security Group Management](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-group-management), which defines 4728 as event 4732's global-group form |
| 4732 | A member was added to a security-enabled **local** group (Administrators is a local group) | domain controllers, member servers and workstations; one event per added member | Audit Security Group Management | [4732(S)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4732) |
| 4756 | A member was added to a security-enabled **universal** group | domain groups | Audit Security Group Management | the same subcategory page, which defines 4756 as event 4732's universal-group form |
| 4729, 4733, 4757 | the matching removals (global, local, universal) | as above | Audit Security Group Management | the same subcategory page and 4732's |
| 2042 | "It has been too long since this machine last replicated with the named source machine": the time since the last replication with that source exceeded the tombstone lifetime and replication with it was stopped | the Directory Service log, source `Microsoft-Windows-ActiveDirectory_DomainService`, level Error, task category Replication | n/a | [Event ID 2042](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/active-directory-replication-event-id-2042) |

The pages for 4728 and 4756 themselves were not found on Microsoft Learn on
the day (their own URLs returned 404); the definition above is from the
subcategory page that lists them. Other replication event IDs people
associate with failures (1925, 1311, 1865, 2087, 2088) were **not verified
and are not used**: replication failure is read from the directory itself
(below), with 2042 as the one event added for immediacy.

The events reach the server through **ADR-0060's collector and detections**,
which this ADR does not duplicate. The Security events are written only when
the controller's audit policy audits User Account Management and Security
Group Management for Success; ADR-0060 owns configuring that policy and
this module only reports when the events are not arriving (see *Fallback*).

#### Alert kinds

| Kind | Source | `threshold` means | `minutes` means | Opens on | Resolves on |
|---|---|---|---|---|---|
| `ad_account_locked_out` | 4740 across the domain's controllers, counting **distinct locked-out accounts** (so the same lockout seen on two controllers counts once) | the number of accounts | the window | at least `threshold` accounts within `minutes` | no new lockout for one more window, or manually |
| `ad_privileged_group_changed` | 4728, 4732, 4756 where the group is in the protected set; and the snapshot difference below | 1: Domain, Enterprise and Schema Admins and built-in Administrators; 2: also the other protected groups of section 4 | unused | any member added to a group at or under the threshold, keyed by group and member | the matching removal event (4729, 4733, 4757), or manually |
| `ad_replication_failed` | `health_read` of the replication checks, hourly (below), and event 2042 | unused | how long a failure must have lasted | a failure whose first failure time is older than `minutes`, or any 2042; keyed by domain and partner | the failure list is empty for the pair, or manually |

* **Replication failure source.** ADR-0073 allows a scheduled read where an
  alert needs a value Facts does not carry: `health_read` with the
  replication check runs **at most hourly per domain**, on the chosen
  controller, only while the module is enabled and `devscope.Allowed(org)`,
  and never when the controller is offline. It uses `Get-ADReplicationFailure
  -Scope Domain -Target <the domain>`, which Microsoft documents as returning
  the failures currently associated with the named controllers, sites,
  domains or forest. The page does not list the properties of the returned
  object; the failure count, first failure time, last error and partner are
  taken from the `ADReplicationFailure` type and are **to confirm on the test
  controller**. A domain of one controller has no partners and so nothing to
  fail. A controller that is not reachable is "unknown", never healthy
  (feature 12).
* **Snapshot difference (fallback and cross-check).** `privileged_members` is
  read hourly with the replication check (sensitive, kept 15 minutes, stored
  as a hash set per group). The first read is the **baseline and opens
  nothing**. A later read with a member the last one did not have opens the
  same alert, keyed so that the event and the difference for the same member
  and group are one alert. This catches changes made when auditing is off
  and changes whose events did not arrive.
* **EasyRMM's own changes are not alerts.** There is nothing to suppress: no
  action adds anyone to a protected group (ADR-0073), and a lockout is never
  caused by this module. A password reset by the module unlocks; it opens
  nothing.
* **Storms.** A mass lockout (a password-spray or a service account with a
  stale password) is one alert per window, with the count; a bulk addition to
  a privileged group is one alert per group and evaluation, not per member.

#### Default policies

Created per organization, idempotently, keyed by module and name, when the
module is first enabled there, owned by the module and marked `default`
(ADR-0073 section 6). Organization-level rows. *Decided in review*: the
owner asked for alerts on these three subjects and, in ADR-0074's words,
default rules; the defaults are chosen so a healthy domain opens none of them
in a normal week. A single lockout is the commonest event in a directory (a
person mistyped their password) and is **off**.

| Name | Kind | Threshold | Minutes | Severity | Default |
|---|---|---|---|---|---|
| Directory: many accounts locked out | `ad_account_locked_out` | 10 | 15 | warning | on |
| Directory: an account locked out | `ad_account_locked_out` | 1 | 60 | warning | **off** |
| Directory: Domain, Enterprise, Schema or built-in Administrators changed | `ad_privileged_group_changed` | 1 | - | critical | on |
| Directory: other privileged group changed | `ad_privileged_group_changed` | 2 | - | warning | **off** |
| Directory: replication failing | `ad_replication_failed` | - | 120 | warning | on |

Why these: ten accounts in fifteen minutes is a spray or a broken service,
not a typo; changes to the four top groups are rare in any domain and each
is worth a person's attention; a replication failure that has lasted two hours
is real, while one during a reboot or a link blip is not (a 2042 opens at
once, as it means replication has been stopped). Per ADR-0074's best-match
rule, where a kind has a threshold and two enabled policies match, only the
higher opens an alert, so turning on "an account locked out" does not double
the many-accounts alert.

Alerts on 4771 and 4776 failures per account, which feature 12 plans, stay
in ADR-0060's detection table and feature 12's slice 4; this module adds
nothing to them.

### 8. Folding in feature 12 (AD health)

Feature 12 predates ADR-0073 and planned its own `adhealth` job kind. *Decided
in review*, amended here:

* **The carrier is `winmod`**, not a new kind. The read-only checks become
  `health_read`, an action of this module, run on the chosen controller.
  Detecting that a device is a domain controller is ADR-0073 slice 1, not
  feature 12's.
* **Its checks are feature 12 slice 1's list**, which that section specifies
  and this ADR does not restate: replication partners with last success and
  failures, FSMO holders, SYSVOL and NETLOGON with DFSR's state, the time
  source and offset, critical services, DNS (SRV registration, each
  controller's records resolving, AD-integrated zones, the controller's own
  DNS settings) and Group Policy processing, each finding `ok`, `warning`,
  `critical`, `unknown`, `not_applicable` or *could not run*. Cmdlets, CSV,
  WMI and the registry first; no parsing of localized `dcdiag` or `repadmin`
  text.
* **Read-only, always**, and "never healthy by default": a controller that
  cannot be reached shows unknown.
* **Domain view and the card.** The organization's Overview card "Directory
  health" is built from the stored `health_read` snapshots, with age, and
  counts from `status`; the Roles tab on a controller shows the same findings
  for that controller. Both are ADR-0072 placements.
* **Feature 12 slice 2** (scheduled checks) is the hourly scheduled read
  above; its notifications go through ADR-0053 as every alert does. **Slice
  3** (directory accounts locked out, expired, passwords expiring, disabled,
  stale, privileged snapshots and their differences) is the `state` filters
  of `user_list` and `privileged_members`; **slice 4's** lockout and
  privileged-change events are section 7 (through ADR-0060); the 4771 and
  4776 detection and the consolidated report stay there. **Slice 5**
  (several domains and forests; unmanaged controllers listed from the
  directory) is partly here (one chosen controller per domain, section 3)
  and partly later (controllers without an agent shown as *not managed*).
* **Samba domain controllers** are not covered, as in feature 12.

### 9. Testing

**Real controller: the owner's two test servers are never promoted.** The
owner forbade it. The module is tested on a **separate Windows Server VM on
the owner's Proxmox host**, one VM at a time, torn back to a snapshot after
each phase. (Credentials and addresses for the host are in the owner's
notes and not in this repository.)

* **The network (review).** The test controller is **one Proxmox VM on the
  normal network**, not on an isolated bridge with a second NIC. It has **no
  DHCP role** and a static address, its own AD-integrated DNS with **no
  forwarders**, and a **fresh forest under a reserved name** (a `.test` name,
  which is never delegated). The **Proxmox VM firewall allows only outbound
  traffic and our server**: inbound to the VM is dropped except what the test
  needs from the operator's host, and outbound is allowed only to the test
  EasyRMM server's address and port (and the Proxmox-side time source if
  needed), so the controller cannot serve DNS or DHCP to, or take them from,
  the real network. The VM has one NIC.
* **How the agent reaches a console.** The agent enrols against the test
  EasyRMM server, the one address the VM firewall allows. No second NIC and
  no isolated bridge are used.
* **One VM at a time** limits what can be proved: a single controller has no
  replication partner. Controller selection, pin and failover, "reads from the
  same controller", the 2042 and replication-failure alert and the
  difference between controllers are tested **server-side with the contract
  test's fake agent and recorded `Get-ADReplicationFailure` output** (a
  fixture captured from a real two-controller domain when the owner allows two
  small VMs at once). Until that real pair exists the ADR says **"not verified
  against a second real controller"**.
* **Steps (a phase each, snapshot between).**
  1. Install, promote (new forest on a `.test` name, no forwarders), confirm
     `roles` lists `ad_ds`, `dns` and not `dhcp` or `ad_cs`.
  2. **The gate:** as SYSTEM on the controller, what can the agent create,
     change, reset, disable, move and delete? Record per action. The
     result decides slice A4 onward (section 3).
  3. `status` and `ou_tree` (RODC flag, domain SID, Recycle Bin, PDC
     emulator, `Domain` registry value), the module-missing path (remove
     the RSAT feature on a snapshot).
  4. Reads: generate **20,000 test users** in several OUs with a script kept
     in the test folder (never committed with real names), walk every page,
     record time and memory; `too_many` at the bound; every state filter.
  5. Writes on ordinary test accounts: create (with a generated and a typed
     password), edit each allowed attribute, disable, enable, unlock (lock
     one out with bad passwords), move, reset with and without must-change,
     add and remove group members, create and delete a group, delete a user
     with the Recycle Bin on and off, computer disable, each with
     confirmation and step-up.
  6. **The guard**, each refused: a Domain Admins member, a member of a group
     nested in Domain Admins, an account whose primary group is Domain
     Admins, `krbtgt`, the built-in Administrator **renamed**, a user with
     a stale `adminCount` of 1, the controller's own computer account, a
     member of DnsAdmins, and an add to Domain Admins; a service account with
     an SPN (allowed only with the second confirmation), a group managed
     service account (the test enables a KDS root key; refused), an object
     protected from accidental deletion (refused, flag untouched).
  7. Secrets: after a reset (and a create), search the server database, its
     logs and the audit rows, the job output, the agent's own log **and its
     job journal**, and **the PowerShell logs 4103 and 4104 as ADR-0060
     collects them (module logging and script block logging switched on
     for this test)** for the test password and, in the credential
     fallback, the test administrator's password; check that the directory's 4724 event names the computer
     account as subject (the attribution caveat of section 3).
  8. Alerts: lock out 10 test accounts for the lockout policy; add a test
     user to a test privileged group (and to Domain Admins from the
     controller's own tools) for the privileged policy; confirm quiet:
     a week-equivalent of ordinary changes opens nothing; auditing off, the
     difference read still opens the privileged alert once.
  9. Toggle the module off: no job is sent (server log and the agent's job
     journal), no snapshot refresh, alerts resolve with `module off`.
* The VM is rolled back to its clean snapshot after each phase and deleted
  when the work is done. Until these steps are run by the owner or the
  orchestrator, the implementation notes say **"not verified on a real
  domain controller"**.

**Unit tests (Go, no Windows).** Per action, ADR-0073's list: the argument
validator with fuzzing on names, DNs and SIDs (a GUID where a SID is
expected; a DN not in the last tree read; a name with quotes, `$()`, a
backtick, a newline or `;` arrives unchanged), the stdin document builder, the
result decoder, the catalogue lint extended with: every write action carries
`GuardsProtected`; every tier 3 action requires step-up and confirmation;
no action's schema has a "group" parameter that could be a protected group's
SID unchecked; **the server's RID table refuses 500, 502, 512, 518, 519 and
`S-1-5-32-544`** under any name; the controller-selection function over a table
(pinned, PDC emulator, most recent heartbeat, offline, RODC, caller's site,
none); the password generator (classes, length, no repeat across calls); the
cursor and the 20,000 bound over fixtures.

**Integration (server, real PostgreSQL).** Permission matrix for the five
built-in roles over the four permissions; a write refused for a Site
Administrator; a job round trip with the contract test's fake agent; the
secret row deleted at delivery and a redelivery refused; **the test password
absent from `jobs`, the audit table, the snapshot table and the server log**
(grep of the stored rows, ADR-0073); a protected result recorded as a failure
and audited as refused; sensitive fields hidden from `ad.view`; snapshot
staleness and invalidation by a write; default policies created
idempotently, a second enable creating none, an organization not allowed by
`devscope` getting none; the alert kinds evaluated, deduplicated across
controllers and skipped while the module is off or the role is removed; the
subject fallback to the chosen controller. No mocks of our own code.

**PowerShell AST check (Windows runner CI).** ADR-0073's check runs over
every script of this module, with the rule that no `-Filter`,
`-LDAPFilter` or `-SearchBase` argument takes a value that is not literal or
the validated `$p.container`, and that `-Server` is never an argument taken
from `$p`, and that a password or credential is read from `$p` into a
variable and passed to `ConvertTo-SecureString`/`-Credential` from that
variable, never as a literal or inside a built string.

**Windows runner CI where feasible.** A `windows-latest` runner has no AD DS.
What it can run: the AST check; every script's parse; the stdin parameter
pattern with hostile values; the typed result of the actions that can run
without a directory (`module_missing` when the module is absent, and the
module's absence is the runner's normal state unless the RSAT feature is
added, which is tried); the replication-failure result decoder over the
recorded fixture. Whether the runner can host an AD LDS instance (the
ActiveDirectory cmdlets work against it, per Microsoft's cmdlet page) so that
some cmdlets run against a real directory without a reboot is **to try, not
relied on**; promotion needs a reboot, which a hosted job cannot do. The CI
says which scripts ran and which were skipped, as ADR-0073 requires.

### Organization scope

Every automatic behaviour here goes through `modules.Allowed`, which wraps
`devscope.Allowed(orgID)` (ADR-0073's framework gate): the hourly
replication and privileged-membership reads, the evaluation of the three
alert kinds, the default-policy creation, the controller-pin choice's
background refresh of `status`, and the rescans that feed them. Operator
requests are gated by the toggle and permissions as every call is. The
dev-scope guard has not landed everywhere; until it has, `modules.Allowed`
calls `devscope.Allowed` and the toggle only, as ADR-0073 says.

## Slices

Files named exist today (checked 2026-11-26) unless marked *new*. Builders
make small additive edits to the hotspots: `server/internal/rbac/rbac.go`
(none: the permissions exist after ADR-0073), `internal/agentproto/agentproto.go`
(the role `detail`), `agent/runner/runner.go`, `web/src/pages/devices/DeviceDetailPage.tsx`,
`web/src/pages/organizations/levelTabs.tsx` and `server/internal/app/app.go`.
New (proposed, not in the repository yet): `server/internal/winmod/` (ADR-0073's
framework) and `server/internal/winmod/activedirectory/` (catalogue, scripts,
guard, selection). A slice merges only when the catalogue lint and its
Windows-runner tests pass. ADR-0073 slices 1 to 5 are required first
(5 proven by Defender); 6 and 7 for slices A6 and A7.

1. **A1 Identity and the gate.** The `ad_ds` role `detail`, `ad_domains`
   (domain SID, DNS name, pinned device; migration `server/migrations/9xxxx_ad.sql`,
   number from the integrator, goose up and down), `status` and `ou_tree`, the
   controller-selection function with its table tests, and the **real-controller
   phases 1 to 3** including the SYSTEM write question. **Go or no-go for A4
   and A5.**
2. **A2 Reads.** `user_list`, `user_get`, `group_list`, `group_members`,
   `computer_list`, paging and the 20,000 bound, the state filters, snapshot
   recording of the controller, the `protection` field. Needs A1. Real phase 4.
3. **A3 The guard.** The script's protected-set walk, the service-account
   classes, the server's RID table, `protected_target` handling and audit,
   and the catalogue lint rules. **Before any write action.** Needs A1.
4. **A4 User writes.** `user_unlock`, `user_enable`, `user_disable`,
   `user_set`, `user_move`, `user_create`, `user_reset_password` with the
   generated-password response, the partial-result handling, the secret path
   and its grep tests. Needs A1 (go) and A3. Real phases 5 to 7.
5. **A5 Groups and deletes.** `group_create`, add and remove members,
   `group_delete`, `user_delete`, `computer_disable`, the delete dialogs
   (Recycle Bin wording). Needs A4.
6. **A6 Health and replication.** `health_read`, the hourly scheduled read,
   `ad_replication_failed` and its default policy, the domain subject (or its
   fallback). Needs A1 and ADR-0073 slices 6 and 7.
7. **A7 Event alerts.** `ad_account_locked_out` and `ad_privileged_group_changed`
   through ADR-0060's events, `privileged_members` and the difference, default
   policies. Needs A3 and A6; the event half waits for ADR-0060's collector,
   and the difference half works without it.
8. **A8 UI.** The "Directory" view in the device's Roles tab (users, groups,
   computers, OU tree, health), the dialogs (tiers, confirmations, the
   one-time password), the domain card (pin the controller, see the chosen one),
   the Overview "Directory health" card, the module-off and not-offered states.
   Grows with each slice, from A2.
9. **A9 CI.** The AST rule additions, the recorded fixtures, the Windows runner
   job, the AD LDS trial. Grows with each slice.

A1 first; then A2 and A3 in parallel; then A4, A5; A6 and A8 alongside.

## Consequences

* The console gets everyday AD tasks on ordinary accounts and cannot touch
  the accounts that hold the domain. An Organization Administrator cannot
  reset the domain administrator's password from here; that is the design.
* **SYSTEM is expected to be able to write (the `SY` SID); to confirm at
  R1.** If some action fails there, the per-request credential fallback
  carries it, at the cost of a typed administrator password per request.
* In the directory's own audit trail, changes appear as the controller's
  computer account, not the technician; EasyRMM's audit row is the only
  record of who asked.
* Reads are bounded: very large containers must be browsed by OU. The
  numbers are measured, not promised.
* One controller per domain keeps the module simple and its failures plain;
  a controller that is offline stops writes until another qualifies.
* The module stores no directory content beyond short-lived snapshots;
  personal fields are sensitive and short-lived.
* Feature 12 becomes this module's health half; its carrier changes from a
  new job kind to `winmod`.
* Everything about real directories is "not verified" until the Proxmox
  steps run; nothing in the claims above was run.

## Owner decisions

The owner's request is the only owner decision recorded. Worth the owner's
eye, with defaults chosen in review:

1. **Help-desk split.** Review gave Technicians the new `ad.helpdesk`
   (unlock, reset, enable, disable, ordinary users only) and kept create,
   delete, edit, move and group changes at Organization Administrator. If the
   owner wants a different split, it is a permission-table change.
2. **Service accounts** are allowed with an extra confirmation (gMSA and MSA
   refused); the stricter alternative is to refuse them all.
3. **If the SYSTEM account cannot write**, the per-request credential
   (section 3) is the designed fallback; storing a delegated account is not
   built.

## Amendments from the first build (2026-11-26)

*Amended 2026-11-26 (decided in review):* the first build (branch `ws/ad`) follows this ADR except where the code showed a better or a
forced choice. Each is the builder's call, not the owner's.

1. **A password becomes a SecureString without `ConvertTo-SecureString -AsPlainText`.** The AST check allows that call only inside
   ADR-0077's one pinned helper. The scripts build the SecureString from the stdin variable one character at a time
   (`AppendChar`), so a password is still never a literal and never part of a built string. The 4103 and 4104 sealing amendment to ADR-0060
   is unchanged.
2. **Pages use a sorted-name cursor, not a paged LDAP search with a sealed cookie.** `user_list` and `group_list` read the scope (at most
   20,000 objects, then `too_many`), sort in memory and return the rows after the last name given. Each page re-reads the scope, which the
   ADR's section 5 wanted to avoid; the cookie design stays the better one and is the follow-up if a real controller makes pages slow.
3. **Tier 2 has no typed confirmation.** The framework confirms only `Destructive` actions, and `Destructive` also means step-up. Tier 3 is
   `Destructive` (typed confirmation `active_directory.<action>:<SID>`, and step-up); tier 2 (`user_set`, `user_move`, `group_create`,
   `group_remove_member`) is neither. The UI asks the person to type the account's name for tier 3.
4. **A group's membership changes one member per request** (`member`, a SID), not up to 50: the framework has no list parameter.
5. **`user_set` takes each attribute as its own optional parameter** (empty clears it), not a map. `userPrincipalName` and
   `accountExpirationDate` are not offered yet.
6. **The server's protected-target check refuses every SID that is not an ordinary domain account or group**: a domain SID with a relative ID of
   1000 or more. That covers 500, 502, 512, 518, 519 and all the built-in and well-known principals without knowing the forest root, so it is
   stricter than the ADR's table. The script's full guard (nested membership through the Global Catalog, `adminCount`, primary group, the
   Domain Controllers OU, managed service accounts, fail closed) is the second check.
7. **The service-account confirmation is sent as `serviceConfirm` (`service-account:<sam>`), and sending it needs `ad.manage`** (for a password
   reset, `ad.reset_password`): the framework checks a parameter's own permission (`Param.Needs`). A Technician (`ad.helpdesk`) therefore
   cannot touch a service account. `user_create`'s password needs `ad.reset_password` the same way.
8. **`user_get` needs `ad.view_sensitive` to be asked at all** (not only to be read), and its result is kept for ten minutes.
9. **A generated password is made by the framework** (`Param.Generate`): when the request leaves a secret parameter out, the server makes it, seals
   it, and returns it once in the answer to the request (`generated`, `Cache-Control: no-store`). There is no retry with a longer one.
10. **An OU is validated in the script at write time**, not against "the last OU tree read": it must exist, be an OU or container of this
    domain, and not be under Domain Controllers. The server checks only its form (a DN of `CN`, `OU` and `DC` parts with letters, digits, space and
    `. _ -`).
11. **Not built in this slice:** controller selection and the pin (`ad_domains`; the tab works on the controller it is opened for, and says
    which), `ou_tree`'s use as a picker in the UI, `computer_list`, `computer_disable`, `privileged_members` and the privileged-group-change
    alert, the lockout alert (it needs ADR-0060's events), the organization Overview "Directory health" card, and the user and group
    create, edit, move and membership dialogs (the actions exist and are tested; the UI offers unlock, enable, disable, reset a password and
    delete for users, and lists groups and their members). `health_read` is scheduled hourly per controller, not per domain, and
    `ad_replication_failed` opens on the controller's device.

## Amendments to ADR-0073 (decided in review)

All are additive.

* **Section 1:** the `ad_ds` role gains the optional `detail` object
  `{domain, readOnly}`.
* **Step-up duration:** ADR-0073 section 4 says "within the last 10 minutes".
  ADR-0055 defines the one step-up, **5 minutes**, as ADR-0074 already says;
  this module follows ADR-0055 (ADR-0073's number is superseded).
* **Section 4, protected targets:** service accounts are a second class
  (allowed with an extra confirmation, gMSA and MSA refused), and the
  protected set also includes groups nested inside the four groups, the
  other AdminSDHolder groups, DnsAdmins and Group Policy Creator Owners,
  matched by RID and SID; a guard that cannot finish its walk refuses.
  "No action adds anyone to a protected group" stands.
* **Section 3, permissions:** `ad.helpdesk` (Technician and above) for
  unlock, reset, enable and disable of non-protected users; `ad.manage` keeps
  the rest and the service accounts. ADR-0073's "no Active Directory
  management for Technicians" is amended to this one narrow permission.
* **Section 4, execution:** the step-up is ADR-0055's 5 minutes, and
  `user_enable` and `group_add_members` also need it.
* **Section 6, alerts:** `ad_privileged_group_changed` is a third AD kind;
  the AD kinds' alert subject is the **domain**, not a device (the mechanism
  is feature 12's).
* **Section 5, reads:** a list read returns a cursor of the last name and the
  script re-enumerates a bounded scope (20,000 objects); the cursor is a
  value compared in memory and never part of a filter.

ADR-0060 is amended by name: its sealing list covers 4103 parameter values
and 4104 script text of `winmod` runs.

Feature 12 is amended as section 8 says: `winmod` instead of an `adhealth`
kind, its slices mapped onto this ADR's.

## References

Read on 2026-11-26 unless marked *not re-read*:

* Event 4740, a user account was locked out (Subcategory Audit User Account
  Management; generated on domain controllers, member servers and
  workstations): https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4740
* Event 4732 (local group member added; domain controllers, member servers,
  workstations; one event per member), and Audit Security Group Management,
  which lists 4728 and 4756 as its global and universal forms, "generated
  only for domain groups", and 4729, 4733, 4757 as the removals:
  https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4732 and
  https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-group-management
  (the pages for 4728 and 4756 returned 404 on the day).
* Active Directory replication Event ID 2042 (Directory Service log,
  tombstone lifetime): https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/active-directory-replication-event-id-2042
* `Get-ADReplicationFailure` (targets and scopes; the page does not list the
  output's properties): https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adreplicationfailure
* Protected accounts and groups, AdminSDHolder and SDProp (60 minutes by
  default, on the PDC emulator):
  https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory
* *Not re-read:* whether `adminCount` is cleared when an account leaves a
  protected group; which operations replicate urgently to the PDC emulator;
  default rights of a controller's computer account; `tokenGroups`;
  the `Domain` value under `Tcpip\Parameters`; DnsAdmins and Group Policy
  Creator Owners as escalation paths; the ActiveDirectory module on Server
  Core.
* Repository: ADR-0073, ADR-0074, ADR-0055 (*Step-up authentication*),
  ADR-0060 (detections, lines for 4740 and 4728/4732/4756), ADR-0072,
  `docs/architecture/feature-plan-msp.md` (feature 12),
  `server/internal/rbac/rbac.go`, `server/internal/monitoring/policies.go`,
  `server/internal/devscope/devscope.go`.
