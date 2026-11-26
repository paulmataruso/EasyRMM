# ADR-0076: Managing the Windows server roles from the console (certificate authority, DNS, DHCP, file sharing, print)

* Status: Accepted (2026-11-26, after an independent review). Design only; no code is changed by this ADR.
* Asked for by the owner (2026-11-26): "In addiitnal to AD, I would like
  modules for AD Cert Authority, DNS, DHCP, File Shareing and Print Server
  as well. These modules can be toggled off if the user does not want them.
  I exspcet full management from the GUI for all of these". Those words are
  the only owner decisions here. Everything marked *decided in review* is the
  writer's call and the owner can overturn it.
* Builds on: [ADR-0073](0073-windows-management-modules.md) (the framework:
  the `winmod` job kind, `params` on standard input, the pinned script
  catalogue and its AST check, `roles` in Facts, toggles, permissions, alert
  kinds and per-organization default policies, `devscope`), which this ADR
  follows except where *Amendments to ADR-0073* says otherwise;
  [ADR-0074](0074-defender-management.md),
  [ADR-0075](0075-active-directory.md) (under review) and
  [ADR-0077](0077-windows-backup.md) (the models for structure: state,
  catalogue with risk tiers, permissions, quiet alert defaults, tests,
  slices); [ADR-0072](0072-what-each-page-shows.md) (where the tab goes);
  [ADR-0055](0055-lets-encrypt-in-one-step.md), section *Step-up
  authentication* (the one definition: a second factor within the last 5
  minutes); [ADR-0068](0068-remote-event-viewer.md) and
  [ADR-0060](0060-collecting-logs.md) (how events reach the server).
* Amends: ADR-0073 section 3 (two permissions added, below).

## Context

ADR-0073 fixes everything the five roles share: the agent reports `ad_cs`,
`dns`, `dhcp`, `file_server` and `print_server` as roles; the modules are
`certificate_authority`, `dns`, `dhcp`, `file_shares` and `print`; each is
**on by default where its role is found** and can be turned off per
organization or site; each has `<m>.view` and `<m>.manage`; a Technician has
none of `ca.view`, `dns.view` or `shares.view`; actions are fixed embedded
PowerShell scripts, with validated parameters read from standard input,
typed one-line results, and an AST check in CI. This ADR adds no job kind,
endpoint style, toggle or cache. It supplies, per role, what ADR-0073's
"How ADR-0074 to 0077 plug in" asks for: the state shown, the action
catalogue and its tiers, the alert kinds and default policies, the tab's
panels, the tests and the slices.

### What "full management" can and cannot mean

The owner expects "full management from the GUI". Honestly, per role:

* **It can mean** everything an administrator does day to day with the
  role's PowerShell module on the server: see state, create, change and
  remove the objects the role owns (zones and records, scopes and
  reservations, shares, queues and jobs), and be told when something is
  wrong.
* **It cannot mean the console as a second set of the vendor's tools.** Not
  offered, and said so in the tab: installing or removing a role, promoting
  or demoting, anything that touches a **CA private key** (backup,
  export, key archival retrieval, renewal with a new key, install), creating
  or editing certificate templates (their permissions and flags), creating a
  DHCP failover relationship (two servers, a shared secret), DHCP
  authorization in Active Directory (needs a domain-level right the agent
  does not hold), DNSSEC signing, installing a printer driver from a file or
  share, and recursive NTFS rewrites over unbounded trees. Each is either
  unsafe to do from a fixed script, needs rights the agent (running as
  SYSTEM, that is, as the computer) does not have, or has no supported
  cmdlet. The tab shows the gap with the one-line reason; it never silently
  omits.
* **Each role is managed on the computer where the agent runs.** No
  `-ComputerName`, `-CimSession` or `-Server` comes from a parameter, so a
  DNS or DHCP console cannot be pointed at another server (ADR-0075's rule
  for `-Server`). A second DHCP server or a second DNS server is its own
  device.
* **The management tools must be on the server.** The cmdlet modules
  (`ADCSAdministration`, `DnsServer`, `DhcpServer`, `PrintManagement`,
  `SmbShare`, `FileServerResourceManager`) ship with the role's
  management-tools feature. A server with the role but without the tools
  answers `module_missing`, and the tab says which feature is missing. The
  module never installs features (*decided in review*).
* **Rights are those of the computer.** The agent runs as SYSTEM. On a
  domain member that is the computer account, which can do on the local
  server what the local Administrators can, and in the directory only what
  the computer account is delegated. So: an AD-integrated DNS change, a CA
  template publication and a DHCP authorization may succeed, fail or need a
  right the computer account lacks. **This is tested first on the real
  domain (slice R1 in each role) and decides what is offered**, the same
  "gate" ADR-0075 uses. A failure is shown as `access_denied` with the
  directory's message, never worked around with a stored credential
  (*decided in review*: no domain credential is stored for these modules).

## Decision

### In short

1. Five modules on ADR-0073's framework, one **"Roles" tab** on the device
   with a view per detected role (ADR-0072), each turned off independently.
2. Permissions: ADR-0073's ten (`ca`, `dns`, `dhcp`, `shares`, `print`, each
   `view` and `manage`), plus two added here: `print.view_sensitive` and
   `print.destroy`.
3. Every action carries a risk tier from 0 to 3. Tier 3 (destroys, weakens
   or issues trust) needs a confirmation naming the effect and a **step-up**
   (ADR-0055: a second factor within 5 minutes).
4. The CA is read-mostly and **never exposes its private key**; DNS, DHCP,
   shares and print are fully manageable with named exceptions.
5. Guards that never relax: no DNS zone transfer "to any server", no
   deletion of the records that locate domain controllers, no Everyone/
   Anonymous full share rights, no NTFS change that removes SYSTEM or
   Administrators, no Point and Print weakening.
6. Alerts are read from Facts, snapshots and Microsoft-documented events,
   with quiet defaults: 17 kinds and 19 default policies, 12 of them on.

### 1. Identity, permissions and where it is offered

| Module | Role (ADR-0073 section 1) | Offered when | PowerShell modules |
|---|---|---|---|
| `certificate_authority` | `ad_cs` | a configured CA (the `CertSvc\Configuration\<CA name>` key exists) | `ADCSAdministration`, plus `certutil.exe` |
| `dns` | `dns` | `DNS` service and a server `ProductType` | `DnsServer` |
| `dhcp` | `dhcp` | `DHCPServer` service on a server; `state: "unconfigured"` offers only a note | `DhcpServer` |
| `file_shares` | `file_server` | at least one non-administrative share | `SmbShare`, `SmbWitness` not used; `FileServerResourceManager` only for quotas |
| `print` | `print_server` | server `ProductType` and a shared printer | `PrintManagement`, plus CIM `Win32_Printer` for queue pause |

Offered also needs the toggle and the view permission, else 404
(ADR-0073). The role `state` the agent reports adds `stopped` (service
installed, not running) for the five, so an alert can read it without a job.

**Permissions.** ADR-0073 section 3's ten, with its role unions unchanged:
Technician holds `dhcp.view` and `print.view` and `print.manage` and none of
`ca.*`, `dns.*`, `shares.*`, `dhcp.manage`; Site Administrator adds
`dns.view`, `dns.manage`, `dhcp.manage`, `shares.view`, `shares.manage`,
`ca.view`; Organization Administrator adds `ca.manage`.

*Decided in review: two permissions are added, as ADR-0077 added
`backup.destroy` and ADR-0074 `defender.weaken`.*

| Permission | Holds | Gives |
|---|---|---|
| `print.view_sensitive` | Site Administrator and above | the **document names, owners and client computers** of print jobs (they name people and files). A Technician sees counts, status and ages |
| `print.destroy` | Site Administrator and above | tier 3 print actions (clear a queue, remove a printer, remove a driver, add a driver). ADR-0073 gives Technicians `print.manage`; clearing a queue or touching a driver is more than low-blast-radius. A Technician still cancels, pauses and resumes jobs |

The other four roles need no third permission: their managers are already
Site Administrator or above, and tier 3 adds the step-up. Read-Only holds
none. The unions in `rbac.go` get a small additive edit.

**Plainly.** `ca.manage` is power over trust for the whole forest: a
certificate this CA issues is accepted by every machine that trusts it. That
is why it stays with Organization Administrator, and why approving a request
is a tier 3 action. `dns.manage` on an AD-integrated zone changes the answer
every domain computer gets, and `dhcp.manage` changes what every client
receives (gateway, DNS server): both are outage-capable and are tier 2 or 3.
`shares.manage` can change who reads a company's files.

### 2. Risk tiers (all five)

| Tier | Meaning | Confirmation | Step-up | Audit |
|---|---|---|---|---|
| 0 Read | no change | none | none | compact, one row per query (ADR-0073) |
| 1 Routine | starts, ends or retries work; nothing lost | none | none | action and parameters |
| 2 Change | changes configuration; reversible by an inverse action | `confirm: "<action>:<subject>"` naming the object | none | as tier 1 plus old and new value |
| 3 Destroy or trust | deletes, weakens access, issues a certificate, rewrites permissions, stops service to clients | names the effect and the subject | **required** (ADR-0055) | as tier 2; the removed or changed set listed |

Tier 3 is `Destructive` for ADR-0073's confirmation rule; a request without
the step-up on its session is refused by the server, and the confirmation is
part of the catalogue entry, not of each handler. A tier is set in the
catalogue and can only be raised by a **dynamic rule** written in the entry
(below, such as publishing a template that allows the requester to name the
subject). Where a cmdlet has `-WhatIf` a tier 2 or 3 action offers a preview.

All scripts: strict mode, error preference stop, the module imported by name
from the system path, the parameter read from stdin as ADR-0073 section 4,
no `-Filter`, `-LDAPFilter` or `-FilterXPath` from a parameter (the CA
actions use `certutil` with a validated argument array, below), and the
result's `version` echoed. Names are length-bounded with a character class;
paths are absolute, no `..`, no device paths, local fixed volumes only;
serials are hexadecimal; addresses are parsed (`[ipaddress]`) not matched.

### 3. Certificate authority (`certificate_authority`)

#### State shown

* Facts: role state (`present`, `stopped`), CA name and type from the
  registry (`CertSvc\Configuration\<name>\CAType`: Enterprise root,
  Enterprise subordinate, standalone root or subordinate; the numeric values
  are to confirm on the test CA).
* On demand, snapshot: CA certificate (subject, thumbprint, **not after**,
  signature algorithm, key length, validity), the CA's published CRL
  distribution points and AIA (read only), the CRL period, overlap, the
  current base and delta CRL's `NextUpdate`, published templates (Enterprise
  CA), the count of pending, issued, revoked, failed and expired requests,
  database size.
* Never returned: key material, the key container name, the HSM, the
  private key location. Subject names of certificates are personal data and
  organization data: the issued and requests lists are `Sensitive` (kept 15
  minutes, redacted in audit). The permission is `ca.view`, which a
  Technician lacks.

#### What the tools allow (honest, and what needs `certutil`)

CA install and uninstall are in the separate **`ADCSDeployment`** module
(`Install-AdcsCertificationAuthority` and kin), which this ADR never calls.
`ADCSAdministration` has cmdlets to read and
change CRL distribution points and AIA (`Get/Add/Remove-CACrlDistributionPoint`,
`Get/Add/Remove-CAAuthorityInformationAccess`) and to read, publish and
unpublish templates on the CA (`Get-CATemplate`, `Add-CATemplate`,
`Remove-CATemplate`). **It has no cmdlet to list issued or pending
requests, approve, deny, revoke or publish a CRL.** Those go through
`certutil.exe`, which ships with Windows:

| Needs `certutil` | Command used (arguments from validated parameters, in an argument array to `&`, never a command string) |
|---|---|
| requests and certificates lists | `certutil -view -restrict <literal restriction built from validated enums and a number> -out <literal column list> csv` |
| approve (resubmit) a pending request | `certutil -resubmit <request id>` |
| deny a pending request | `certutil -deny <request id>` |
| revoke, and unrevoke (hold) | `certutil -revoke <serial> <reason>` and `-revoke <serial> unrevoke` |
| publish a CRL | `certutil -CRL` (or `-CRL delta`) |
| read a CRL's dates | `certutil -dump <file under the CA's CertEnroll folder>` |

The cmdlet and `certutil` list above is from the module's documented
cmdlets and from `certutil`'s help; both are **to confirm on the test CA
(slice C1)**. The restriction for `-view` is built in the script from fixed
fragments plus a typed number or enumerated disposition, **never from a free
string**; requests are looked up by request ID or serial only, never by
requester name text. Template reads and publishing (no `certutil`) use the
module alone.

#### Never exposed (decided in review)

**No CA private-key operation exists in the catalogue**: no `certutil
-backupKey`, `-backup`, `-restore`, `-recoverkey`, `-getkey`, `-repairstore`,
`-exportPFX` or `-deleteHelper`; no CA renewal or reinstallation; no archived
key retrieval (event 4883); no install, uninstall, role separation, audit
filter or CA permission change; no editing of CDP and AIA (a wrong URL breaks
chain validation for the forest; read only). A catalogue lint fails any
CA script that names a `certutil` verb not on the list above. Certificate
**templates are never created or edited** (their flags and enrollment
permissions are the common route to certificate-based privilege escalation);
they are only listed, published and unpublished.

#### Catalogue

| Action | Does | Parameters | Tier | Timeout |
|---|---|---|---|---|
| `status` | CA type, name, service, CA certificate dates, CRL dates, counts | none | 0 | 60 s |
| `ca_certificate` | the CA certificate chain: subject, issuer, thumbprint, not after | none | 0 | 30 s |
| `crl_status` | base and delta CRL: this and next update, size, period, overlap, publication points reachable (`certutil -URL` is interactive and not used; HTTP points are fetched with a bounded `Invoke-WebRequest` to the CDP URL read from the CA, from the server, 10 s) | none | 0 | 60 s |
| `template_list` | published templates on this CA, with, for each, the name, version and the **risk flags read from the template**: enrollee supplies subject, client-authentication or any-purpose EKU, who may enroll | none | 0 | 60 s |
| `template_available` | templates in the directory not yet published here (`certutil -ADTemplate` read; the "Add-CATemplate" candidates) | none | 0 | 60 s |
| `ca_findings` | **read-only misconfiguration detection, ESC1 to ESC8** (the AD CS escalation classes): template name flags, EKUs and enrollment ACLs read **from the directory** (the `CN=Certificate Templates` objects through ADSI; `Get-CATemplate` returns only the name and OID), the CA's `EditFlags` (ESC6: `EDITF_ATTRIBUTESUBJECTALTNAME2`, by `certutil -getreg policy\EditFlags`), the CA's own permissions (ESC7: ManageCA and ManageCertificates held by low-privilege principals) and **HTTP web enrollment** (ESC8: the `/certsrv` endpoint over HTTP or without extended protection). Returns findings `{id, class, subject, evidence}`; changes nothing and offers no fix button | none | 0 | 120 s |
| `template_publish` | `Add-CATemplate -Name` | template name (from `template_available`, validated against the last read) | 2; **3 when `template_list` flags the template as enrollee-supplies-subject with a client-authentication or any-purpose EKU** (dynamic rule) | 60 s |
| `template_unpublish` | `Remove-CATemplate -Name` (certificates already issued stay valid) | template name from `template_list` | 2 | 60 s |
| `requests_pending` | pending requests: id, requester, template, submitted | optional page cursor | 0, Sensitive | 60 s |
| `requests_list` | issued, revoked, failed, expired, by disposition and page | disposition enum, cursor, since | 0, Sensitive | 90 s |
| `request_get` | one request or certificate: subject, SAN, template, serial, dates, revocation | request id or serial | 0, Sensitive | 30 s |
| `request_approve` | `certutil -resubmit` on a pending request, then reports the resulting disposition | request id | **3** | 60 s |
| `request_deny` | `certutil -deny` | request id | 2 | 60 s |
| `certificate_revoke` | `certutil -revoke` with a **reason from the RFC 5280 set** (unspecified, key compromise, CA compromise, affiliation changed, superseded, cessation of operation, certificate hold) | serial, reason enum, optional free note (not sent to the CA, audit only) | **3** | 60 s |
| `certificate_unrevoke` | takes a *certificate hold* back; only that reason can be undone | serial | 2 | 60 s |
| `crl_publish` | `certutil -CRL` (base) or delta; then rereads dates | `kind` base or delta | 1 | 120 s |
| `activity` | audit events 4870, 4872, 4886, 4887, 4888, 4880, 4881 from the Security log through ADR-0068's reader, last 200; empty with a note when *Audit Certification Services* is off | cursor | 0, Sensitive | 60 s |

Honest limits: **approval is the dangerous door** (a certificate for any
subject the request names). The console shows the full request (subject, SAN,
template, requester) and requires the step-up; it can still be approved by
mistake, which is why it is tier 3 and Organization-Administrator-only.
Revocation cannot be undone except for *certificate hold*; the dialog says
so, and a revocation takes effect for clients only when the next CRL is
published and fetched (the dialog offers "publish CRL now", tier 1, after
it). On a standalone CA there are no templates and requests are usually
pending: only the request and certificate actions apply.

#### Events (Microsoft documentation read on 2026-11-26)

Security log, subcategory *Audit Certification Services* (Microsoft,
[Audit Certification Services](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services)),
written on the CA only when that subcategory audits Success and the CA's own
audit filter is set (the filter is a CA setting this module does not
change; the tab says when events are not arriving):

| Event | Meaning |
|---|---|
| 4870 | Certificate Services revoked a certificate |
| 4871 / 4872 | received a request to publish the CRL / published the CRL |
| 4886 | received a certificate request |
| 4887 | approved a certificate request and issued a certificate |
| 4888 | denied a certificate request |
| 4868 | the certificate manager denied a pending request |
| 4880 / 4881 | Certificate Services started / stopped |

The pages for individual events (for example 4887) returned 404 on
Learn on the day; the meanings above are from the subcategory page that
lists all of them. **Only 4870 and 4872 are used by an alert** (below); the
others feed the `activity` view.

#### Alert kinds

| Kind | Source | `threshold` | `minutes` | Opens on | Resolves on |
|---|---|---|---|---|---|
| `ca_certificate_expiring` (named by ADR-0073) | hourly `ca_certificate` read | days before *not after* | unused | the CA certificate expires within `threshold` days | a renewed certificate, or manually |
| `ca_crl_expiring` | hourly `crl_status` read | unused | minutes before `NextUpdate` | the base CRL's `NextUpdate` is within `minutes` or past | a new CRL |
| `ca_service_stopped` | role `state` from Facts | unused | how long | `CertSvc` stopped for `minutes` | running again |
| `ca_findings_new` | weekly `ca_findings` read | unused | unused | a **finding not in the previous read** (the first read is the baseline and opens nothing) | the finding no longer appears |
| `ca_certificate_revoked` | event 4870 | unused | unused | any revocation **made outside the console** (the module's own revoke is excluded by serial and time) | manually |

Alerts name the CA and the count, never a subject or requester (alerts are
visible to everyone who sees the device; the names are behind `ca.view`).

### 4. DNS server (`dns`)

#### State shown

* Facts: role state; the service's start type.
* On demand, snapshot: server settings (listen addresses, recursion,
  forwarders and whether forwarding is the only path, root hints present,
  scavenging interval, response rate limiting off or on, DNSSEC validation),
  zones (name, type primary, secondary, stub or forwarder; **AD-integrated**
  with its replication scope, or file-backed; dynamic update setting;
  aging; paused, shut down, signed), per zone the record count, transfer
  settings, and the notify list; statistics (queries, failures) read from
  `Get-DnsServerStatistics` where cheap.

**AD-integrated zones.** A zone stored in Active Directory is replicated by
directory replication to every DNS server in its replication scope (the
domain's, the forest's, or a custom directory partition). A change made on
this server is visible domain-wide after replication, not at once, and
**cannot be undone by looking at this server alone**. The tab labels each
zone `AD-integrated (domain)`, `(forest)` or `(custom)`, shows the scope
before any change, and says "replicated by Active Directory; other servers
will receive this". The module changes the zone **through this server**
(`DnsServer` against `localhost`), never against the directory directly.

#### Protected records (decided in review)

On a domain, DNS carries the records that let computers find domain
controllers. The module **refuses to edit or delete** this explicit set, and
nothing else (amended after review; the earlier "any name starting with `_`"
rule is withdrawn): every record under `_msdcs.<forest root>` (including the
`gc` and `<guid>` CNAMEs); the `_ldap`, `_kerberos`, `_kpasswd` and `_gc`
SRV records under `_tcp`, `_udp` and `_sites` of an AD-integrated zone; the
zone apex A, AAAA, NS and SOA records that point at domain controllers; and
the `DomainDnsZones` and `ForestDnsZones` trees. Non-AD underscore records
(`_dmarc`, `_acme-challenge`, `_domainkey`, `_spf`, SRV for other services)
**are editable**. These are changed by Active Directory itself (netlogon). A change
is refused with `protected_record`; the server's own denylist also refuses
by name, and the guard runs twice as ADR-0073 does for AD. Everything else
can be edited.

#### Catalogue (`DnsServer` module)

| Action | Does | Parameters | Tier | Timeout |
|---|---|---|---|---|
| `status` | settings, zone summary, forwarders | none | 0 | 60 s |
| `zone_list` | the zones with type, scope, dynamic update, aging | none | 0 | 60 s |
| `zone_get` | one zone's full settings, **transfer settings** and notify list | zone name | 0 | 30 s |
| `record_list` | records of a zone, paged: name, type, TTL, data, timestamp, static or dynamic | zone, optional name, type enum, cursor, bound 5,000 per page | 0 | 90 s |
| `record_add` | A, AAAA, CNAME, PTR, MX, TXT, SRV, NS (not SOA) | zone, name, type enum, TTL, typed data per type | 2 | 30 s |
| `record_set` | change a record by its old value and new value (`Set-DnsServerResourceRecord` needs both) | zone, old record, new record | 2 | 30 s |
| `record_remove` | one record by name, type and data | zone, name, type, data | 2; **3 for removing every record of a name** (`-RemoveAll`-style) | 30 s |
| `zone_create` | primary zone, file-backed or AD-integrated (scope enum), forward or reverse | name, kind, scope, dynamic update setting (never `NonsecureAndSecure` by default) | 2 | 60 s |
| `zone_set_update` | dynamic update: `None`, `Secure` (AD only), or `NonsecureAndSecure`; **`None` on an AD-integrated zone is refused** (domain computers could no longer register) | zone, enum | 2; **3 for `NonsecureAndSecure`** (allows unauthenticated updates; the dialog says so) | 30 s |
| `zone_remove` | `Remove-DnsServerZone`; **refuses outright** (not a tier, `protected_zone`) the AD domain zone, `_msdcs.<forest>`, `DomainDnsZones` and `ForestDnsZones` | zone | **3** | 60 s |
| `zone_set_replication` | AD-integrated replication scope, or convert file-backed to AD-integrated | zone, scope enum | **3** | 120 s |
| `forwarders_set` | `Set-DnsServerForwarder`: the list and timeout | up to 10 addresses (parsed), timeout | 2 | 30 s |
| `scavenging_set` | server interval and per zone aging, refresh and no-refresh intervals | zone or server, hours | 2 | 30 s |
| `scavenging_run` | `Start-DnsServerScavenging` now: **deletes stale records** | none | **3** | 120 s |
| `transfer_set` | zone transfer: none, to named servers, or to servers listed as NS; notify list | zone, mode enum (`None`, `ListedNameServers`, `NamedServers`), servers | 2 | 30 s |
| `cache_clear` | `Clear-DnsServerCache` | none | 1 | 30 s |
| `zone_reload` | `Restart`/reload of a file zone, or force an AD zone to reread from the directory | zone | 1 | 60 s |
| `service_restart` | restart the DNS service (drops in-flight queries; clients lose name resolution) | none | **3** | 90 s |

**Zone transfers: "to any server" is not an option** (decided in review). The
enumeration has no member for it; a zone found transferring to any server (the `SecureSecondaries` value `TransferAnyServer` in the `Set-DnsServerPrimaryZone` reference on Learn, read 2026-11-26; the spelling `TransferToAnyServer` used earlier in this draft is withdrawn)
is shown with a warning and a one-click "restrict to listed name servers"
(`transfer_set`, tier 2). An unrestricted transfer gives anyone the whole
zone.

**Honest limits.** DNSSEC signing and key rollover, policies, scopes (views),
conditional forwarders with AD-stored scopes and stub zones are read only.
Secondary zones and their masters can be created and listed, not edited.
Changes made by this module are logged in the server's audit log (events
below), which is how an administrator sees them in Event Viewer too.

#### Events (Microsoft documentation read on 2026-11-26)

The DNS Server audit channel (Event Viewer: *Applications and Services Logs,
Microsoft, Windows, DNS-Server, Audit*; enabled by default, Microsoft,
[Enable DNS Logging and Diagnostics in Windows Server](https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-logging-and-diagnostics)):

| Event | Meaning |
|---|---|
| 513 | the zone was deleted |
| 514 | the zone was updated (a zone setting changed) |
| 515 / 516 | a resource record was created / deleted |
| 517 / 518 | all records of a type and name / all records at a node were deleted |
| 521 | a resource record was scavenged |
| 537 | the forwarder list was reset |
| 541 | a server setting was set |
| 548 | a request to restart the DNS service was received |
| 552 | **to confirm on the test server (T1)**, with 517 and 518: not read from Learn on the day; used only in the activity view until confirmed |

#### Alert kinds

| Kind | Source | `threshold` | `minutes` | Opens on | Resolves on |
|---|---|---|---|---|---|
| `dns_service_stopped` (named by ADR-0073) | role `state` | unused | how long | the DNS service stopped for `minutes` | running |
| `dns_zone_deleted` | event 513, read through ADR-0068's reader | unused | unused | a zone deleted outside the console (the module's own delete excluded) | manually |
| `dns_forwarders_changed` | event 537 | unused | unused | forwarders reset outside the console | manually |

An alert names the zone (organization data, not personal), never records.

### 5. DHCP server (`dhcp`)

#### State shown

* Facts: role state (`present`, `stopped`, `unconfigured`).
* Snapshot: **authorization** (`Get-DhcpServerInDC` lists the servers
  authorized in Active Directory; this computer's address is in it or not;
  a workgroup server is shown "not applicable"), the server's bindings,
  conflict detection attempts, database path, audit log on; scopes with
  state (Active, Inactive), range, mask, lease duration, **free, in use and
  percentage** (`Get-DhcpServerv4ScopeStatistics`), exclusion ranges,
  reservations, options at server and scope level, policies (read only),
  failover relationship (state, mode, partner, scope list, `Get-DhcpServerv4Failover`),
  filters (read only).
* Leases are on demand, paged, and **Sensitive**: client IDs and host names
  identify devices and people. They are kept 15 minutes and not in alerts.

#### What the tools allow

`DhcpServer` covers scopes, leases, reservations, exclusions, options and
failover for IPv4. IPv6 scopes are read only (decided in review: the
common managed estate is IPv4). **Authorization in Active Directory is read
only**: `Add-DhcpServerInDC` needs a right in the directory (Enterprise
Administrators or delegation) that the computer account does not hold, and
an unauthorized DHCP server on a domain **does not start serving**, which is
the point of the control. The tab shows "not authorized in Active Directory"
with the exact command for an administrator to run and offers no button
(decided in review). **Failover** is read, and `replicate` (tier 2) pushes
configuration to the partner; creating or breaking a relationship is not
offered (it needs two servers and a shared secret).

#### Catalogue (`DhcpServer` module)

| Action | Does | Parameters | Tier | Timeout |
|---|---|---|---|---|
| `status` | authorization, bindings, scopes, statistics | none | 0 | 60 s |
| `scope_list` / `scope_get` | scopes and one scope in full | scope id (an IPv4, parsed) | 0 | 60 s |
| `exclusion_list` | exclusion ranges of a scope | scope id | 0 | 30 s |
| `reservation_list` | reservations | scope id | 0 | 30 s |
| `option_list` | server and scope options | optional scope id | 0 | 30 s |
| `lease_list` | active leases, paged (bound 5,000 per page) | scope id, cursor, optional state | 0, Sensitive | 90 s |
| `failover_get` | relationship and state | none | 0 | 30 s |
| `scope_create` | `Add-DhcpServerv4Scope`: name, start, end, mask, lease duration, state **Inactive by default** | name, range, mask, duration | 2 | 60 s |
| `scope_set` | name, lease duration, description; not the range | scope id, fields | 2 | 30 s |
| `scope_activate` | state Active | scope id | 2 | 30 s |
| `scope_deactivate` | state Inactive: **stops leasing to every client of the scope** | scope id | **3** | 30 s |
| `scope_remove` | `Remove-DhcpServerv4Scope`: also removes its leases, reservations and options; **in a failover relationship the dialog shows the partner and the relationship and that the partner's copy is affected by replication** | scope id | **3** | 60 s |
| `exclusion_add` / `exclusion_remove` | exclusion ranges (the add refuses a range outside the scope) | scope id, start, end | 2 | 30 s |
| `reservation_add` / `reservation_set` | reservation by client ID (MAC) and address | scope id, address, client id, name | 2 | 30 s |
| `reservation_remove` | removes a reservation (an active client keeps its lease until it expires) | scope id, address | 2 | 30 s |
| `option_set` | scope or server **options by a fixed list**: 3 router, 6 DNS servers, 15 domain name, 42 NTP, 51 lease time, 66 and 67 boot server and file (parsed as addresses or bounded strings) | scope id or server, option id from the list, value | 2; **3 for any change to 3 or 6 at server level, and on a scope with more than 50 active leases** (dynamic rule: the new gateway or DNS server reaches that many clients) | 30 s |
| `lease_remove` | `Remove-DhcpServerv4Lease`: frees an address; the client renegotiates | scope id, address | 2 | 30 s |
| `lease_to_reservation` | `Add-DhcpServerv4Reservation` from a lease | scope id, address | 2 | 30 s |
| `failover_replicate` | `Invoke-DhcpServerv4FailoverReplication` | optional scope | 2 | 120 s |
| `service_restart` | restart the DHCP service (clients cannot renew meanwhile) | none | **3** | 90 s |

A new scope is created **Inactive** and the console shows an activate step,
so a scope never begins serving by accident (decided in review). Options
outside the list (vendor classes, policies) are read only.

**Events (to confirm at the R-step).** The writer's recollection of the DHCP
Server System-log events, **not verified on Learn on the day**: 1046 (not
authorized, to confirm), 1020 (scope range full or nearly so, to confirm) and
1063 (authorization state, to confirm). They are the **only** DHCP event
sources an alert may use, and only after slice H1 confirms ID, log, source and
text on the test server (tested in T1 and T2). Until then the alerts read
authorization from `status` and fullness from scope statistics.

#### Alert kinds

| Kind | Source | `threshold` | `minutes` | Opens on | Resolves on |
|---|---|---|---|---|---|
| `dhcp_scope_exhausted` (named by ADR-0073) | hourly `scope_list` statistics | percentage in use | how long | an **Active scope of at least 20 addresses** at or above `threshold` for `minutes` | below `threshold` |
| `dhcp_not_authorized` | hourly `status` | unused | unused | a domain member DHCP server not in the authorized list (it will not serve) | listed |
| `dhcp_service_stopped` | role `state` | unused | how long | stopped for `minutes` | running |

### 6. File sharing (`file_shares`)

#### State shown

* Facts: role state.
* Snapshot: shares (name, path, description, scoped or continuously
  available, encryption, caching, folder enumeration, concurrent-user limit,
  special or not: the administrative shares `C$`, `ADMIN$`, `IPC$` and
  others created by Windows are **shown and read only**), share access
  (`Get-SmbShareAccess`), the server's SMB settings (SMB1 on or off, signing
  required, encryption required, from `Get-SmbServerConfiguration`; read
  only), counts of sessions and open files.
* **Sensitive on demand (15-minute retention):** NTFS permissions of a
  path, open files (user, client computer, path), sessions (user, client).
  A Technician has no `shares.view` at all (ADR-0073).
* Quotas, only if the **FSRM** role service is installed
  (`FileServerResourceManager` loads): quotas by path with limit, usage,
  hard or soft, template; templates; otherwise a card "quotas need File
  Server Resource Manager" with no install button.

#### What the tools allow, and the risk of NTFS changes

Share definitions are managed by `SmbShare`; share permissions are the
second gate; the effective access to a file is the **more restrictive** of
the share permission and the NTFS permission. NTFS permissions are read and
set with `Get-Acl` and `Set-Acl`. They are **the riskiest edit in this ADR**,
and are limited as follows (decided in review):

* **Edit by access entry, never by SDDL text.** The parameter is a typed
  entry (account or group by SID or `DOMAIN\name` resolved on the server, a
  right from the fixed list *Read*, *ReadAndExecute*, *Modify*, *FullControl*,
  *Write*, allow or deny, inheritance and propagation flags), added or
  removed. No parameter carries SDDL, and no action sets the owner or turns
  off inheritance.
* **The result must keep SYSTEM and the local Administrators with Full
  Control.** A change that would remove them (a deny, a removal) is refused
  with `would_lock_out`, checked in the script on the in-memory ACL before
  `Set-Acl`.
* **Large trees.** Changing the ACL of a folder with inheritance makes
  Windows rewrite the inherited entries of **every child**. On a tree of
  millions of files this takes hours, is not interruptible without leaving
  the propagation half done (a killed run leaves some children updated and
  some not; running the same entry again finishes it), and loads the disk.
  So an `ntfs_preview` action first counts items under the path with a bound
  of **100,000 items or 30 seconds**, and returns "at least N". `ntfs_ace_set`
  and `ntfs_ace_remove` refuse a path whose last preview (within 10 minutes)
  exceeded the bound, unless the request repeats the count in its
  confirmation (`confirm: "ntfs:<path>:<count>"`); the timeout for it is 2
  hours, and **one NTFS edit runs at a time per device**. The dialog says
  how long this may take and that it cannot be cancelled once started.
* **Protected paths** are refused: a drive root, `C:\Windows`,
  `C:\Program Files*`, `C:\ProgramData`, `C:\Users` itself, `System Volume
  Information`, the EasyRMM agent folder, and any path that is not inside a
  **share's path** (the module edits files that are shared, not the
  system).
* The old ACL of the **target folder** (not its children) is kept in the
  audit row as an SDDL string, `Sensitive`, for a manual restore.

**Never** (named): taking ownership, `icacls /reset`, `/inheritance:r`,
`/T` recursion by us, `takeown`, and permissions on a path outside a
share. An administrator who needs them uses ADR-0064's script runner under
`script.run`, audited as a script.

**Protected shares (amended after review).** `SYSVOL`, `NETLOGON`, `print$`,
`IPC$`, `ADMIN$` and every share whose name ends in `$` are protected:
**no remove, no access change, no NTFS edit**, refused with `protected_share`
(the server's denylist refuses by name as well). **A domain controller also
reports `file_server`** (it has SYSVOL and NETLOGON), so these rules apply
there and the module is offered there like on any server.

**Share permission guards.** Granting `Full` or `Change` to **Everyone**,
**Anonymous Logon** or **Authenticated Users**, or `Full` to **Users**, is
refused with `weakens_access` (reading is allowed). Blocking and unblocking
(`Block-SmbShareAccess`) are tier 2.

#### Catalogue

| Action | Does | Parameters | Tier | Timeout |
|---|---|---|---|---|
| `status` | shares count, SMB settings, sessions and open-file counts | none | 0 | 60 s |
| `share_list` | shares and special flag | none | 0 | 60 s |
| `share_perms_get` | `Get-SmbShareAccess` | share name | 0 | 30 s |
| `ntfs_acl_get` | the path's entries, owner, inheritance | path inside a share | 0, Sensitive | 60 s |
| `ntfs_preview` | bounded item count (above) | path | 0 | 60 s |
| `session_list` | `Get-SmbSession`, paged | cursor | 0, Sensitive | 60 s |
| `openfile_list` | `Get-SmbOpenFile`, paged, optional share | share, cursor | 0, Sensitive | 60 s |
| `quota_list` | FSRM quotas and templates | none | 0 | 60 s |
| `share_create` | `New-SmbShare`: path must exist on a local fixed volume; **refused (`protected_path`) when the path is a drive root, `%SystemRoot%` or below, or SYSVOL**; name not special; defaults: encryption off, access `Read` for Administrators and the creator account only | name, path, description, enumeration, caching enum | 2 | 60 s |
| `share_set` | description, caching, enumeration mode, concurrent limit, encrypt data (cannot set `-Special`) | name, fields | 2 | 30 s |
| `share_grant` / `share_revoke` | `Grant-/Revoke-SmbShareAccess`, `Block-/Unblock-` | share, account, right enum (`Read`, `Change`, `Full`), guards above | 2 | 30 s |
| `share_remove` | (**refused for protected shares**) `Remove-SmbShare` **removes the share, not the files**; users lose access at once and open files are dropped | name | **3** | 60 s |
| `ntfs_ace_set` / `ntfs_ace_remove` | the typed entry edits above | path, account, right, type, flags | **3** | 2 h |
| `session_close` | `Close-SmbSession`: the user reconnects at once; open files can lose unsaved changes | session id | 2 | 30 s |
| `openfile_close` | `Close-SmbOpenFile`: **unsaved changes in the file can be lost**; the dialog names the user and file | file id | 2 | 30 s |
| `quota_set` | `New-/Set-FsrmQuota`: path (inside a share), size, hard or soft, from a template or by size | path, size, kind, threshold percent | 2 | 60 s |
| `quota_remove` | `Remove-FsrmQuota` (data is untouched) | path | 2 | 30 s |

A hard quota below current usage blocks writes at once; the dialog shows
usage and refuses a hard limit below 100 percent of use without the
confirmation naming it.

SMB settings (SMB1, signing, encryption) are **read only**; ADR-0064 or the
hardening feature owns them (decided in review).

#### Events (Microsoft documentation read on 2026-11-26)

Security log, subcategory *Audit File Share* (not audited by default;
Microsoft, [Audit File Share](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-file-share)):

| Event | Meaning |
|---|---|
| 5142 | a network share object was added |
| 5143 | a network share object was modified |
| 5144 | a network share object was deleted |

5140 (a share was accessed) is **not used**: it is one event per access and
is noise.

#### Alert kinds

| Kind | Source | `threshold` | `minutes` | Opens on | Resolves on |
|---|---|---|---|---|---|
| `file_server_service_stopped` | role `state` | unused | how long | `LanmanServer` stopped for `minutes` | running |
| `share_changed` | events 5142, 5143, 5144 via ADR-0060's collector | unused | unused | a share added, modified or deleted **outside the console** | manually |
| `fsrm_quota_high` | hourly `quota_list` | percent used | unused | a hard quota at or above `threshold` | below |

### 7. Print server (`print`)

#### State shown

* Facts: role state.
* Snapshot: printers (name, driver, port, shared and share name, published
  to AD, status, queue length, default or not), ports (TCP/IP address and
  port number, WSD, local), drivers (name, version, manufacturer,
  environment, whether **inbox or third-party**), jobs (id, status, size,
  submitted, **age**) with **document name, owner and client computer
  `Sensitive`** and gated by `print.view_sensitive`, spooler state, and the
  **Point and Print state** below.

#### PrintNightmare and Point and Print (decided in review: never weakened)

The Print Spooler was the route of CVE-2021-34527 ("PrintNightmare").
Microsoft's guidance (MSRC, CVE-2021-34527, and KB5005652) is that installing
or updating a printer driver should need administrator rights, controlled by
the registry value `RestrictDriverInstallationToAdministrators` (set to 1),
and that Point and Print must not be configured to suppress warnings and
elevation (`NoWarningNoElevationOnInstall`, `UpdatePromptSettings`, under
the Point and Print policy key). This module:

* **Reads** these (`hardening_status`) and shows them red when weakened.
* **Offers one write that can only strengthen**: `point_and_print_restrict`
  sets `RestrictDriverInstallationToAdministrators` to 1 and sets neither of
  the other two. No action takes a value for any of the three, so none can
  weaken them. An enforcing Group Policy overrides the registry; the tab
  says "managed by policy" (ADR-0074's rule).
* **Installs no driver from a file, share or the internet.** The only driver
  action installs one already in the driver store, by name. A third-party
  driver that is not staged is installed by an administrator (staging with
  `pnputil`), outside the console.
* Shows a note on **domain controllers and servers that do not print**:
  Microsoft's guidance is to stop the Print Spooler where it is not needed;
  the console does not do it (a service action; ADR-0064).

The exact key path and value names and the Group Policy precedence are from
Microsoft's CVE and KB pages and are **to confirm on the test server**
(slice P1).

#### Catalogue (`PrintManagement`, plus CIM for queue state)

| Action | Does | Parameters | Tier | Timeout |
|---|---|---|---|---|
| `status` | counts, spooler state, the hardening state | none | 0 | 60 s |
| `printer_list` | printers with status and queue length | none | 0 | 60 s |
| `port_list` / `driver_list` | ports; drivers with inbox or third-party | none | 0 | 60 s |
| `job_list` | jobs of a printer, paged, bound 1,000 | printer, cursor | 0, Sensitive (names) | 60 s |
| `hardening_status` | Point and Print and restrict-driver values, spooler on a DC | none | 0 | 30 s |
| `job_cancel` | `Remove-PrintJob`, **up to 50 job ids** in one request | printer, ids | 1 | 60 s |
| `job_pause` / `job_resume` / `job_restart` | `Suspend-/Resume-/Restart-PrintJob` | printer, ids (up to 50) | 1 | 60 s |
| `printer_pause` / `printer_resume` | `Win32_Printer` `Pause`/`Resume` through CIM (PrintManagement has no queue pause) | printer | 1 | 30 s |
| `printer_set` | rename, comment, location, **sharing on or off and share name**, publish to AD, default settings through `Set-PrintConfiguration` (duplex, paper, colour) | printer, fields | 2 | 60 s |
| `printer_add` | `Add-Printer` with a driver **already installed** and an existing port | name, driver name, port name | 2 | 60 s |
| `port_add` | `Add-PrinterPort` TCP/IP: a parsed address and port number | name, address, port | 2 | 30 s |
| `port_remove` | `Remove-PrinterPort` of a port **no printer uses** | name | 2 | 30 s |
| `spooler_restart` | restart the Print Spooler (queued jobs persist; all printing stops meanwhile) | none | **3** | 90 s |
| `point_and_print_restrict` | the strengthening write above | none | 2 | 30 s |
| `queue_clear` | cancel **all** jobs of a printer | printer | **3** | 120 s |
| `printer_remove` | `Remove-Printer`: removes the queue **and its share** | printer | **3** | 60 s |
| `driver_add` | `Add-PrinterDriver -Name` for a driver already in the store | driver name from the store list | **3** | 120 s |
| `driver_remove` | `Remove-PrinterDriver` (not `-RemoveFromDriverStore`), refused while a printer uses it | driver name | **3** | 60 s |

Tier 3 needs `print.destroy` (Site Administrator and above) plus the
step-up (so a Technician cannot restart the spooler); a Technician manages jobs, queues and sharing through tiers 1 and 2.

#### Alert kinds

| Kind | Source | `threshold` | `minutes` | Opens on | Resolves on |
|---|---|---|---|---|---|
| `print_queue_stuck` (named by ADR-0073) | hourly `printer_list` | jobs | age | a queue whose oldest job is in an error or offline state, or older than `minutes`, with at least `threshold` jobs; **a deliberately paused printer is not stuck** | the queue drains |
| `print_point_and_print_weakened` | `hardening_status`, hourly | unused | unused | `RestrictDriverInstallationToAdministrators` not 1, or either suppression value set | corrected |
| `print_service_stopped` | role `state` | unused | how long | Spooler stopped for `minutes` on a computer reporting `print_server` | running |

**Events (to confirm at the R-step).** PrintService 808 and 316 (the
writer's recollection of Admin-log events about a failed spooler plug-in load
and a driver added; **not verified on Learn on the day**) are the only print
event sources an alert may use, after slice P1 confirms them on the test
server. Until then the alerts read the registry and the queues.

### 8. Where it sits (ADR-0072, ADR-0073 section 7)

One **"Roles" tab on the device**, with a view per detected and enabled
role (the module's toggle and permission decide the view); the Overview card
per role at organization level shows counts from snapshots and Facts, never a
job: certificates expiring, zones, scopes with the highest fill, shares,
printers with stuck queues. Toggles live in the "Windows modules" card of the
organization and site pages. A role that is off for the site: URL shows "this
module is off for this site". One shared `ModuleTab` frame; each role
supplies panels:

| Role | Panels |
|---|---|
| CA | Overview (CA certificate, CRL), Templates, Requests (pending, issued, revoked), Activity |
| DNS | Zones, Records (per zone), Forwarders and scavenging, Transfers |
| DHCP | Scopes, Leases, Reservations, Options, Failover |
| File sharing | Shares, Permissions (share, NTFS), Open files and sessions, Quotas |
| Print | Printers, Queue and jobs, Drivers and ports, Security (Point and Print) |

Server Core has no GUI and the modules run all the same; Windows desktops
never report these roles (ADR-0073). A role the agent has not yet reported
shows "not detected yet".

### 9. Alerts: all kinds and the quiet defaults

Registered with the monitoring package as ADR-0073 section 6 describes. All
obey `modules.Allowed` (so `devscope.Allowed(org)`): nothing evaluates for an
organization that is not allowed, a module that is off or a role not
detected, and open alerts resolve with `module off` or `role removed`.

Scheduled reads (`ca_certificate`, `crl_status`, `ca_findings` (weekly), `scope_list`, `status` for
DHCP, `printer_list`, `hardening_status`, `quota_list`) run **at most hourly
per device**, only for enabled modules, never when the computer is offline
(ADR-0073 section 5). Events reach the server through ADR-0068's reader (the
DNS and CA audit channels) and ADR-0060's collector (the Security log); this
ADR adds no collection. Where auditing is off, the kind is silent and the tab
says why.

Created per organization, idempotently, when the module is first enabled
there; owned by the module and marked `default`; organization-level rows.
*Decided in review*: the owner asked for server-role modules, not for rules
on them; alerts are listed because ADR-0073 names five of these kinds. A
healthy server opens none in a normal week.

| Name | Kind | Threshold | Minutes | Severity | Default |
|---|---|---|---|---|---|
| Certificate authority: CA certificate expires within 90 days | `ca_certificate_expiring` | 90 days | - | warning | on |
| Certificate authority: CA certificate expires within 14 days | `ca_certificate_expiring` | 14 days | - | critical | on |
| Certificate authority: CRL about to lapse | `ca_crl_expiring` | - | 240 | critical | on |
| Certificate authority: service stopped | `ca_service_stopped` | - | 15 | critical | on |
| Certificate authority: new misconfiguration finding | `ca_findings_new` | - | - | warning | on |
| Certificate authority: certificate revoked outside the console | `ca_certificate_revoked` | - | - | warning | **off** |
| DNS: service stopped | `dns_service_stopped` | - | 10 | critical | on |
| DNS: zone deleted | `dns_zone_deleted` | - | - | warning | on |
| DNS: forwarders changed | `dns_forwarders_changed` | - | - | warning | **off** |
| DHCP: scope nearly full | `dhcp_scope_exhausted` | 95 % | 60 | warning | on |
| DHCP: not authorized | `dhcp_not_authorized` | - | - | warning | on |
| DHCP: service stopped | `dhcp_service_stopped` | - | 10 | critical | on |
| Files: server service stopped | `file_server_service_stopped` | - | 15 | warning | **off** |
| Files: share added, changed or deleted | `share_changed` | - | - | warning | **off** |
| Files: quota nearly full | `fsrm_quota_high` | 95 % | - | warning | **off** |
| Print: queue stuck | `print_queue_stuck` | 1 job | 60 | warning | on |
| Print: Point and Print weakened | `print_point_and_print_weakened` | - | - | critical | on |
| Print: service stopped | `print_service_stopped` | - | 15 | warning | **off** |

Seventeen kinds (5 CA, 3 DNS, 3 DHCP, 3 files, 3 print) and nineteen policies
(the CA certificate kind has two thresholds), twelve on and seven off.

Why these: a stopped CA, DNS or DHCP service for ten or fifteen minutes is an
outage and a reboot is shorter; a CA certificate 90 days from its end is
warning enough to plan a renewal, and 14 days is urgent; a CRL within four
hours of lapsing means publication is failing, which breaks validation for
the forest; a DNS zone deletion is rare and consequential; a scope that has
stayed at 95 percent for an hour is about to refuse clients (small scopes are
ignored); a print queue whose first job is an hour old is stuck; a weakened
Point and Print is a known attack route. Off by default: events that are
routine on a busy estate (changes, revocations, quotas near full by design)
and the file and print service-stopped kinds. Per ADR-0074's best-match rule,
where a kind has a threshold and two enabled policies match, only the higher
opens an alert.

### 10. Organization scope

Every automatic behaviour here goes through `modules.Allowed`, which wraps
`devscope.Allowed(orgID)` (ADR-0073's framework gate): the hourly reads, the
evaluation of the alert kinds, the default-policy creation, and the role
rescans that feed them. Operator requests are gated by the toggle and the
permissions as every call is. Until the guard has landed everywhere,
`modules.Allowed` calls `devscope.Allowed` and the toggle only.

### 11. Tests

**Where each role can be tested.** The owner's two test Windows servers may
get roles except **domain controller promotion**. This ADR does not rely on
them: *adding roles is not allowed there*, and DNS, DHCP and CA must not run
on a machine on a real network. A **Proxmox Windows Server VM**, one at a
time, is used, as ADR-0075 and ADR-0073 do. (Credentials and addresses are in
the owner's notes, not here.)

* **The network.** The isolated bridge ADR-0075 describes: no physical port,
  no routing, forwarding off, used by this VM and its EasyRMM test instance
  only. **DHCP on it must never serve a real network and DNS must have no
  forwarders to a real resolver**: the DHCP role is added only on this
  bridge, with a private range made for the test; DNS forwarders are empty
  or point to the VM itself. The fallback of a second NIC on the real
  network is the owner's call, as ADR-0075 says, and is **not used by these
  tests** (DHCP on a real segment is refused outright).
* **Which VM, which role, in which order.** A snapshot per phase; one VM
  runs at a time (about 4 GiB of RAM; roughly 5 GiB is free on the host).

| Phase | VM | Roles | Needs a domain | Why |
|---|---|---|---|---|
| T1 | a **standalone** Windows Server (workgroup) | file sharing, print, DNS (file-backed primary zones), DHCP (unauthorized, workgroup), standalone root CA | no | the whole of file, print, DNS record and zone work, DHCP scopes and leases without a domain; a standalone CA's requests and CRLs |
| T2 | the **ADR-0075 domain controller VM**, restored to its post-promotion snapshot **after ADR-0075's phases are done** (its design says that VM has no DHCP; this phase uses a separate branch of snapshots so ADR-0075's clean state is untouched) | AD-integrated DNS (already there), **DHCP with authorization** (done by a person with the domain rights), an **Enterprise CA** | yes | AD-integrated zones and scope, the protected locator records, DHCP authorization state, Enterprise CA templates and the publication rights of the computer account |
| T3 | the same, with the CA on a **domain-joined member** if memory allows a second small VM at once | Enterprise CA on a member server | yes | a CA on a domain controller is allowed for a test but not recommended for production; the member case is the real one |

  The CA as an Enterprise CA, the AD-integrated DNS and the DHCP
  authorization **share ADR-0075's test DC VM** from a separate snapshot
  branch (T2); the standalone roles (T1) do not need it and can run first,
  in parallel with ADR-0075's work. What one VM cannot show is **DNS
  replication to a second server, DHCP failover and a CA's CRL fetch from a
  second machine**: those are tested server-side with the contract test's
  fake agent over **recorded output** from a real pair (captured when the
  owner allows two small VMs at once); until then the ADR and the notes say
  **"not verified against a second real server"**.

* **The gate (first, per role).** As SYSTEM on the server: what can the
  agent do? Record per action: publish a template, remove a record from an
  AD-integrated zone, authorize DHCP, close an open file, `Set-Acl`. This
  decides what each role offers (the rule in *Context*).
* **Steps per role** (a phase each, rollback between):
  * *CA*: enrol; `roles` lists `ad_cs` (and not `ad_ds` on T1);
    `status`; submit a test request from a second VM or `certreq` on the
    same one; `requests_pending`, `request_approve` with the step-up,
    `request_deny`, revoke each reason, unrevoke a hold, `crl_publish`,
    confirm the CRL `NextUpdate`; publish and unpublish a test template
    (Enterprise); confirm **no certutil verb outside the list ever ran**
    (process-creation auditing in the test); confirm the private key is
    untouched.
  * *DNS*: create primary file-backed and AD-integrated zones; add, set and
    remove every record type; try to remove each protected record (refused);
    set forwarders, aging and run scavenging; set transfers to listed
    servers (and confirm "any server" is not available); confirm events 515,
    516, 513, 537 appear and the console's own changes are excluded from the
    alert.
  * *DHCP*: scope create (inactive), activate, lease from a second test VM,
    reservation, exclusion, options, lease remove, scope remove; deactivate
    with active leases; the authorization state on T1 and T2; the dynamic
    tier-3 rule for options 3 and 6 (always at server level; on a scope with leases).
  * *Files*: share create, access grant and the refused weakening, the
    open-file close (hold a file open from a second VM), session close;
    **NTFS entry add and remove on a generated tree of 150,000 files** to
    measure the time and the bound; refuse `would_lock_out`; kill the agent
    mid-propagation and rerun to confirm the documented recovery; FSRM
    quotas (install the feature on a snapshot for this phase).
  * *Print*: add a TCP/IP port to a non-existent address, a printer with an
    inbox driver, pause, resume, cancel jobs, clear the queue, share and
    unshare, driver add (staged) and remove; `hardening_status` with each
    value weakened by hand (the alert opens) and strengthened by the module;
    a refused driver from a path; Point and Print precedence under a local
    policy.
  * *All*: toggle each module off and confirm no job is sent (server log and
    the agent's job journal), no snapshot refresh, alerts resolve with
    `module off`; the audit rows hold no sensitive values.
* Rolled back after each phase, deleted when the work is done. Until these
  steps are run by the owner or the orchestrator, the implementation notes
  say **"not verified on a real server"**.

**Unit tests (Go, no Windows).** ADR-0073's list, per action: the validator
with fuzzing (zone names, record names and data, MACs, scope IDs, UNC and
local paths, share names, serials, request IDs, printer names); a value
containing quotes, `$()`, backticks, newlines and `;` arrives unchanged; the
stdin builder, the decoder, the pinned hash; plus this ADR's: the CA
`certutil` verb allowlist lint (a script naming a verb off the list fails);
that no CA action takes a free string into a `-view` restriction; the
dynamic tiers (template publish, DNS update setting, DNS record-remove-all,
DHCP options 3 and 6, NTFS bound) over a table; the protected-record and
protected-path denylists (the DNS name set, the path set, the paths outside
a share); the weakening refusals (everyone, anonymous, authenticated users,
`TransferAnyServer`, Point and Print values); the NTFS entry builder
(rights enumeration, `would_lock_out` over a table of ACLs, SYSTEM and
Administrators kept); the 100,000 bound logic; the catalogue lint
(every tier 3 needs step-up, confirmation, `print.destroy` where print).

**Integration (server, real PostgreSQL).** The permission matrix over the
five built-in roles and the twelve permissions (a Technician holds none of
`ca.*`, `dns.*`, `shares.*`, `dhcp.manage`, a Site Administrator no
`ca.manage`; `print.destroy` only Site Administrator and above); toggle and
404; a job round trip with the contract test's fake agent; a tier 3 refused
without a step-up and accepted with one inside 5 minutes and refused at 6;
confirmation mismatch refused; Sensitive results hidden from a caller
without the permission and absent from the audit row (grep of stored
rows); default policies created idempotently, a second enable creating none,
a disallowed organization getting none; alert kinds skipped while the module
is off or the role removed; the console's own changes excluded from the
event alerts. No mocks of our own code.

**PowerShell AST check (Windows runner CI).** ADR-0073's check over every
script, plus: no `-ComputerName`, `-CimSession`, `-Server`, `-CimInstance`
taken from `$p`; `certutil` called only with the call operator and an
argument array; no `Set-Acl -Path` with a value other than the validated
path; no `Remove-*` with `-Force` unless in the catalogue; no
`-RemoveFromDriverStore`.

**Windows runner CI.** A `windows-latest` runner has the `SmbShare` and
`PrintManagement` cmdlets and `certutil`, and no DNS, DHCP or CA role. It
runs: the AST check; every script's parse; the stdin hostile-value pattern;
the file-share and print actions against **a local test share and a test
printer (a "Microsoft Print to PDF" queue)**; the `module_missing` result of
the CA, DNS and DHCP scripts; the decoders over recorded fixtures from the
test VMs. The CI says which scripts ran and which were skipped.

## Slices

ADR-0073 slices 1 to 5 (roles in Facts, toggles and permissions, `params`,
step-up, the `winmod` kind proven by Defender) are required first; 6 and 7
(snapshots, alerts) for the alert slices; 8 (the `ModuleTab` frame) for the
UI slices. Files named exist after ADR-0073's slices; builders make small
additive edits to `server/internal/rbac/rbac.go`, `server/internal/app.go`,
`agent/runner/runner.go`, `web/src/pages/devices/DeviceDetailPage.tsx` and
`web/src/pages/organizations/levelTabs.tsx`. New: `server/internal/winmod/<role>/`
(catalogue, scripts, guards). A slice merges only when the catalogue lint and
its Windows-runner tests pass. The five roles are independent after R0 and can
be built in parallel.

**R0 Shared.** The two added permissions and their unions, the "Roles" tab
shell with a view per role and its empty states, the `stopped` role state, the
tier-3 dynamic-rule support in the catalogue type, the shared AST additions,
the Overview cards frame. Do first.

**Order across roles** (by risk, simplest first; any can run in parallel after
R0): file sharing and print (testable on the runner and on any test server),
then DNS and DHCP (a domain for the AD-integrated and authorization steps),
then the certificate authority (most sensitive, needs the Enterprise CA).

* **File sharing.** **F1** reads and **the protected-share list and refusals (SYSVOL, NETLOGON, `print$`, `IPC$`, `ADMIN$`, every `X$`, protected create paths)** (`status`, `share_list`, `share_perms_get`,
  sessions, open files) and the view, runner tests. **F2** share create, set,
  remove, share access grant and revoke with the weakening guards. **F3**
  open-file and session close. **F4** NTFS: `ntfs_acl_get`, `ntfs_preview`,
  the entry builder, the lockout and protected-path guards, the bound, the
  2-hour run and the generated-tree test. **F5** FSRM quotas. **F6** alerts
  (`file_server_service_stopped`, `share_changed`, `fsrm_quota_high`) and
  default policies.
* **Print.** **P1** reads, `hardening_status`, the gate. **P2** jobs (cancel,
  pause, resume, restart) and printer pause and resume. **P3** printers,
  ports, sharing, spooler restart. **P4** tier 3: queue clear, printer
  remove, driver add and remove. **P5** `point_and_print_restrict` and the
  Security panel. **P6** alerts and default policies.
* **DNS.** **D1** reads, **the protected-zone and protected-record lists and the `protected_zone` refusals**, and **the gate** (what SYSTEM can do against an
  AD-integrated zone). **D2** record add, set, remove with the protected-record
  guard. **D3** zone create, remove, update setting, replication scope.
  **D4** forwarders, scavenging, transfers (no "any server"), cache and
  reload. **D5** events and alerts (`dns_service_stopped`, `dns_zone_deleted`,
  `dns_forwarders_changed`).
* **DHCP.** **H1** reads, authorization state and **the gate**. **H2** scopes
  (create inactive, set, activate, deactivate, remove). **H3** exclusions,
  reservations, options with the dynamic tier. **H4** leases (list, remove,
  to reservation), failover read and replicate. **H5** alerts and default
  policies.
* **Certificate authority.** **C1** reads (`status`, `ca_certificate`,
  `crl_status`, `activity`) and **the gate** (which cmdlets and `certutil`
  verbs exist and work as SYSTEM). **C2** templates (list, available, publish,
  unpublish with the dynamic tier) and **`ca_findings` (ESC1 to ESC8) with `ca_findings_new`**. **C3** requests and certificates lists,
  `request_get`, the restriction builder and its lint. **C4** approve, deny,
  revoke, unrevoke (tier 3 and 2). **C5** `crl_publish` and the CRL alerts.
  **C6** the remaining alerts and default policies. The `certutil` verb
  allowlist lint lands **in C1**, before any write.
* **Cross.** **X1** the test phases T1 to T3 and the recorded fixtures (the
  owner or orchestrator; not a builder). **X2** the Windows runner job and the
  per-role CI skips. **X3** the Overview cards, one per role.

Dependencies: F1, P1, D1, H1 and C1 first in each role; D2 needs D1; H2 needs
H1; C3 needs C2's flag reading; C4 needs C3 and the step-up.

## Consequences

* Each role is a catalogue of fixed scripts on the existing framework: no new
  job kind, transport or store; a mistake in quoting or audit is fixed once.
* Some "full management" stops at named lines (CA keys, template editing,
  DHCP authorization and failover creation, DNSSEC, unstaged drivers,
  unbounded NTFS rewrites). The tab says so; it is a deliberate cost for
  safety, not an omission.
* Running as the computer, some directory-touching actions may be refused
  where an administrator's own account would succeed; the gate in each role
  reports that and no credential is stored to get around it.
* Without the management-tools features a role shows `module_missing`; the
  console never installs them.
* A Technician sees print and DHCP state but none of CA, DNS, shares: a
  deliberate cost of ADR-0073.
* NTFS changes remain the riskiest action; the bound, the lockout refusal and
  the single-edit rule reduce it and do not remove it.

## Owner decisions

None are required to start. Choices made in review that the owner may want to
see: server roles stay **on by default where the role is found** (ADR-0073);
no domain credential is stored for these modules; the CA exposes no private
key operation and no template editing; DHCP authorization is read only; NTFS
edits are by typed entry only and bounded; and the test plan uses a Proxmox VM
and, for the Enterprise CA, AD-integrated DNS and DHCP authorization, shares
ADR-0075's domain controller VM from a separate snapshot branch. The one
place an owner yes would change the plan is the **fallback second NIC**, which
these tests do not use.

## Amendments to ADR-0073 (decided in review)

* Section 3 gains `print.view_sensitive` and `print.destroy`, both held by Site
  Administrator and above. Section 1's role `state` gains `stopped` for the five
  server roles. The catalogue type supports a **dynamic tier** (a rule written
  in the entry that raises an action's tier from the parameters or the last
  read).

## Amendments from building DNS and DHCP (decided in review)

*Amended 2026-11-26 (decided in review), by the builders of the DNS and DHCP
modules. Each is the safe side of what the code showed; the owner can
overturn any.*

* **No dynamic tier.** ADR-0073's `Action` has two levels (a plain action, and
  a destructive one with confirmation and step-up), and a tier that depends on
  a parameter would make the confirmation depend on a value the server has not
  yet read. The rules are instead **separate actions**, the dangerous one always
  tier 3: `record_remove` (tier 2) and `record_remove_all` (tier 3);
  `zone_set_update` (`None` or `Secure`, tier 2) and `zone_allow_nonsecure`
  (tier 3); `option_set` (options 15, 42, 51, 66, 67, tier 2) and
  `option_set_network` (options 3 and 6, tier 3 at **every** level, not only at
  server level or on a busy scope). `option_set` refuses 3 and 6 with
  `use_network_option`. The DHCP rule is stricter than section 5 wrote it.
* **Tier 2 has no framework confirmation.** Only tier 3 sends `confirm` and
  needs the step-up. A tier 2 change is confirmed by the console's dialog, and
  its old and new values are the action's parameters, which the audit holds.
* **A server-side guard on parameters.** `winmod.Action` gains `Guard`, which
  runs after the schema on the canonical values and refuses before any job
  exists. DNS uses it for the protected-record and protected-zone lists (409
  `protected_record`, `protected_zone`); DHCP for addresses, masks, ranges,
  hardware addresses and option values. The server's list is by name; the
  script's is the same names plus what only the computer knows: the apex A,
  AAAA, NS and SOA records of an Active Directory zone, the locator SRV names
  only in an Active Directory zone, and the computer's own domain and forest
  root zones. A non-Active Directory zone that holds `_ldap._tcp` is therefore
  refused by the server (a rare case; a name is not a zone's storage).
* **Page sizes.** A result is at most 64 KiB (ADR-0073), so `record_list` pages
  of 80 and `lease_list` pages of 100, not 5,000. The zone count of records is
  not shown (it costs a full read per zone).
* **Service state in the snapshot.** `dns.status` and `dhcp.status` carry
  `serviceState` (read with `Get-Service`), and `dns_service_stopped` and
  `dhcp_service_stopped` read it from the hourly snapshot, as the other kinds
  do, rather than from the Facts role state, which no evaluator reads.
* **Leases are opened by `dhcp.manage`.** There is no `dhcp.view_sensitive`;
  `lease_list` is a sensitive action served only with `dhcp.manage` (Site
  Administrator and above), kept 15 minutes, never a snapshot. A Technician
  sees scopes, reservations, exclusions and options.
* **A scope in a failover relationship is not removed** (`in_failover`) rather
  than removed with a dialog that shows the partner; creating and breaking
  relationships was never offered.
* **Not built here.** `dns_zone_deleted` and `dns_forwarders_changed` (they
  need the audit-channel reader, D5), forwarders, scavenging, transfers,
  replication scope, cache, reload and service restart (D4 and the rest of D3),
  and DHCP failover read and replicate and `service_restart` (H4).

## Amendments from building the certificate authority, file sharing and print (decided in review, 2026-11-26)

* **Built.** Certificate authority: `status`, `ca_certificate`, `crl_status`, `template_list`, `template_available`, `ca_findings`, `template_publish`, `template_publish_risky`, `template_unpublish`, `requests_pending`, `requests_list`, `request_get`, `request_approve`, `request_deny`, `certificate_revoke`, `certificate_unrevoke`, `crl_publish`, `activity`. File sharing: `status`, `share_list`, `share_perms_get`, `session_list`, `openfile_list`, `share_create`, `share_set`, `share_grant`, `share_revoke`, `share_block`, `share_unblock`, `share_remove`, `session_close`, `openfile_close`. Print: every action of section 7 except `Set-PrintConfiguration` defaults (duplex, paper, colour) and rename. **Not built:** NTFS permission edits and the bound (F4), FSRM quotas (F5), the `share_changed`, `fsrm_quota_high` and `ca_certificate_revoked` alerts and the PrintService event alerts (they need the event readers), the CA's CDP fetch in `crl_status`, ESC5.
* **Dynamic tier as two actions.** The server cannot read a template to know its tier, so `template_publish` (tier 2) refuses a template that lets the enrollee name the subject and can authenticate (`risky_template`), and `template_publish_risky` (tier 3, step-up) publishes it. The script decides, from the directory, not the caller.
* **Confirmation is the computer's name** for every tier 2 and 3 action here (`SubjectIsDeviceName`), not the object's name; the dialog still names the object. Tier 1 print job and printer pause or resume carry no confirmation.
* **ca_findings** reads ESC1 to ESC4 from the directory, ESC6 from the CA's `EditFlags` in the registry (not `certutil -getreg`), ESC7 from the CA's security descriptor in the registry, ESC8 by a bounded HTTP probe of `/certsrv/` on the CA itself. ESC5 is listed in the result's notes as not checked. "Low privilege" means Everyone, Authenticated Users, Users, Anonymous, Domain Users and Domain Computers; other groups are not judged. The ADR's `certutil` list shrinks to `-view`, `-resubmit`, `-deny`, `-revoke`, `-CRL` and `-dump`; a Go test fails any other verb.
* **`ca_findings_new` becomes `ca_findings_present`.** The monitoring framework judges one snapshot and keeps no earlier one, so "not in the previous read" cannot be decided. The kind holds while the weekly read has findings, resolves when none, and starts **off** (a finding stays until fixed, so it would stay open). Turn it on per organization.
* **`ca_crl_expiring` takes hours as its threshold** (default 4), not minutes with a grace. **`ca_certificate_expiring`** reads `status` (hourly), and a lower days threshold is the more urgent, so monitoring gained `ModuleKind.LowestWins`: of two matching policies the lower opens (the first, warning, stays open until it clears).
* **Print.** `hardening_status` calls Point and Print weakened when `RestrictDriverInstallationToAdministrators` is 0 or `NoWarningNoElevationOnInstall` is 1 or `UpdatePromptSettings` is 2; an absent restrict value is the default (restricted on updated Windows) and is not weakened. `print_queue_stuck` judges the snapshot: not paused, at least `threshold` jobs, and an error or offline job or a job older than 15 minutes, held for the policy's minutes. The client computer of a job comes from `Win32_PrintJob.HostPrintQueue` (to confirm on a real server).
* **File sharing.** `session_list` and `openfile_list` use `shares.view` as their opening permission (there is no `shares.view_sensitive`; a Technician has no `shares.view`). A new share is readable by the Administrators only until access is granted. Blocking Everyone, Authenticated Users, Users, Administrators or SYSTEM is refused (`would_lock_out`).
* Alerts: ADR section 9's counts become 4 CA kinds with 5 policies, 1 file kind with 1 policy (off) and 3 print kinds with 3 policies (two on); the CA defaults on are the three of section 9 plus the service-stopped one.

## References

* ADR-0073 to 0075, 0077; `docs/architecture/feature-plan-msp.md`.
* Microsoft: [Audit Certification Services](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services),
  [Audit File Share](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-file-share),
  [Enable DNS Logging and Diagnostics in Windows Server](https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-logging-and-diagnostics)
  (all read on 2026-11-26); MSRC CVE-2021-34527 and KB5005652 (the Point and
  Print and `RestrictDriverInstallationToAdministrators` guidance, read on
  2026-11-26). The module and cmdlet names (`ADCSAdministration`, `certutil`
  verbs, `DnsServer`, `DhcpServer`, `SmbShare`, `PrintManagement`,
  `FileServerResourceManager`) are from the writer's knowledge of the Microsoft
  documentation and were **not re-read on the day**; slice gates C1, D1, H1,
  F1 and P1 confirm each against the real server.
