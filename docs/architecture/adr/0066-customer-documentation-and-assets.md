# ADR-0066: Customer documentation and asset records

* Status: Accepted (2026-11-21, after an independent review). Not
  implemented.
* Requirements: feature 4, "Customer Documentation and Asset Records",
  of the owner's
  [requirements of 2026-11-21](../requirements/2026-11-21-msp-features.md#4-customer-documentation-and-asset-records).
  Every bullet is placed in [The requirements](#the-requirements).
  Feature 1, "Hardware Warranty and Lifecycle Management", is cited for
  the asset record it extends.
* Part of the [plan for the twelve MSP features](../feature-plan-msp.md#4-customer-documentation-and-asset-records):
  feature 4. Slice 1 is step 13 of the plan's [order](../feature-plan-msp.md#order);
  slice 2 is step 14, built with feature 1's slices 1 and 2. The plan
  decided that feature 4 owns one asset record and feature 1 extends it;
  this ADR defines that record and its
  [extension points](#extension-points-for-feature-1), and leaves
  warranty itself to feature 1's ADR.
* Where this differs from the plan, each argued where it is decided:
  * password manager references come in slice 1, not slice 6, so that
    the warning about secret-like text has somewhere to send people;
  * restricted pages come before network documentation;
  * credentials, if stored at all, are stored only in the plan's
    keystore, as a slice of their own after the keystore's reads (an
    owner question);
  * organization and site notes become pages;
  * the audit log records a revision's number and size, not its body's
    SHA-256, which stays beside the revision, as ADR-0064 decided for
    one-off commands: a hash confirms a guessed secret;
  * search uses a table of terms, not a full-text index, which row-level
    security would leave unused (measured, below).
* Builds on: [ADR-0002](0002-postgresql-rls-tenant-isolation.md)
  (row-level security), [ADR-0007](0007-hash-chained-audit-log.md) (the
  audit log), [ADR-0018](0018-inventory-and-telemetry.md) (the hashed
  inventory), [ADR-0029](0029-reports.md) (audited CSV),
  [ADR-0047](0047-tokens-shown-again.md) (a read and its audit record in
  one transaction), [ADR-0050](0050-removing-a-device.md) (removing a
  device), [ADR-0052](0052-the-host-updater.md) (the updater's backups),
  and these proposed ADRs: [ADR-0053](0053-one-notification-sender.md)
  (notices, the address policy, sites' maintenance windows),
  [ADR-0055](0055-lets-encrypt-in-one-step.md#step-up-authentication)
  (step-up authentication), [ADR-0060](0060-collecting-logs.md) (indexes
  under row-level security) and
  [ADR-0062](0062-the-audit-log-across-restores.md) (the audit log
  across restores). Two ADRs are on branches of their own and not
  merged, so they are cited without links: ADR-0063 (who sees a job's
  output and arguments), whose bound on recorded refusals and whose rule
  and test for `SECURITY DEFINER` functions' `search_path` this ADR
  reuses; and ADR-0065 (hardware health, proposed), whose states for
  facts EasyRMM reports this ADR's agent values carry. The plan's
  [keystore](../feature-plan-msp.md#the-keystore-for-bitlocker-and-luks-recovery-keys)
  has no ADR yet.
* Revised after an independent review the same day: downloads hold no
  transaction while they stream; restricted pages are hidden by
  row-level security, not by checks in each path; search terms name
  their subject by foreign key and leave out lines that look like
  secrets; assets that turn out to be the same hardware are merged on a
  person's answer; credentials, if stored, get a key pair of their own;
  storage is bounded for the whole deployment; audit records carry
  identifiers, not titles or names.
* Amends: nothing. Extended by feature 1's ADR.

## Context
Each claim about the code was checked at `main` `1c21f6e` for this ADR.
The surveys behind the plan were made at `6f9fe99`.

**What exists.**

* **Organizations** have a name, a time zone and plain-text `notes` of up
  to 10,000 characters (`server/migrations/00001_core.sql:48-51`; the
  time zone from `00020_one_set_of_organizations.sql:8`). **Sites** have a
  name, a time zone, one free-text `address` of up to 1,000 characters
  and `notes` (`00001_core.sql:59-65`), and `UNIQUE (organization_id,
  id)` so that child tables can carry the pair (`:70`). An organization
  may be the MSP itself (`server/internal/tenancy/tenancy.go:35`).
* **Notes have no history and Technicians cannot edit them.** Editing
  needs `org.manage` or `site.manage` (`tenancy.go:279,450`), and
  `organization.update` and `site.update` record the name and time zone,
  not the notes (`tenancy.go:296-305,465-470`). The console shows notes as
  plain text (`web/src/pages/organizations/OrganizationDetailPage.tsx:177`,
  `SiteDetailPage.tsx:204-205`) and filters the organization list by them
  in the browser (`OrganizationsPage.tsx:31`).
* **Devices** have a name, host name, platform, organization, site and an
  optional group (`server/migrations/00002_remote_access.sql:13-31`), and
  no notes, tags, custom fields or owner. Custom fields appear only in a
  comment on `device.edit` (`server/internal/rbac/rbac.go:30`). Devices
  have no `UNIQUE (organization_id, id)`. A device's group uses the
  composite foreign key with `ON DELETE SET NULL (device_group_id)`
  (`00002_remote_access.sql:30`). Moving and renaming devices are not
  built (`IMPLEMENTATION_STATUS.md:145`).
* **Removing a device deletes its rows**, which cascade
  ([ADR-0050](0050-removing-a-device.md)). A `BEFORE DELETE` trigger on
  `devices` already records what the patching engine must undo, "whoever
  deletes" (`00020_one_set_of_organizations.sql:34-38,135-146`).
* **The agent reports** manufacturer, model and serial, BIOS and
  virtualization (`internal/agentproto/inventory.go:62-73`), the OS
  (`:83-90`), interfaces with CIDR addresses and MACs, gateways and DNS
  servers (`:31-34,103-110`). Firmware placeholders such as "To be filled
  by O.E.M." are dropped (`agent/inventory/collector.go:34-38`). The
  server keeps the latest upload as JSON, replaced on each change, in one
  transaction at the system scope
  (`server/internal/inventory/service.go:65-87`).
  There is no inventory history (`IMPLEMENTATION_STATUS.md:150`).
* **The patching engine's own organizations and sites** carry a contact
  name and email, notes and an address
  (`easypatch/backend/Core/Entities/Tenancy.cs:8-10,28`). EasyRMM sends
  them back unchanged and shows them nowhere
  (`server/internal/easypatch/manage.go:16-18`). This ADR leaves them so.
* **Roles** are five, fixed in code, granted at platform, organization or
  site scope; Read-Only holds the view permissions only
  (`rbac.go:122-125,142-181`). Organization-level objects can be made
  readable to site-scoped users through `easyrmm.scope_read_orgs`, as the
  script library is (`00004_scripts_jobs.sql:40-46`).
* **Row-level security** on every tenant table follows `sites_tenant`
  (`00001_core.sql:357-367`): the platform scope, the organization in
  `scope_orgs`, or the site in `scope_sites`.
* **The audit log** is written in the change's transaction; its details
  are capped at 16 KiB (`server/internal/audit/audit.go:69-73,112-114`).
  Every append takes one advisory lock for the rest of its transaction
  (`pg_advisory_xact_lock` in `easyrmm_audit_append`,
  `00001_core.sql:262`), so every writer in the deployment waits while a
  transaction that has appended stays open. One record per action, not
  per click.
* **Every query runs in a transaction** that first sets the caller's
  scope (`applyScope`, `server/internal/database/database.go:127-150`),
  from a pool of 20 connections by default (`config.go:223`), with a
  statement timeout of 30 seconds and an idle-in-transaction timeout of
  60 seconds (`database.go:74-75`).
* **Sealing**: `secrets.Sealer`, AES-256-GCM under `EASYRMM_SECRET_KEY`
  with a key ring, each value bound to its row by associated data
  (`server/internal/secrets/seal.go:84-117`;
  `server/internal/config/config.go:272-283`). A sealed token is shown
  again only in the transaction that writes its audit record
  (`server/internal/agents/tokens.go:178-213`, ADR-0047).
* **The backup guide writes `.env`, which holds that key, into the same
  folder as the database dumps**, and says the two together "give full
  control of every managed device"
  ([backup guide](../../operations/backup-restore.md#back-up), lines
  35-37 and 49-56). The updater's backup holds both: before each upgrade
  it checks for room for a copy of the data root, copies the whole data
  root (PostgreSQL's files with it) and the deployment directory, and
  keeps the last two copies
  ([ADR-0052](0052-the-host-updater.md), lines 205-206 and 212-215).
* **Uploads**: only signed agent builds, read as a raw body under
  `http.MaxBytesReader` up to 64 MiB and kept as `bytea` "so that backups
  keep them" (`server/internal/httpapi/agentupdatesapi/agentupdatesapi.go:56`;
  `server/internal/agents/signed_builds.go:35`;
  `00026_signed_agent_builds.sql:4-5,19`). JSON bodies are capped at 1 MiB
  (`server/internal/httpapi/respond.go:21`).
* **The console's headers**: `script-src 'self'`, `img-src 'self' data:`,
  `frame-ancestors 'none'`, `nosniff`
  (`server/internal/httpapi/middleware.go:167-189`). The console has five
  runtime dependencies and no Markdown library (`web/package.json:21-27`),
  and no `dangerouslySetInnerHTML` in `web/src`.
* **The request log** has the method, path and status, never query
  strings or bodies (`server/internal/httpapi/middleware.go:96-114`).
* **CSV**: reports neutralize cells a spreadsheet would read as formulas
  (`server/internal/reports/csv.go:14-17`), and each export is audited
  once per organization (`reports.go:257`; `docs/security/rbac.md:59-63`).
* **Dependencies' licences**: CI accepts MIT, ISC, Apache-2.0, BSD-2 and
  BSD-3, 0BSD and MPL-2.0 for the console's npm packages
  (`scripts/ci/check-npm-licences.mjs:15`, ADR-0037).
  `THIRD_PARTY_NOTICES.md` lists the Go modules one by one and says the
  console's packages are in the inventory CI generates (lines 26-39).
* **Discovered devices**: MeshCentral nodes that no EasyRMM agent claims
  are recorded as devices of their own
  (`server/internal/remote/service.go:46-47`), with no inventory.
* **`PRIVACY.md`** lists what the software collects (lines 27-37) and
  says the console keeps one setting in the browser's storage, the theme
  (lines 39-43).

**Measured for this ADR** on PostgreSQL 18.6, the deployment's image
(`deploy/docker-compose.yml:92`), in a throwaway container, with a
non-superuser role under policies shaped like `sites_tenant`:

* **Which operators may run before a policy.** `@@` on `tsvector`
  (`ts_match_vq`), `LIKE` and `ILIKE` (`textlike`, `texticlike`) are not
  leakproof; `=`, `<`, `<=`, `>`, `>=` on `text`, `uuid` and `bigint` are.
  PostgreSQL runs a policy's condition before any condition of the query
  that is not leakproof, and only a superuser can mark a function
  leakproof
  ([row security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html),
  [CREATE FUNCTION](https://www.postgresql.org/docs/current/sql-createfunction.html)).
  The server's roles are not superusers.
* **A full-text index goes unused.** With 200,000 pages and a GIN index
  on a stored `tsvector`, a superuser's query used the index; the
  application role's did not, at one organization's scope or the
  platform's. A query that named the organization used the btree on
  `organization_id` and filtered; the platform scope read the whole
  table. On 100,000 pages of about 4 KB each (905 MB), the platform-wide
  search took 14 and 46 seconds in two runs, and one organization's 200
  pages 0.8 and 2.9 seconds. The host was shared and loaded (a load
  average of 15 to 21 on 16 processors), and the text was random tokens,
  the worst case for a `tsvector`, so the times are indicative only; the
  plans are not.
* **A table of terms is used.** A table of each page's lexemes (1.4
  million rows), with a btree on `(term, organization_id)` under the
  `C` collation, answered a prefix search as a range on `term`, through
  the index, at both scopes, in 2 to 10 milliseconds on the same host.
  This is ADR-0060's finding (equality and ranges are leakproof, so its
  facts table has btree indexes and no GIN) applied to text.
* **Links cannot cross organizations.** A composite foreign key
  `(organization_id, device_id)` refused an asset in one organization
  pointing at a device of another, although the role's scope could see
  both. `ON DELETE SET NULL (device_id)` cleared the link when the
  application role deleted the device.
* **Append-only revisions.** With `INSERT` and `SELECT` only, the
  application role could neither update nor delete a revision, and
  deleting the page still removed its revisions through the foreign
  key's cascade. Referential checks bypass row security, as PostgreSQL
  documents ([row security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)).

Measured again after the review, on the same image:

* **A device's move carries its asset.** With the foreign key
  `(organization_id, site_id, device_id) → devices (organization_id,
  site_id, id) ON UPDATE CASCADE`, moving a linked device to another site
  as the application role moved the asset; a `BEFORE UPDATE OF site_id`
  trigger on the asset cleared its place, which belonged to the old
  site. Without the trigger, the same move failed on
  `assets_site_id_place_id_fkey`, the place not being in the new site.
* **Restricted rows hidden by the policy.** With a condition on
  `doc_pages` that lets a restricted page through only for organizations
  or sites listed in a scope setting, the application role saw neither
  a restricted page nor its revisions (read directly, through a policy
  that reads through the page) without the setting, and both with it.
* **Excerpts with control characters.** `ts_headline` with
  `StartSel=E'\x02'`, `StopSel=E'\x03'` and `MaxFragments=2` marked the
  matched words with those two characters and nothing else, and dropped
  `<script>` from the excerpt; with its default markers it returned
  `<img src=x onerror=alert(1)>` from the text unchanged.
* **A 25 MiB attachment** written as 25 rows of 1 MiB in one
  transaction took 1.5 seconds, generating the data included.
* **The terms table at three scopes.** 500 organizations with 4 sites
  each, 100,000 pages (one in ten restricted), 6.0 million terms (1.5
  GB with its indexes), one nullable foreign key per kind of subject and
  btrees on `(organization_id, term)` and `(term, organization_id)`;
  policies with the tenant and restricted conditions; `EXPLAIN
  (ANALYZE)` as the application role:

  | Scope | Query | Plan | Rows read, kept | Time |
  |---|---|---|---|---|
  | One organization | 3-character prefix, `organization_id = ANY ($orgs)` | Index scan on `(organization_id, term)`, both conditions in the index | 5, 5 | 0.3 ms |
  | One organization | 6-character prefix, the same | Index scan on `(term, organization_id)`, both in the index | 1, 1 | 0.2 ms |
  | One site | 3-character prefix, the organization and `site_id = ANY ($sites)` | Index scan on `(organization_id, term)`; the site and the policy as a filter | 5, 0 | 0.1 ms |
  | The platform | 6-character prefix, no organization | Index scan on `(term, organization_id)` | 125, 125 (50 returned) | 2.4 ms |
  | One organization | 3-character prefix, **without** the explicit organization | Bitmap scan on `(term, organization_id)`; the policy's organization only a filter | 1,817, 5 | 24 ms |

  The policy's conditions call `easyrmm_scope_ids`, so the planner keeps
  them as a filter and does not take the organization from them; only a
  condition the query states itself reaches the index. The terms were
  random, so each prefix matched few rows in any one organization; a
  common prefix in real text matches more, which the explicit
  organization keeps to that organization's rows. Times are indicative
  (a shared host, load average 4 to 8 on 16 processors); the plans are
  not.

**External facts used below.**

* `react-markdown` (MIT; current line 10, 10.1.0 on npm) is "secure by
  default", builds React elements without `dangerouslySetInnerHTML`,
  escapes HTML in the Markdown unless `rehype-raw` is added, and its
  default `urlTransform` allows `http`, `https`, `irc`, `ircs`, `mailto`
  and `xmpp` and relative URLs; it warns that plugins and components may
  be insecure ([README](https://github.com/remarkjs/react-markdown)).
  Resolved on 2026-11-21 with `remark-gfm` 4.0.1 (MIT) and React 19.3.1
  into a lock file (no install scripts run): 102 packages besides React,
  101 MIT and 1 ISC, all on CI's list.
* `markdown-it` 15.0.3 (MIT) refuses `javascript:`, `vbscript:`, `file:`
  and `data:` links except four image types (`BAD_PROTO_RE` and
  `GOOD_DATA_RE` in its `dist/markdown-it.mjs`), renders to an HTML
  string, and depends on `argparse`, whose licence is PSF-2.0, not on
  CI's list (read from the package on the npm registry).
* Without `'unsafe-inline'`, a policy with `script-src` blocks inline
  scripts, inline event handlers and `javascript:` URLs; the CSP
  `sandbox` directive sandboxes the response like an iframe's `sandbox`
  attribute ([MDN, Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy)).
* Go's `http.DetectContentType` implements the WHATWG MIME Sniffing
  algorithm on at most the first 512 bytes and returns
  `application/octet-stream` when unsure
  ([pkg.go.dev](https://pkg.go.dev/net/http#DetectContentType)). Run for
  this ADR on Go 1.27.3: a Markdown file that begins with `<!--` is
  sniffed as `text/html`, the same text with the comment on its second
  line as `text/plain`; an SVG file as `text/plain`; an XML declaration
  as `text/xml`; `%PDF-` as `application/pdf`; a ZIP header (which every
  Office file has) as `application/zip`; PNG, JPEG, GIF and WebP
  headers as `image/png`, `image/jpeg`, `image/gif` and `image/webp`.
* Go's `mime.FormatMediaType` writes a media type with its parameters
  and returns an empty string when an argument would break the standard
  ([pkg.go.dev](https://pkg.go.dev/mime#FormatMediaType)). Run for this
  ADR on Go 1.27.3 with `attachment` and a `filename`: an ASCII name is
  written as `filename=` (quoted when it holds `"` or `;`); a name with
  other characters, or with a carriage return and line feed, as
  `filename*=utf-8''` and the percent-encoded bytes. It keeps path
  segments (`../../etc/passwd` came back as given), so names are cleaned
  first.
* PostgreSQL's `ts_headline` "is not guaranteed to be safe for direct
  inclusion in web pages", removes only some simple tags, and "uses the
  original document, not a `tsvector` summary, so it can be slow and
  should be used with care"; `StartSel` and `StopSel` set the strings
  around matched words, `MaxFragments` above zero selects fragments, and
  `MaxWords` and `MinWords` bound each one
  ([text search controls](https://www.postgresql.org/docs/current/textsearch-controls.html#TEXTSEARCH-HEADLINE)).
* SMBIOS identifiers are not always unique: "While the SMBIOS attribute
  should be unique, some specialty hardware devices have duplicate
  identifiers" (Microsoft's Configuration Manager documentation,
  [Manage duplicate hardware identifiers](https://learn.microsoft.com/en-us/intune/configmgr/core/clients/manage/manage-clients#manage-duplicate-hardware-identifiers)).
  That a cloned virtual machine can keep its source's SMBIOS UUID is
  **to be confirmed** for each hypervisor; this ADR does not depend on
  it.
* OWASP: allow-list extensions, never trust the client's `Content-Type`,
  check signatures but not alone, name stored files on the server, cap
  sizes ([File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)).
* RFC 6266: `filename*` (RFC 5987 encoding) carries names outside
  ISO-8859-1, recipients prefer it over `filename`, and treat the name as
  advisory, stripping path segments
  ([RFC 6266 §4.3](https://www.rfc-editor.org/rfc/rfc6266#section-4.3)).
* Writing to the clipboard needs a secure context; Firefox and Safari
  require transient user activation, and Chromium either that or the
  `clipboard-write` permission
  ([MDN, Clipboard API](https://developer.mozilla.org/en-US/docs/Web/API/Clipboard_API#security_considerations)).
* A PostgreSQL field holds at most 1 GB
  ([Appendix K](https://www.postgresql.org/docs/current/limits.html)).

## Decision

### In short
* **Two levels**: an organization and its sites. No pages shared across
  organizations; the MSP's own knowledge base is the MSP's own
  organization. **Site-scoped people read their sites' documentation
  only**, not the organization's.
* **The customer record** (slice 1): the organization's main phone, email
  and website; contacts with primary, secondary and emergency; each
  site's address as fields; places within a site (building, floor, room,
  rack); business hours per site, else per organization, in its time
  zone.
* **Pages** (slice 1): Markdown or plain text, rendered in the console to
  React elements with raw HTML shown as text and links checked; every
  save a revision with its author, a person's saves within 10 minutes
  coalesced; a trash; redaction of one revision, or of a person's or a
  customer's history at once, by an administrator; an export per
  organization; search through a table of terms. Organization and site
  notes become pages.
* **Secrets in text** are warned about, never refused, and pointed at a
  password manager reference (slice 1), which holds where the secret is,
  never the secret.
* **The asset record** (slice 2, step 14): one record per piece of
  equipment or service, with or without an agent, made for every device
  that reports an inventory. Each identifying field keeps a value per
  source (the agent, entered by hand; feature 1 adds its own sources),
  and neither overwrites the other. A device links to at most one asset;
  a match by serial, and two records of the same hardware, are proposed
  to a person, never linked or merged silently. Assets outlive devices.
* **Credentials are not stored under `EASYRMM_SECRET_KEY`**, which sits
  beside every backup's dumps. If the owner wants them stored, they go
  into the keystore (slice 7) under a key pair of their own, revealed
  under a permission of their own with step-up and one audit record per
  reveal, copied without display, and never in lists, search, exports or
  the audit log.
* **Attachments** (slice 3) are kept in PostgreSQL and served only as
  downloads; a download writes its audit record first and then streams
  without holding a transaction.
* **New permissions**: `doc.view` (all roles), `doc.manage` (Technician
  and above), `doc.view_restricted` (Site Administrator and above),
  `doc.credential_reveal` (Technician and above, with step-up).
* **Everything is in PostgreSQL**, attachments too, under row-level
  security with composite foreign keys, so backups and restores need no
  new step. Restricted pages are hidden by the policies themselves.
  Storage is bounded per organization and for the deployment.

### Where documentation lives
*Decided in review.*

* **An organization, or one of its sites.** Every table carries
  `organization_id NOT NULL` and, where a row can belong to a site, a
  nullable `site_id` with the composite foreign key to `sites
  (organization_id, id)`, as `devices` has. A row with no site belongs to
  the organization.
* **No shared pages.** A page shared by every organization would be read
  by every organization's people, customers' own staff included. The
  MSP's internal knowledge base (procedures, vendor notes) is kept as
  pages in the MSP's own organization, which customers' staff are never
  assigned to. The only shared rows are custom field definitions (slice
  6), which hold no customer data.
* **Site-scoped people read their sites' documentation, not the
  organization's.** The policies are `sites_tenant`'s, without
  `scope_read_orgs`: unlike the script library, organization-level pages
  can hold the MSP's own notes about the customer, and site-scoped
  accounts are often the customer's own staff. An MSP technician who
  needs the whole customer is given the role at the organization. What
  site-scoped people still see of the organization is its row, as today
  (`organizations_read`, `00001_core.sql:344-348`), which gains the main
  phone, email, website and default business hours.
* **Pages move between the organization and its sites**, with
  `doc.manage` at both, audited; never between organizations.

### The customer record
Slice 1, first pull request. *Decided in review.*

* **The organization**: `main_phone`, `main_email` and `website` (an
  `https` or `http` URL), as columns of `organizations`.
* **Contacts** (`contacts`): at the organization or a site; a name
  (required), a job title, an email, an office phone, a mobile phone, a
  note of up to 2,000 characters; `priority` of `primary`, `secondary` or
  none, and `emergency` (a flag, since an emergency contact can also be
  primary). At most one primary per organization and one per site, by a
  partial unique index. Contacts are customers' staff, not EasyRMM
  accounts, and are personal data: `PRIVACY.md` changes with this slice,
  in the owner's words (plan's owner question 11).
* **Addresses**: each site gains `address_line1`, `address_line2`,
  `city`, `region`, `postal_code` and `country_code` (ISO 3166-1
  alpha-2). Today's free-text `address` stays beside them for addresses
  that fit no fields; nothing is parsed from it. The console shows the
  fields when any is set, else the free text.
* **Places within a site** (`site_places`): a building, floor, room, rack
  or other, each with a name and an optional parent in the same site
  (composite key on `(site_id, parent_id)`), at most four deep. Slice 2's
  asset record uses them for its physical location. The requirement's
  "customer locations" are the sites; places are where inside them.
* **Business hours**: a weekly schedule as a column of `sites` and of
  `organizations` (JSON validated by the server: up to four intervals a
  day, each a start and an end in local time, across midnight allowed
  and belonging to the day it starts, as ADR-0053's maintenance windows
  are), plus a note for after-hours instructions. A site without its own
  uses its organization's. Times are in the site's time zone, else the
  organization's, both validated IANA names
  (`tenancy.go:166-172`). Daylight saving follows ADR-0053
  (lines 824-826): a time in a
  skipped hour begins when the gap ends, one in a repeated hour at its
  first occurrence. The site's page shows *Open* or *Closed now*. Closures
  on given dates (public holidays) are not in this slice.
* **Who edits**: `doc.manage` at the organization (its fields, its
  contacts) or the site (the site's address, hours, places and contacts).
  A site's name and time zone stay `site.manage`, an organization's
  `org.manage`.

### Pages
Slice 1, second pull request. *Decided in review.*

**Format.**

* **Markdown (CommonMark with GitHub's tables, task lists, strikethrough
  and autolinks) or plain text**, chosen per page. The editor is a text
  area with a toolbar that inserts Markdown and a preview. This is how
  the requirement's "rich-text documentation" is met. A WYSIWYG editor is
  not chosen (*Not chosen*).
* **The server stores the source and never renders it.** The API returns
  Markdown as text; a client that renders it must do what the console
  does. The documentation export (below) carries the source as written.
* **Control characters are removed on save**: every C0 control but tab
  and line feed, with carriage returns turned into line feeds, in
  titles, bodies, notes and every other text this ADR stores. The search
  excerpts rely on it (*Search*).
* **The console renders with `react-markdown` and `remark-gfm`**, pinned,
  with these settings, each covered by tests:
  * no `rehype-raw` and no plugin that passes HTML through: HTML in a
    page is shown as text;
  * a `urlTransform` of EasyRMM's own, allowing only:
    * `https:`, `http:` and `mailto:` URLs, which open in a new tab with
      `rel="noopener noreferrer"`;
    * the console's own paths (other pages, devices, assets), judged by
      `new URL(href, location.origin)`: the result's `origin` must equal
      the console's, the text must begin with `/` followed by neither `/`
      nor `\` (so `//host` and `/\host`, which a URL parser reads as
      another host, are refused before parsing), and the path must not
      begin with `/api`, so that a
      link cannot make the reader's browser call the API.

    Anything else becomes plain text;
  * images: none in slice 1 (`disallowedElements`); from slice 3, only
    the page's own image attachments, by an `attachment:` reference the
    transform maps to the preview endpoint. The content security policy
    already refuses images from anywhere but the console (`img-src 'self'
    data:`), so a page cannot carry a tracking image;
  * no custom component that writes HTML.

  The console's `script-src 'self'` stays as it is, so an inline handler
  or a `javascript:` URL that got through would still not run (MDN,
  above). The 102 packages are a cost, weighed under *Not chosen*. Slice
  1 adds `react-markdown` and `remark-gfm` to `THIRD_PARTY_NOTICES.md`
  in a section for the console's packages, each with its licence, and
  points to CI's inventory for the packages they bring.
* **Size**: a body of at most 256 KiB in UTF-8, a title of at most 200
  characters, an optional section name of at most 100 that groups pages
  on the organization's and site's lists, and a *pinned* flag.

**Revisions.**

* **Every save is a revision**, in `doc_page_revisions`: an ID (a UUID),
  the page, its number, the title, format and body as saved, the body's
  size and SHA-256, the author's ID and name as they were then, the time
  and an optional note of up to 500 characters. The SHA-256 is shown with
  the revision, to whoever can read its text, and nowhere else: not in
  the audit log, which is forwarded and outlives pages, since a hash of a
  page that holds a short secret confirms a guess at it offline
  (ADR-0064's reason for one-off commands). The runtime role holds
  `INSERT` and `SELECT` only; revisions leave with their page, through
  the foreign key's cascade (measured above). The page row keeps the
  current title, body, revision and a `version` counter, so lists and
  reads do not touch revisions.
* **A save names the version it was made from** (`baseVersion`), which
  goes up by one with every save, coalesced or not. If the page has moved
  on, the save is refused (`409 page_changed`) with the newer revision's
  author and time, and the console shows both texts for the person to
  merge. Nothing is merged automatically.
* **A person's saves within 10 minutes are coalesced.** The editor saves
  only when asked; there is no autosave. A save by the author of the
  current revision, less than 10 minutes after that revision was first
  written and with no one else's save between, replaces that revision's
  title, body, size, hash and note instead of adding one; the revision
  keeps its ID, number and first time and records the last. A
  `SECURITY DEFINER` function does it, since the runtime role cannot
  update revisions: `easyrmm_doc_revision_coalesce`, owned by
  `easyrmm_owner` with `search_path = pg_catalog, public, pg_temp` as
  ADR-0063 requires of every such function (and its test enforces). The
  function itself refuses anything but the current revision of a page
  the caller's scope can see, by its own author, within the window. The
  audit log still has one record per save, marked `coalesced`. A
  colleague's save, a restore or a redaction ends the window. Ten
  minutes is chosen to cover fixing what was just saved; a longer window
  would hide edits from the history.
* **History**: the console lists revisions, shows any one, and shows a
  line diff between two, computed in the browser. *Restore this
  revision* saves its text as a new revision; history is never rewritten
  except by coalescing and redaction, both above.
* **Unsaved edits stay in the page only.** The console warns before
  leaving a page with changes and keeps no drafts in the browser's
  storage, which `PRIVACY.md` limits to the theme.
* **Saves are rate-limited** to 60 a minute per person, by the limiter
  per key the server already has (`server/internal/auth/ratelimit.go:13-35`).
* **Revisions count against the organization's storage quota**
  (*Storage*).

**The trash, and redaction.**

* **Deleting a page moves it to the trash** for 30 days, restorable by
  `doc.manage` holders at its level; then a sweeper at the system scope
  deletes it with its revisions, recorded once per organization with the
  count. An Organization Administrator can empty the organization's
  trash sooner, to free its quota.
* **Redacting a revision** empties its title and body, clears its
  SHA-256 and marks it redacted, keeping its ID, number, author, time and
  size: for a secret pasted into a page, which would otherwise stay in
  its history. `easyrmm_doc_revision_redact` does it, a `SECURITY
  DEFINER` function made as the coalescing one is (owner,
  `search_path = pg_catalog, public, pg_temp`). The function refuses the
  page's current revision itself, so no path through the service can
  redact it; the person saves a corrected revision first. Only
  `org.manage` holders at the page's organization (Organization
  Administrators and Super Administrators) may, with a reason, audited.
* **Redacting at once, for a person or a customer.** For a request to
  erase what is kept about someone, an Organization Administrator
  chooses pages (search for the person's name finds them) and redacts
  every revision of each but its current one, in one transaction, after
  editing the current ones; the person's contact is deleted the usual
  way. For a customer whose history must go but whose pages stay, the
  same is offered for every page of the organization. One audit record
  per action, with the counts and the pages' IDs. Both say plainly that
  backups made before keep the text until they expire; the guide says so
  too.

**The documentation export.** For handing a customer's documentation
over, at the end of a contract or for a request for a copy, an
Organization Administrator (`org.manage`) exports the organization: a
ZIP with each page's current text as a Markdown or text file in a folder
per site, a JSON manifest (pages with their IDs, sections, links and
revision counts; contacts; addresses, places and hours; references;
from slice 2 assets with each field's values by source; from slice 3
attachments as files; from slice 5 the network records), and nothing
from credentials beyond their names. Restricted pages are included only
for a caller who may read them, by the policies themselves (*Restricted
pages*). Revisions are left out: a customer's copy is what is current,
and the history stays the MSP's record. The export is recorded before it
starts (`doc.export`, the organization and the counts) and streams as
attachments do: no transaction is held while it is sent; at most one
export per organization and two per server process at once.

**Notes become pages.** Slice 1's migration copies each organization's
and site's non-empty `notes` into a plain-text page titled *Notes* at the
same level, as revision 1, authored by the system (`migration`), records
one `doc_page.create` per organization with the count (migrations append
to the audit log, ADR-0062), and drops the two `notes` columns. The
organization list shows the primary contact where it showed notes; its
filter becomes search. The API's `notes` fields go, and the upgrade
notes say so. The updater's rollback restores the data root, columns
included (ADR-0052). Requirement 4 asks for revision history and for
Technicians to edit; notes had neither, and a second place for free text
beside pages would be two of the same thing.

### Search
Slice 1. *Decided in review*, on the measurements in *Context*.

**The table of terms.**

* **`doc_search_terms`**: the organization, the site, a `restricted`
  flag, one term per row (`text COLLATE "C"`), and **one nullable
  foreign key per kind of subject**: `page_id`, `contact_id`,
  `subject_site_id` for a site's own fields, `place_id`, `reference_id`;
  later `asset_id`, `subnet_id`, `vlan_id`, `attachment_id`,
  `custom_field_value_id` and `credential_id`, each added by the slice
  that adds its table. Each is `ON DELETE CASCADE` with a partial index,
  so a subject's terms go with it whoever deletes it, and `CHECK
  (num_nonnulls(…) = 1)` makes every row name exactly one subject.
* **Two btrees**: `(organization_id, term)` for searches that name
  organizations, which is every search but a Super Administrator's
  across the platform, and `(term, organization_id)` for that one; the
  planner also chose the second for a long prefix in one organization,
  both conditions in the index either way (measured).
* **Terms are PostgreSQL's own**: `tsvector_to_array(to_tsvector('simple',
  …))` of the subject's searchable text, in the same transaction as the
  save that changed it. `simple` lower-cases and splits without stemming,
  so it serves every language that separates words with spaces. At most
  10,000 distinct terms per subject; terms over 64 bytes are skipped.
* **What is never a term**: any line the secret-like warning matches,
  acknowledged or not (*Secrets in text*); a credential's username or
  secret; a reference's item; attachments' contents. A credential is
  found by its name, an attachment by its file name.

**A query.**

* At most 200 characters and 8 words; **each word at least 3
  characters**, since a shorter prefix matches a large share of the
  terms and says little. Each word is a prefix: a range from the word to
  the word followed by the highest code point.
* **It names the caller's organizations itself**:
  `organization_id = ANY ($orgs)`, with `uuid_eq`, which is leakproof, so
  the planner can use it in the index before the policy runs; for a
  caller whose roles are at sites only, `site_id = ANY ($sites)` too. The
  lists come from the caller's roles, as the scope settings do, narrowed
  by the organization or site the person chose. The policy still decides,
  restricted pages included; the explicit condition only lets the index
  be used. Only a caller at the platform scope searches without naming
  organizations.
* Subjects that have every word are found with `GROUP BY` and `HAVING`
  over the words' ranges, then read back under row-level security and
  the permission checks, titles matched first, then the most recently
  changed; at most 50 a page.
* **Restricted pages** are left out by the policy for callers without
  `doc.view_restricted` there (*Restricted pages*), and their results are
  read back through the pages' policy as well.
* **Not logged**: the query travels in the query string, which the
  request log leaves out.

**Excerpts.**

* For pages the caller can read, a short excerpt from `ts_headline`,
  given only the first 16 KiB of the body (`left(body, 16384)`), with
  `MaxFragments=2`, `MaxWords=20`, `MinWords=5`, since it reads the text
  itself and "can be slow".
* **Its markers are control characters**: `StartSel` U+0002 and `StopSel`
  U+0003, which no stored text can contain, since saves remove control
  characters (*Pages*). PostgreSQL warns that the output is not safe in a
  web page, and its default markers would be indistinguishable from markup
  in the text (*Context*). The API returns the excerpt as text; the
  console splits it at the two characters and renders the pieces as
  React text nodes, the matched ones inside `<mark>`. Nothing in an
  excerpt is ever parsed as HTML or Markdown.
* The cross-site scripting corpus of the page tests runs through excerpts
  too (*Testing*).

**Measured** (*Context*): with the explicit organization, an
organization's and a site's searches used `(organization_id, term)` and
read only that organization's matching rows; without it, the policy's
own condition stayed a filter and the same search read every
organization's matching rows first, about 360 times as many here.

* Slice 1's tests run `EXPLAIN` as the application role at an
  organization's scope, a site's and the platform's, and fail on a
  sequential scan of the terms table or on an organization's search
  whose index condition lacks `organization_id`, as ADR-0060's tests
  check their plans.

### Secrets in text
Slice 1, third pull request. *Decided in review.*

* **A warning, never a refusal**, as the warning on scripts that install
  updates is (`IMPLEMENTATION_STATUS.md:123`). On saving a page, a
  contact's note, a place, a reference's notes or (slice 2) an asset's
  notes, the server looks for text that looks like a secret:
  * a word such as `password`, `passwd`, `pwd`, `passcode`, `PIN`,
    `secret`, `API key` or `token` followed by `:` or `=` and a value on
    the same line;
  * a PEM or OpenSSH private key block;
  * EasyRMM's own `ert_` tokens (`internal/agentproto/agentproto.go:51`);
  * further token shapes kept in a list in code, each with its source and
    tests.

  The save answers `409 secret_like_text` with the line numbers, never
  the text, unless it says it was acknowledged. The console shows the
  lines, offers *Add a password manager reference instead*, and *Save
  anyway*. The audit record says a warning was acknowledged and how many
  lines, nothing more.
* **Only lines new or changed since `baseVersion` warn**, found by a
  line diff against the current text on the server, so a line someone
  acknowledged is not raised again at every save. A new page's lines are
  all new.
* **Lines that look like secrets are never indexed.** Whether or not
  the warning was acknowledged, no term is taken from a line that
  matches, so search cannot be used to find secrets or to confirm a
  guess at one (*Search*).
* **Password manager references** (`credential_references`): at the
  organization or a site, a name, the manager (from a list: 1Password,
  Bitwarden, Dashlane, Devolutions, Keeper, KeePass, LastPass, Passbolt,
  or other with a name), the vault or collection, the item's name and ID,
  an `https` link that opens it in the manager, and notes; linked to
  assets in slice 2. They hold where a secret is, never the secret, and
  are read with `doc.view` and edited with `doc.manage`. The requirement
  asks for "references or integrations"; integrations that call a
  manager from the server are later and need an ADR of their own, under
  ADR-0053's [address policy](0053-one-notification-sender.md#the-address-policy),
  and a credential for the manager, stored as credentials are.
* **Differs from the plan**, which put references in slice 6: without
  them the warning has nowhere to point, and they hold no secret.

### The asset record
Slice 2, step 14, built with feature 1's slices 1 and 2 and F1's SMBIOS
identifiers. *Decided in review.*

**What an asset is.** One piece of equipment or one service the
organization has: a computer with or without an EasyRMM agent, a switch,
a firewall, a printer, a UPS, a licence, an internet connection. A
**device** is an agent's identity; an asset is the thing. A reinstall
makes a new device for the same asset; a replaced laptop is a new asset
that replaces the old.

**Kinds**, fixed in code and extended by migration: workstation, laptop,
server, virtual machine, virtualization host, firewall, router, switch,
wireless access point, other network device, printer, UPS, storage
system, phone or mobile device, internet connection, licence, other. The
kind chooses the fields shown and, from slice 6, the custom fields.

**Status**: ordered, in stock, in use, in repair, retired, disposed,
lost. Assets made for devices start *in use*.

**The table** (`assets`): ID; `organization_id`; `site_id` (null for
organization-wide assets such as licences); `place_id` (a place of that
site, `ON DELETE SET NULL (place_id)`); `kind`; `status`; `device_id`;
`assigned_contact_id` (a contact of the organization, `ON DELETE SET NULL
(assigned_contact_id)`), the requirement's "assigned user", since the
agent reports no user; `replaces_asset_id` (an asset of the same
organization); notes of up to 4,000 characters of plain text (anything
longer is a linked page); who made it and when. It also carries, as
columns, the **effective value** of each built-in field (below) and two
match keys, `serial_key` and `maker_key`, all derived by the service in
the same transaction as the values they come from and written nowhere
else, so that lists sort and filter on indexed columns. The keys are
made by one Go function (below), used by every path that writes them,
the backfill included; no SQL makes them.

**Fields and their sources.**

* **One value per field and source**, in `asset_field_values`: the
  asset, the organization, the field, the source, the value as text in
  the field's form (dates as `YYYY-MM-DD`), its state, when the source
  said it (`observed_at`), and when and by whom it was recorded. Primary
  key `(asset_id, field, source)`. A column for what a source wants to
  keep beside its value is feature 1's to add with the first source that
  needs it, not added empty here.
* **The agent's values carry ADR-0065's states** for facts EasyRMM
  reports and does not judge: *reported* with a value, or *unknown*
  (could not be read this time), *unsupported* (this hardware has no
  such fact: a virtual machine's chassis asset tag) or *unavailable*
  (the fact exists but the agent cannot reach it), each with a reason.
  A field that is not *reported* is never shown as empty, never decides
  the effective value, and never makes a person's value *differ*. Until
  F1's collector at step 14 says which of the three applies, an empty
  agent value is *unknown*, as the agent's own rule leaves what it cannot
  read empty (`agent/inventory/collector.go:6-7`). A `manual` value is
  always *reported*.
* **Sources now**: `agent` (copied from the linked device) and `manual`
  (entered by hand). Feature 1 adds its own (*Extension points*). The
  `CHECK` on `source` lists them and each feature's migration extends it.
* **A catalogue of fields in code** gives each field its form, the kinds
  it applies to, the sources it accepts and the order in which sources
  decide the effective value. Slice 2's fields:

  | Field | Sources | Effective value |
  |---|---|---|
  | Name | manual, agent (the device's name) | manual first |
  | Manufacturer, model, serial | agent, manual | agent first |
  | Host name, operating system | agent only | agent |
  | Asset tag | manual, agent (F1's SMBIOS chassis asset tag) | manual first |
  | SKU, family and version, SMBIOS UUID, chassis type | agent only (F1, at step 14) | agent |

* **The agent's values and people's never overwrite each other.** A
  person editing the serial of an asset whose agent reported one writes
  the `manual` value; the agent's stays and stays effective, and the
  console shows both: "Reported by the agent: X. Entered: Y (differs)."
  An inventory upload rewrites the `agent` values only. Where the
  catalogue puts `manual` first (the name, the asset tag), a person's
  value wins and the agent's is shown beside it. Removing a manual value
  leaves the agent's.
* **When the agent's values are copied**, in the transactions that
  change them, and only when they changed:
  * the inventory's (manufacturer, model, serial, operating system and
    F1's identifiers) in `Record`'s transaction
    (`server/internal/inventory/service.go:83`). It runs at the system
    scope, so its statements name the device's organization explicitly.
    Uploads happen only when the inventory's hash changes (ADR-0018), so
    this adds a few statements to an upload that already rewrites the
    device's inventory and software;
  * the name and host name in the heartbeat's update of the device's row
    (`server/internal/agents/heartbeat.go:32-38`), which runs every
    minute: one comparison, and a write only on a change.

  The 2,000-agent drill (`docs/development/drills.md`) measures both
  against the release before.

**Devices and assets.**

* **At most one asset per device, and one device per asset**:
  `UNIQUE (device_id)` and the foreign key `(organization_id, site_id,
  device_id) → devices (organization_id, site_id, id) ON UPDATE CASCADE
  ON DELETE SET NULL (device_id)`, with `CHECK (device_id IS NULL OR
  site_id IS NOT NULL)`. `devices` gains `UNIQUE (organization_id,
  site_id, id)` and `UNIQUE (organization_id, id)` for these keys. A
  linked asset is therefore at its device's site.
* **Moving a device to another site moves its asset**, by the cascade,
  and a `BEFORE UPDATE OF site_id` trigger on `assets` clears the
  asset's place, which belonged to the old site, and records a `moved`
  event with both sites. Measured: as the application role, moving a
  linked device moved the asset and cleared its place; without the
  trigger the same move failed on the place's key. Moving devices is not
  built (`IMPLEMENTATION_STATUS.md:145`); the trigger is there so that
  it works when it is. A move between organizations is refused by the
  foreign keys while links exist; that feature's ADR decides what
  moves.
* **Every device that reports an inventory gets an asset**, made in the
  upload's transaction, linked, with the agent's values, unless a match
  is proposed (below). Devices that already have an inventory when slice
  2 arrives get theirs from Go, not from SQL, so that the one function
  that makes `serial_key` and `maker_key` makes them here too: at each
  start, the server finds devices with an inventory and neither an
  asset nor an open proposal, and treats each as its upload would, in
  batches of 100 in short transactions at the system scope. Once every
  device has one, the search finds nothing and the step costs one query.
  Devices without an EasyRMM agent (MeshCentral nodes recorded as
  discovered, `server/internal/remote/service.go:46-47`) get none
  automatically; *Create an asset record* on their page makes one.
  The kind is suggested from what the agent reports: a hypervisor named
  in `virtualization` gives *virtual machine*; F1's chassis type gives
  laptop, workstation or server; an operating system named Windows
  Server gives server; otherwise *workstation*. People change it; the
  agent never does after.
* **A match is proposed, never made silently.** When a device without an
  asset reports a serial, the server looks in the device's organization,
  never elsewhere, for assets without a device whose `serial_key` is the
  same and whose `maker_key` is the same or empty. One or more
  candidates make a proposal (`asset_link_proposals`) instead of a new
  asset, shown on the device and the candidates: *Link to this asset*,
  or *Not this one, make a new record*. Until someone answers, the device
  has no asset, and its page says so.
* **The match key includes the manufacturer.** Serials repeat between
  makers, and the plan notes HP reportedly reuses its own. `serial_key`
  is the serial upper-cased without spaces, dashes or dots; `maker_key`
  the manufacturer lower-cased with punctuation and company suffixes
  (Inc., Corp., Corporation, Co., Ltd., LLC, GmbH) removed and a short
  list of aliases in code (for example *Hewlett-Packard* to *hp*). An
  empty manufacturer matches any, so that a record entered by hand with
  the serial alone is still proposed. A proposal is a suggestion, so a
  rare wrong one costs a click.
* **New records entered by hand** with a serial already recorded in the
  organization show *An asset with this serial exists* with a link to it,
  and are saved only when the person confirms.
* **Removing a device keeps its asset.** A `BEFORE DELETE` trigger on
  `devices`, like `devices_easypatch_forget`, records *device removed* in
  the asset's history with the device's name, whoever deletes; the
  foreign key then clears the link. The agent's last values stay, shown
  as "last reported by the agent on" their date. A later enrolment of the
  same hardware gets a link proposal for it.
* **Two records of the same hardware are proposed for merging.** A
  computer enrolled again before its old device was removed has two
  devices, and so two assets. Whenever an asset loses its device, or an
  agent value changes its keys, the server looks in the organization for
  another asset with the same non-empty `serial_key` and the same
  `maker_key` (or either empty), where at most one of the two has a
  device. Each pair found becomes a merge proposal
  (`asset_merge_proposals`), shown on both assets and on the device:
  *Merge into this record* or *Not the same hardware*, which is kept so
  the pair is not proposed again. A merge, by `doc.manage` holders at
  both assets' sites, keeps the record with the device (or the one the
  person chooses), takes the other's manual values where it has none
  and asks about each field where both have one, moves its page links,
  attachments, references, credential links and replacement links, adds
  its history with a `merged` event naming its ID, and deletes it: one
  transaction, one audit record (`asset.merge`) with both IDs.
* **Never linked or merged automatically**, whatever matches, F1's
  SMBIOS UUID included: Microsoft documents hardware with duplicate SMBIOS
  identifiers (*Context*), cloned virtual machines may share one (to be
  confirmed), and a wrong merge puts one computer's history, warranty and
  documentation on another, which no one can take apart afterwards. A
  proposal costs a click; a wrong merge cannot be undone.
* **Linking and unlinking by hand**: `doc.manage` and `device.edit` at
  the device's site; linking moves the asset to that site (and clears
  its place if the site changed). Unlinking keeps the agent's values as
  they were.

**History and replacement.**

* **`asset_events`**, append-only (the runtime role inserts and reads):
  the asset, the organization, the time, who (a person, the agent or the
  system), the kind (`created`, `field_changed`, `status_changed`,
  `linked`, `unlinked`, `device_removed`, `replaced`, `moved`,
  `merged`), and for a field change the field, the source and the old
  and new values. Every change made by a person is also in the audit
  log; the agent's are only here, since they are not anyone's action.
* **Replacement**: *Replace with…* links a new asset to the old
  (`replaces_asset_id`), sets the old to *retired* and records both. A
  change of the agent's serial, model or (from step 14) SMBIOS UUID on a
  linked device, as a new motherboard brings, is a `field_changed` event
  with both values, which the asset's page shows as *the hardware's
  identity changed*. That is the part of feature 1's "historical hardware
  information when a device is upgraded or replaced" this record keeps:
  identities, replacements, merges, and the asset outliving its device.
  The history of components (disks, memory, processors) is feature 1's
  slice 6 (*Extension points*).
* **Deleting an asset** is for mistakes: only without a device, with a
  confirmation, audited by its ID and kind; its history goes with it.
  Retired and disposed assets are kept.

**Pages linked to devices and assets** (`doc_page_links`): a page, and a
device or an asset, each through a composite foreign key with the
organization, `ON DELETE CASCADE`. A link is visible where its page is
(the policy reads through the page, as `device_removals` reads through
its device, `00025_device_removal.sql:24-36`). The device's page gains a
*Documentation* tab and the asset's page lists its pages; a page lists
what it is linked to. References link to assets the same way.

**Export**: an *Assets* report in the reports framework (ADR-0029): one
row per asset, each built-in field's effective value and its source, the
device's name and the site, with CSV, formula cells neutralized, audited
once per organization. Feature 1's warranty columns join it.

### Extension points for feature 1
*Decided in review*, so that feature 1's ADR adds and does not
redesign. Feature 1's ADR decides everything about warranty itself.

**Extension points**, each a place in this record that feature 1 adds
to without changing what is here:

1. **Fields**: feature 1 adds to the catalogue, for example the purchase
   date, warranty start, warranty end, warranty type and notes, ship
   date, each with its form, kinds and the order of its sources.
2. **Sources**: feature 1's migration extends the `source` check with its
   four labels from the plan (vendor API, vendor tool on the device,
   firmware estimate, entered by hand, which is `manual`), and adds to
   `asset_field_values` the column it needs for what a source keeps
   beside its value (a reference to the vendor's raw answer, which
   feature 1 keeps in a table of its own). Each value's `observed_at`
   holds the source's own date (a vendor tool's last refresh).
3. **Precedence** is per field, so feature 1 can put `manual` first for
   warranty dates, as the plan says ("A technician's correction is kept
   and labelled, never overwritten by a lookup").
4. **History kinds**: `asset_events.kind` is checked against a list
   feature 1 extends: a lookup, and `component_changed` (below).
5. **Component history**: the device's previous inventory is still in
   `device_inventory` when `Record`'s transaction replaces it
   (`server/internal/inventory/service.go:83-86`), so feature 1's slice 6
   can read it there first, compare, and append `component_changed` events (a
   disk, memory or processor added, removed or replaced) to the linked
   asset's history, with no inventory history table. Which components,
   and what counts as a change worth keeping, is lifecycle policy and so
   feature 1's; this ADR leaves the event kind and the hook.
6. **Identity**: `serial_key`, `maker_key` and F1's SMBIOS UUID as an
   agent value, for feature 1's replacement detection and its lookups,
   which key on the serial and, for some vendors, the product number
   (F1's SKU). Merge proposals (above) are where its detection reports a
   match; it does not link or merge by itself.
7. **Reports**: the *Assets* report's columns come from the catalogue,
   and feature 1's *Warranty and lifecycle* report reads the same tables.

**Statements, not extension points**: what this record leaves to
feature 1 by not doing it.

* **Warranty status and hardware age** are computed by feature 1 from
  the values, not stored here.
* **Alerts** are per device today (`alerts_active_key`,
  `00006_monitoring.sql:118`). An asset with a device can alert through
  it; feature 1's ADR decides what an asset without one does.
* **Virtual machines** are the kind *virtual machine*, which feature 1
  skips by kind.

### Attachments and diagrams
Slice 3. *Decided in review.*

* **What they attach to**: a page, an asset, or the organization or a
  site directly (contracts, diagrams). Immutable: a new version is a new
  upload marked as replacing the old.
* **Stored in PostgreSQL**, as signed builds are, in chunks of 1 MiB
  (`doc_attachment_chunks`) beside a metadata row (`doc_attachments`:
  the cleaned file name, the type found, the size, the SHA-256, the
  number of chunks, a thumbnail for images, who uploaded it and when, the
  subject). Chunks let a download read the file a piece at a time and
  keep lists from reading content. Row-level security on both, the
  chunks through their attachment, and an attachment of a page through
  its page (*Restricted pages*). Backups and restores carry them with no
  new step, and a restore never leaves a file without its row or a row
  without its file. Files on the data root are under *Not chosen*.

**Uploading.**

* **The file is received before any transaction begins.** The body is
  read whole under `http.MaxBytesReader`, at most 25 MiB, as signed
  builds are, into memory: at most four uploads at once per server
  process and two per person, so at most 100 MiB is held. Its type is
  checked, its SHA-256 computed and its thumbnail made while no
  connection is held.
* **Then one short transaction** checks the quotas (*Storage*), with the
  organization's usage row locked so that two uploads cannot both pass,
  writes the metadata row and the chunks, adds the size to the usage
  and appends the audit record last, so that the audit log's lock is
  held only from the append to the commit. Writing 25 rows of 1 MiB
  took 1.5 seconds (*Context*), well inside the 30-second statement
  timeout; slice 3's tests measure it on the release.
* **The name**: the console sends it in `X-File-Name`, percent-encoded
  UTF-8 (`encodeURIComponent`), since a header cannot carry other bytes
  safely. The server decodes it (`url.PathUnescape`), refuses it if it is
  not valid UTF-8 or longer than 255 bytes, and cleans it: path segments
  before the last `/` or `\` removed, control characters removed, leading
  dots and trailing dots and spaces removed, and an empty result replaced
  by `attachment`. The cleaned name is stored and shown.
* **Types, by allow-list**, checked twice: the extension, then the bytes.
  * Binary types must carry their signature: PDF (`%PDF-`); PNG, JPEG,
    GIF and WebP by `http.DetectContentType`; Word, Excel, PowerPoint
    and Visio (`.docx`, `.xlsx`, `.pptx`, `.vsdx`) and OpenDocument as a
    ZIP whose entries name that format. A file whose bytes contradict its
    extension is refused.
  * Text types (plain text, CSV, Markdown, log, JSON, XML, YAML,
    configuration files `.conf`, `.cfg` and `.ini`, `.drawio` diagrams
    and SVG) must be valid UTF-8 without NUL bytes, and any `text/`
    verdict of `http.DetectContentType` is accepted for them: a Markdown
    file that begins with an HTML comment is sniffed as `text/html`
    (*Context*), which is no reason to refuse it, since nothing is ever
    served as HTML (below).
  * Not executables, scripts, HTML or archives: an archive can carry any
    of those, and EasyRMM has no malware scanner to look inside.
* **Thumbnails are made at upload**, for PNG, JPEG and GIF (the first
  frame), with Go's own decoders: `image.DecodeConfig` first, and no
  thumbnail for an image over 24 megapixels; one decode at a time per
  process, so at most about 100 MB of decoded pixels; scaled to at most
  256 pixels on the longer side, written as PNG, at most 64 KiB, kept in
  the metadata row. WebP files are stored and previewed but get no
  thumbnail: Go's standard library has no WebP decoder, and a thumbnail
  is not worth a new dependency. An image without a thumbnail shows an
  icon.

**Downloading.**

* **The record first, in its own short transaction**: the attachment is
  read under row-level security (so a caller who cannot see it gets
  `404`), the `doc_attachment.download` record is appended, and the
  transaction commits before a byte is sent. If the record cannot be
  written, nothing is sent.
* **Then the file streams with no transaction open between chunks.**
  The headers go first, `Content-Length` with them; each chunk is read
  by its own query in its own short transaction with the caller's scope,
  as every query is (*Context*), and written to the client before the
  next is read. A slow client therefore holds no connection, no lock and
  no transaction while it reads: not the audit log's lock, not one of
  the pool's 20 connections, and never long enough for the 60-second
  idle-in-transaction timeout.
* **The SHA-256 is checked as the file streams.** If a chunk is missing
  (the attachment was purged meanwhile) or the hash at the end does not
  match, the server aborts the connection before the last byte, so that
  the browser, knowing the length, marks the download failed, and logs
  the attachment's ID as an error.
* **Served only as downloads**: `GET /api/v1/attachments/{id}/content`
  answers `Content-Type: application/octet-stream`, `Content-Disposition`
  made by `mime.FormatMediaType("attachment", {"filename": name})` from
  the cleaned name (`filename=` for ASCII, `filename*=utf-8''…` for
  others, as measured in *Context*; RFC 6266 has recipients prefer
  `filename*`), and `attachment` alone if it returns nothing,
  `X-Content-Type-Options: nosniff`, `Content-Security-Policy:
  default-src 'none'; sandbox`, `Cache-Control: private, no-store`.
  Nothing is ever served as HTML or SVG on the console's origin.
* **Image previews**: PNG, JPEG, GIF and WebP whose first bytes say so,
  through `/preview` with their own type and the same headers, streamed
  the same way but not recorded, since a page shows its images whenever
  it is read. **Lists never load full images**: they show thumbnails, from
  `/thumbnail`, read in one query. Full images appear only on the
  attachment's own page and as the `attachment:` images of a page.
  Whether every supported browser shows an `<img>` whose answer says
  `attachment` is **to be confirmed** by slice 3's browser test; if one
  does not, previews answer `inline` with everything else the same.
* **Limits on reads**: at most four downloads and previews at once per
  person and 16 per server process; beyond them the server answers `429`
  with `Retry-After`. Each chunk takes a pooled connection for one query
  only, so 16 streams use at most 16 of the 20 connections at any moment
  and usually far fewer.

**The rest.**

* **Diagrams** are attachments (Visio, `.drawio`, PDF, images), drawn
  in the tools people already use. An editor inside the console is not
  built: its code would have to be served by EasyRMM, a large dependency
  for the console to carry, or loaded from elsewhere, which the content
  security policy refuses.
* **Deletion** moves to the trash for 30 days, as pages do; then the
  chunks go and the usage drops.
* **Every upload, download and deletion is audited** (the attachment's
  ID, its subject's, the type and size; the SHA-256 stays on the
  attachment's row, for the same reason as a revision's).

### Storage
Slices 1 and 3. *Decided in review.*

Documentation lives in the database, so it grows the database, every
dump, every restore and each of the updater's two copies of the data
root, and the updater refuses to start an upgrade when the host lacks
room for a copy (ADR-0052, *Context*). Two bounds keep it in hand.

* **A quota per organization**, 1 GiB by default, which a Super
  Administrator changes per organization (`settings.manage`). It counts
  attachments with their thumbnails and the bodies of revisions, pages
  in the trash included. `doc_storage_usage` keeps each organization's
  total, changed in the same transaction as what it counts, so that no
  check has to add up the tables. Slice 1 counts revisions; slice 3 adds
  attachments.
  * At 80% and at 100%, a notice (ADR-0053) to the organization's
    administrators.
  * At 100%, new attachments are refused (`409 quota_exceeded`). Saves
    of pages go on, since a body is at most 256 KiB, until 110%, and are
    then refused too, except redaction and emptying the trash, which
    free space.
* **A limit for the deployment**, 20 GiB by default, set by Super
  Administrators (`settings.manage`): the sum of every organization's
  usage. At 80%, a notice to the Super Administrators; at 100%, new
  attachments are refused everywhere (`409 storage_full`) and the
  console says why. Page saves are not refused by this limit, only by
  the quotas. The backup guide gains the sum as a line to watch beside
  the disk's free space, and says that the updater needs room for a copy
  of it.
* **Coalescing** keeps a person's run of saves to one revision
  (*Pages*); there is no autosave.

### Restricted pages
Slice 4. *Decided in review.*

* A page can be marked **restricted** by `doc.manage` holders who also
  hold `doc.view_restricted` there, and unmarked by the same, audited.
  Its title, body, revisions, links, attachments and search terms are
  then read only with `doc.view_restricted`: Site Administrators and
  above. Others see neither the page nor that it exists, in lists,
  search, links, the device's *Documentation* tab and exports.
* **Row-level security hides them**, so that no path can leak one
  through a check it forgot. `applyScope` sets two more settings for
  every transaction, `easyrmm.scope_restricted_orgs` and
  `easyrmm.scope_restricted_sites`: the organizations and sites where the
  caller holds `doc.view_restricted`, resolved from the caller's roles as
  the other scopes are. The policy on `doc_pages` adds to the tenant
  condition: `NOT restricted OR easyrmm_scope_all() OR organization_id =
  ANY (scope_restricted_orgs) OR site_id = ANY
  (scope_restricted_sites)`. Every table that belongs to a page
  (revisions, links, attachments of a page and so their chunks) reads
  through the page with `EXISTS`, so it inherits the condition; the
  terms table carries the page's `restricted` flag, written in the same
  transaction as the page's, under the same condition, and search reads
  its results back through the pages' policy as well. Measured: as the
  application role, a restricted page and its revisions were invisible
  without the setting and visible with it, through the page and through
  the revisions table directly.
* **Each read of a restricted page or its attachment is audited**
  (`doc_page.view_restricted`), since these are the pages someone chose
  to protect; the console reads a page once per opening.
* For what an MSP keeps about the customer and does not show its
  Technicians: incidents, contracts, HR matters. Credentials are not
  pages (slice 7).
* **Differs from the plan**, which put this last with references: the
  requirement's "sensitive information must have appropriate access
  restrictions" is met by this, and it is small.

### Network documentation
Slice 5. *Decided in review.*

* **VLANs** (`network_vlans`): at a site, an ID from 1 to 4094 unique in
  the site, a name, notes.
* **Subnets** (`network_subnets`): at a site, a CIDR (PostgreSQL `cidr`),
  an optional VLAN, the gateway, DNS servers, how addresses are given
  (static, DHCP with its range and the server, as an asset or a note),
  notes.
* **Address assignments** (`ip_assignments`): an address in a subnet,
  assigned to an asset or described, static or reserved.
* **Managed devices' addresses are shown, not stored**: a subnet's page
  lists the organization's devices whose reported interfaces have an
  address in it, read from the inventory (`agentproto/inventory.go:103-110`),
  with gateways and DNS servers; nothing is copied, so nothing goes
  stale.
* **Internet connections** are assets of that kind, which gain built-in
  fields: the provider (a contact or a name), the circuit ID, the account
  number, bandwidth down and up, the static addresses, the contract's
  end. Their support logins are references or credentials.
* **DNS information** beyond servers (registrar, zones, records) is pages
  and references; this slice adds no DNS model.
* Discovery (SNMP, scans) is not part of this ADR.

### Custom fields and import
Slice 6. *Decided in review.*

* **Definitions** (`custom_field_definitions`): shared (no organization,
  managed with `settings.manage`) or an organization's (`org.manage`),
  each for organizations, sites, contacts or assets (optionally only
  some kinds): a label, a key, a type (text, number, date, yes or no, a
  choice from a list, a URL), required or not, an order. No secret type:
  secrets are slice 7.
* **Values** (`custom_field_values`): one nullable column per subject
  (site, contact, asset; none for the organization itself), each a
  composite foreign key with the organization, at most one set; validated
  by the definition's type; searchable; edited with `doc.manage`.
* **The requirement's "customer-specific custom fields"** are definitions
  for organizations.
* **Import from CSV**, assets and contacts, by `doc.manage` at the
  organization: at most 5,000 rows and 5 MiB; a dry run first that lists
  each row's errors and what would be created or changed; then one
  transaction, one audit record with the counts. A row with an `id` from
  an export of the same organization updates that asset's or contact's
  `manual` values; other rows create. Import never writes an `agent`
  value and never touches another organization.

### Credentials
Slice 7, if the owner wants credentials stored at all ([Owner
questions](#owner-questions)). *Decided in review*, the storage
included.

**Where they are stored: in the keystore, not under `EASYRMM_SECRET_KEY`.**

* **Why not the existing key.** Today's sealed secrets are EasyRMM's own:
  TOTP seeds, agent tokens, the job key, the certificate authority's
  key, MeshCentral's secrets, single sign-on client secrets
  (`server/internal/auth/service.go:758`, `agents/tokens.go:169`,
  `jobs/key.go:83`, `pki/pki.go:159`, `remote/secrets.go:116`,
  `sso/sso.go:359`), and with ADR-0053 the MSP's own channels. Credentials in
  documentation would be the customer's: firewall and switch
  administrators, a domain's administrator, the cloud tenant's global
  administrator, the registrar. The backup guide puts `.env`, which
  holds the key, beside the dumps, and the updater's backup holds both.
  Sealed with that key, a stolen backup set, which today gives "full
  control of every managed device", would also give the customers'
  cloud, network and registrar accounts, which device control does not
  reach. Moving them into the keystore later would not help: every
  backup made in the meantime keeps them sealed under the old key until
  it expires.
* **Why the keystore.** It is the one place planned with a
  key-encryption key outside PostgreSQL and `.env`, keys per
  organization, versioned key-encryption keys kept as long as a backup
  needs them, reads in the transaction that writes their audit record,
  rate limits enforced inside it too, and its own backup rules. A
  database dump, with or without `.env`, opens nothing in it.
* **What the keystore's ADR must therefore allow** (a request to it, not
  a decision for it): a second kind of record beside recovery keys,
  written from the console rather than escrowed by an agent, with a
  policy of its own (below). Whether the console seals to the
  organization's public key, so that the main server never holds a new
  credential's plaintext, is that ADR's choice. Its on-host protection
  applies unchanged.
* **A key pair of its own.** Each organization has one HPKE key pair for
  recovery keys and, if credentials are stored, a second one for
  credentials, each private key wrapped by the key-encryption key
  separately. Revealing a credential unwraps only the credentials' private
  key, so no bug, permission or rate limit on the far busier credential
  path can ever open the key that opens a disk.

**The read policy, beside the keystore's for recovery keys**
(the plan's, `docs/architecture/feature-plan-msp.md:1157-1164`):

| | Recovery keys (the plan) | Credentials (this ADR) | Why they differ |
|---|---|---|---|
| Permission | Its own | Its own, `doc.credential_reveal` | Same |
| Step-up | Yes (F5) | Yes, within 5 minutes (ADR-0055) | Same |
| A stated reason, kept in the audit record | Yes | Yes, at most 200 characters; the console offers the last one typed in that tab | Same |
| Rate limits per user and per organization, enforced inside the keystore too | Yes | Yes (below) | Same |
| The audit record in the transaction that opens it | Yes | Yes | Same |
| A notice to every Super Administrator per read | Yes | No: a notice (ADR-0053) when a limit is reached; the audit log has every read | Technicians read credentials daily; a notice per read would make Super Administrators ignore the notices, including those for recovery keys, which are rare and open whole disks |
| Two-person rule | Built; per read or per organization is an owner question | Not offered | A second person for each routine login would stop the work; the record and the limits are the control |
| Shown once, `Cache-Control: no-store` | Yes | Yes; *Reveal* hides after 30 seconds, *Copy* never shows it | Same |
* **Until then**, references (slice 1) and the warning are what EasyRMM
  offers. Slice 7 waits for the keystore's reads (its slice 2, step 19 of
  the plan's order) and step-up (ADR-0055's 5b2, step 17).

**The record.** `credentials`: at the organization or a site, a name, a
kind (login, licence key, Wi-Fi key, other), the username, a URL, notes,
links to assets and pages; the secret itself is a record in the
keystore, referred to by ID, never a column of this table. A TOTP seed
for a shared account is not stored (*Not chosen*).

**Who sees what.**

| | Read-Only | Technician and above |
|---|---|---|
| That the credential exists: name, kind, URL, links | Yes (`doc.view`) | Yes |
| Username | No | Yes (`doc.credential_reveal`) |
| The secret | Never | With `doc.credential_reveal` at its organization or site, step-up within 5 minutes, one audit record per read |
| Create, change, replace the secret, delete | No | `doc.manage` (writing a secret needs no reveal) |

**Revealing and copying.**

* `POST /api/v1/credentials/{id}/secret` with `{"purpose": "reveal"}` or
  `{"purpose": "copy"}` answers the secret with `Cache-Control:
  no-store`. A `POST`, since it writes a record.
* **The record and the read are one transaction** (ADR-0047's pattern,
  `tokens.go:178-213`): `credential.reveal` or `credential.copy`, under
  the credential's organization and site, with its ID, the reason and
  who; if the record cannot be written, nothing is answered.
* **Step-up as ADR-0055 defines it**: a second factor within the last
  5 minutes, recorded on the session; never a password or a recovery
  code alone.
* **Rate limits**: 20 reads per person in 10 minutes and 200 per
  organization in an hour, beyond which reads are refused and a notice
  (ADR-0053) goes to the organization's administrators and the Super
  Administrators; the keystore's own limits apply too.
* **Refusals** (no permission, no step-up) answer `403` and are recorded
  with the outcome `denied`, bounded as ADR-0063 bounds its refusals (at
  most once per caller, action, target and organization in 10 minutes,
  and 20 per caller in 10 minutes). A caller who cannot see the
  credential gets `404` and no record.
* **Reveal** shows the secret in a dialog for 30 seconds, then hides it.
  **Copy** fetches it and writes it to the clipboard without putting it
  in the page: it is never rendered. Firefox and Safari require the
  write to follow a click closely; whether a write after the read's round
  trip still counts is **to be confirmed** in each browser, and where it
  does not the console asks for a second click (*Copy now*). The record
  says which was asked for; the server cannot know what the browser did
  with it.
* **Never** in lists, the API's other answers, search terms, exports,
  reports, notifications, the audit log's details, logs or errors.
  Usernames are never search terms either; a credential is found by its
  name. A
  test feeds a known secret through every path and searches every output
  for it, as ADR-0053's tests do for channels' URLs (never in logs or
  `last_error`).
* **Offboarding**: a customer's credentials leave only through the
  keystore's own export, encrypted, with step-up and audit, never as CSV.

**What it does not fix**: whoever holds the role and passes step-up can
read and keep the secret; a Super Administrator, or root on the host, can
read every one, as the threat model says of them
(`docs/security/threat-model.md:34-36,195`). The record shows who read
what; rotating a secret after people leave is the MSP's practice.

### Permissions
*Decided in review.* New permissions, listed in `rbac.go` and
`docs/security/rbac.md`:

| Permission | Read-Only | Technician | Site Admin | Org Admin | Super Admin | What it allows |
|---|:-:|:-:|:-:|:-:|:-:|---|
| `doc.view` | ✓ | ✓ | ✓ | ✓ | ✓ | Read pages and their revisions, contacts, addresses, places, hours, references, assets and their history, network documentation, attachments, custom fields, credentials' names |
| `doc.manage` | | ✓ | ✓ | ✓ | ✓ | Create, change and delete all of those; link; import; restore from the trash |
| `doc.view_restricted` | | | ✓ | ✓ | ✓ | Read restricted pages and their attachments (slice 4) |
| `doc.credential_reveal` | | ✓ | ✓ | ✓ | ✓ | Usernames, and secrets with step-up (slice 7) |

* `doc.view` joins `viewPerms`; `doc.manage` and `doc.credential_reveal`
  the Technician's; `doc.view_restricted` the Site Administrator's. The
  roles stay a chain of supersets, as `TestRoleHierarchyIsMonotonic`
  checks (`server/internal/rbac/rbac_test.go:42-55`).
* Each is checked at the row's organization, or its site for a site's
  rows. Organization-level rows need the permission at the organization;
  a site-scoped grant does not reach them (*Where documentation lives*).
* Redacting a revision, redacting at once, emptying the trash early and
  the documentation export need `org.manage`; custom field definitions
  `org.manage` or `settings.manage`; an organization's quota and the
  deployment's limit `settings.manage`. Merging assets needs
  `doc.manage` at both assets' sites.
* **Reports** (the *Assets* report, contacts as CSV) need `doc.view` and
  `report.view`, as other reports do, audited per organization.

### Row-level security
*Decided in review.*

* **Tables with their own organization and site** (`contacts`,
  `doc_pages`, `doc_search_terms`, `credential_references`, `assets`,
  `doc_attachments`, the network tables, `credentials`, custom field
  values): `ENABLE` and `FORCE ROW LEVEL SECURITY` and `sites_tenant`'s
  policy on `organization_id` and `site_id`. `site_places` likewise, its
  site required.
* **Tables reached through a parent** (`doc_page_revisions`,
  `doc_page_links`, `doc_attachment_chunks`, `asset_field_values`,
  `asset_events`, `asset_link_proposals`, `asset_merge_proposals`): a
  policy that reads through the parent (`EXISTS (SELECT 1 FROM parent
  WHERE id = …)`), as `device_removals` does. They still carry
  `organization_id` for their composite foreign keys. An attachment of a
  page has both: its own tenant condition and `EXISTS` through its
  page.
* **The restricted wall** is part of the policies on `doc_pages` and
  `doc_search_terms`, from the scope settings `applyScope` sets
  (*Restricted pages*); every table under a page inherits it through
  `EXISTS`.
* **Shared custom field definitions** (no organization): read by anyone
  who holds `doc.view` anywhere, as the shared script library is read,
  and written at the platform scope only.
* **Every link names its organization** in a composite foreign key, so
  that the database refuses a page, asset, contact, place, reference,
  credential or device of another organization, whatever the server
  asks (measured above).
* **Permissions are the service's**, as roles always are
  (`docs/security/rbac.md:37-38`); row-level security is the tenant wall
  beneath them, and the restricted wall beside it.

### Audit
*Decided in review.* Every change and every read of a secret or a
restricted page is recorded, in the change's transaction, except a
download's and an export's, which are recorded in a short transaction
of their own before anything is sent (*Attachments*). **Details carry
identifiers, never titles or names**: the record's target is the row's
ID, and its details hold other rows' IDs, field names, kinds, sizes,
counts and outcomes. Never a page's title, text or hash, a contact's
name or details, an address, a note, a file name, a field value typed by
people or a secret, since any of them can be personal data or a secret
and records are forwarded as written (ADR-0023). The console shows a
record's subject by looking its ID up, for those who may see it.
Revisions are named by their ID, which a restore does not reuse, and
not only by their number, which repeats after a restore (ADR-0062).

| Action | When | Details |
|---|---|---|
| `organization.details_update`, `site.details_update` | Contact information, address, hours | Field names |
| `site_place.create`, `.update`, `.delete` | Places | Kind, parent's ID |
| `contact.create`, `.update`, `.delete` | Contacts | Field names, priority and emergency |
| `doc_page.create`, `.update` | Each save | Revision ID and number, body size, `coalesced`, whether a secret warning was acknowledged and on how many lines |
| `doc_page.move`, `.delete`, `.restore`, `.purge`, `.trash_empty` | Level changes, trash | From and to; purges counted per organization |
| `doc_page.restrict`, `.unrestrict` | The restricted mark | |
| `doc_page.links_update` | `PUT /pages/{id}/links` | Device and asset IDs added and removed |
| `doc_page.revision_redact`, `doc_page.history_redact` | Redaction, one or at once | Revision IDs or pages' IDs, counts, the reason |
| `doc_page.view_restricted` | Each read of a restricted page | Revision ID |
| `doc.export` | Each documentation export | Counts by kind |
| `credential_reference.create`, `.update`, `.delete` | References | Manager, field names |
| `asset.create`, `.update`, `.delete`, `.link`, `.unlink`, `.replace`, `.merge` | Asset changes by people | Kind, field names and sources; device ID for links; both asset IDs for a merge or replacement |
| `asset.link_proposal_answer`, `asset.merge_proposal_answer` | Proposals answered | Asset and device IDs, the answer |
| `asset.import`, `contact.import` | CSV imports | Counts created and changed |
| `report.export` | Asset and contact reports | As today |
| `doc_attachment.upload`, `.download`, `.delete` | Attachments | Subject's ID, type, size |
| `network_vlan.create`, `.update`, `.delete`; `network_subnet.*`; `ip_assignment.*` | Network documentation (slice 5) | VLAN number, the subnet's prefix length, field names; the asset's ID for an assignment |
| `custom_field.create`, `.update`, `.delete` | Definitions | Type, subject kind |
| `organization.documentation_quota_update`, `settings.documentation_limit_update` | Quotas and the deployment's limit | Old and new values |
| `credential.create`, `.update`, `.delete` | Credentials | Kind, whether the secret changed |
| `credential.reveal`, `credential.copy` | Each read of a secret, and each refusal (`denied`) | The reason |

The agent's changes to an asset are in its history, not the audit log.
Searches, ordinary page reads and previews are not audited: there are
too many and they reveal nothing beyond what `doc.view` already allows.
Addresses and VLAN names are left out like other typed values; a
subnet's prefix length is not personal and says what changed.

### Deleting an organization or a site
*Decided in review.* Today an organization must have no sites and a site
no devices (`tenancy.go:317-352,482-512`). Documentation is kept from
being lost by accident the same way: deleting a site or an organization
that has documentation answers `409` with the counts (pages, contacts,
assets, attachments, references, credentials). The console shows them
and offers to delete the documentation with it once the person types the
name; the request then carries the counts it confirmed and is refused if
they changed. Everything goes in one transaction, recorded with the
counts. Credentials leave with the keystore's records for them.

### The data model
New tables and columns by slice. Every table: `ENABLE` and `FORCE ROW
LEVEL SECURITY`, policies as above, grants to `easyrmm_app` as listed,
`created_at` and `updated_at` with `easyrmm_touch_updated_at` where rows
change.

| Slice | Migration adds | `easyrmm_app` may |
|---|---|---|
| 1 | `organizations`: `main_phone`, `main_email`, `website`, `business_hours`, `after_hours_note`; drops `notes` | as today |
| 1 | `sites`: address fields, `business_hours`, `after_hours_note`; drops `notes` | as today |
| 1 | `site_places`, `contacts` | all |
| 1 | `doc_pages` (with `version` and `deleted_at`; `restricted` from slice 4) | all |
| 1 | `doc_page_revisions` (an ID, a number, the body's size and hash); the coalescing and redaction functions, `SECURITY DEFINER` with `search_path = pg_catalog, public, pg_temp` | `INSERT`, `SELECT`; execute the functions |
| 1 | `doc_search_terms`: one nullable foreign key per subject kind, each `ON DELETE CASCADE` with a partial index, and `CHECK (num_nonnulls(…) = 1)`; btrees on `(organization_id, term)` and `(term, organization_id)` | all |
| 1 | `doc_storage_usage` (per organization: the quota, the bytes used); the deployment's limit in the platform settings | all on usage; the quota and limit through the service's `settings.manage` checks |
| 1 | `credential_references` | all |
| 2 | `devices`: `UNIQUE (organization_id, id)`, `UNIQUE (organization_id, site_id, id)`; a `BEFORE DELETE` trigger | as today |
| 2 | `assets` with a `BEFORE UPDATE OF site_id` trigger; `asset_field_values`, `asset_link_proposals`, `asset_merge_proposals`, `doc_page_links`, links from references to assets; columns on the terms table for assets | all |
| 2 | `asset_events` | `INSERT`, `SELECT` |
| 3 | `doc_attachments` (with the thumbnail), `doc_attachment_chunks`; the terms table's column for attachments | all |
| 4 | `doc_pages.restricted`; the two scope settings and the policies' restricted condition | as above |
| 5 | `network_vlans`, `network_subnets`, `ip_assignments` | all |
| 6 | `custom_field_definitions`, `custom_field_values` | all |
| 7 | `credentials`, links; the keystore's records | all on `credentials`; the keystore's as its ADR says |

Migrations are additive within a release apart from the two `notes`
columns, whose content moves first. Each migration has its `Down`, which
for slice 1 puts the notes back from the *Notes* pages' first revision.

### The API
Under `/api/v1`, JSON, as the rest of the API: lists paged, errors as
`apperr` gives them.

* **Slice 1**: `PUT /organizations/{id}/details`; `PUT
  /sites/{id}/details`; `GET`, `POST /sites/{id}/places`; `PATCH`,
  `DELETE /places/{id}`; `GET`, `POST /organizations/{id}/contacts`
  (`?siteId=`); `PATCH`, `DELETE /contacts/{id}`; `GET`, `POST
  /organizations/{id}/pages` (`?siteId=&section=&deleted=`); `GET`, `PUT`
  (with `baseVersion`), `DELETE /pages/{id}`; `POST /pages/{id}/restore`;
  `POST /pages/{id}/move`; `GET /pages/{id}/revisions`; `GET
  /pages/{id}/revisions/{n}`; `POST /pages/{id}/revisions/{n}/redact`;
  `POST /organizations/{id}/documentation/redact-history` (pages chosen,
  or all); `POST /organizations/{id}/documentation/empty-trash`; `GET
  /organizations/{id}/documentation/export` (the ZIP); `GET
  /documentation/search?q=&organizationId=&siteId=&kind=`; `GET`, `POST
  /organizations/{id}/credential-references`; `PATCH`, `DELETE
  /credential-references/{id}`; `GET /organizations/{id}/documentation/usage`;
  `PUT /organizations/{id}/documentation/quota` and the deployment's
  limit in the platform settings.
* **Slice 2**: `GET`, `POST /organizations/{id}/assets` (filters by site,
  kind, status, linked or not); `GET`, `PATCH`, `DELETE /assets/{id}`;
  `GET /assets/{id}/history`; `POST /assets/{id}/link`, `/unlink`,
  `/replace`, `/merge`; `GET /devices/{id}/asset`; `POST
  /devices/{id}/asset-proposal` and `POST
  /asset-merge-proposals/{id}` with the answer; `PUT /pages/{id}/links`;
  the *Assets* report through `/reports`.
* **Slice 3**: `POST /attachments?subject=page:{id}` (or `asset:`,
  `site:`, `organization:`), the raw body, the name in `X-File-Name`
  (percent-encoded UTF-8); `GET /attachments/{id}`, `/content`,
  `/preview`, `/thumbnail`; `DELETE /attachments/{id}`; `POST
  /attachments/{id}/restore`.
* **Slice 4**: `restricted` in the page's `PUT`.
* **Slice 5**: `/organizations/{id}/vlans`, `/subnets`,
  `/ip-assignments`, with `GET /subnets/{id}/devices`.
* **Slice 6**: `/custom-fields` (shared), `/organizations/{id}/custom-fields`;
  values inside each subject's `PATCH`; `POST
  /organizations/{id}/assets/import?dryRun=true`, likewise contacts.
* **Slice 7**: `GET`, `POST /organizations/{id}/credentials`; `PATCH`,
  `DELETE /credentials/{id}`; `PUT /credentials/{id}/secret` (write);
  `POST /credentials/{id}/secret` (read, above).

### The console
* **Documentation** in the main navigation: search across the caller's
  organizations, recently changed pages, and the organizations.
* **An organization's page** gains tabs beside *Overview* and *Patch
  policy*: *Overview* shows the contact information, primary and
  emergency contacts, each site with its address and whether it is open
  now; *Contacts*; *Pages*; *Assets* (slice 2); *Network* (slice 5);
  *Passwords* (references, and credentials from slice 7).
* **A site's page**: its address, hours and places; its contacts, pages,
  assets and network.
* **A page**: the rendered page, its sections and links, *Edit* (the
  editor with its toolbar and preview), *History*, attachments (slice 3),
  the restricted mark (slice 4).
* **A device's page**: an *Asset* card on *Overview*, with any link or
  merge proposal, and a *Documentation* tab (slice 2).
* **For Organization Administrators**, on the organization's *Pages*
  tab: storage used against the quota, *Export documentation*, *Redact
  history* and *Empty trash*.
* **An asset's page**: each field with its effective value, its source
  and the other sources' values; status, location, assigned contact;
  history; pages, attachments, references and credentials.
* Controls hidden where the permission is missing; the server decides
  regardless.

### Backups and restore
*Decided in review.*

* **No new backup part.** Everything is in the `easyrmm` database, which
  the guide's `pg_dump` already copies, attachments included; no file is
  written beside it. The guide's table keeps its rows. It gains a note
  that documentation grows the dumps, the restore and each of the
  updater's two copies of the data root (ADR-0052), that the updater
  refuses an upgrade when the host lacks room for a copy, and how the
  quotas and the deployment's limit bound it (*Storage*).
* **Credentials** (slice 7) follow the keystore's backup rules: each
  key-encryption key version apart from the data and kept as long as a
  backup needs it. A restore without the version its data needs starts
  with reveals turned off and says so, as the keystore's restore does.
* **After a restore**, documentation changed after the backup is lost.
  If the audit log was forwarded (ADR-0023), it names each lost revision
  by its ID, its page's ID, its number, author, time and size, never its
  text. The number alone would not do: the next save after the restore
  takes the same number again, while its ID is new. ADR-0062 keeps the
  audit IDs from repeating.
* **Derived rows** (`doc_search_terms`, the effective values on `assets`)
  are in the dump like the rest. `easyrmm-server documentation reindex`
  rebuilds the terms from their subjects, for a change of tokenizing
  between releases.
* **Tested**: the restore drill gains a page with revisions and a redacted
  one, an attachment, an asset with history and a removed device; after
  restoring onto a new host, the attachment's SHA-256 matches, the
  revisions and history are intact, and search finds the page.

### Not chosen
*Decided in review.*

* **A WYSIWYG editor**: it stores HTML or an editor's own document
  format, takes pasted HTML from other pages, and needs a sanitizer of
  its own on every path in and out, beside a much larger dependency.
  Markdown with a toolbar and a preview covers the requirement, and the
  stored text stays readable without EasyRMM.
* **Rendering Markdown on the server to HTML**, or `markdown-it` in the
  console: either puts an HTML string into the page
  (`dangerouslySetInnerHTML`, which the console has never used) behind a
  sanitizer. `markdown-it` also brings `argparse` (PSF-2.0), not on CI's
  licence list. A renderer of EasyRMM's own from `markdown-it`'s tokens
  was weighed: fewer packages, but a parser's output mapped by hand is
  where escaping bugs live. `react-markdown`'s 102 packages are pinned in
  the lock file, checked by CI's licence check, and updated through
  Dependabot's reviewed pull requests like every other.
* **A `tsvector` with a GIN index**: unused under row-level security
  (measured). **Making `@@` leakproof**: only a superuser can, and the
  operator is not declared leakproof upstream.
* **Shared pages for every organization**: read by customers' staff
  (*Where documentation lives*).
* **Organization-level documentation for site-scoped people** through
  `scope_read_orgs`: above.
* **Storing credentials under `EASYRMM_SECRET_KEY`**, now or as a
  stop-gap: above. **Storing credentials as a page field or a custom
  field type**: the requirement's "casually stored".
* **TOTP seeds of shared accounts** beside credentials: a second factor
  kept with the password is no longer a second factor.
* **Linking a device to an asset, or merging two assets, without
  asking**, by serial or by SMBIOS UUID: serials repeat, SMBIOS
  identifiers are duplicated on some hardware (*Context*), and a wrong
  link or merge would put one computer's warranty and history on
  another.
* **One transaction for a whole download or upload**: it would hold the
  audit log's lock, a pooled connection and an open transaction for as
  long as the client takes, and run into the idle-in-transaction
  timeout (*Context*).
* **Autosave**: every pause would be a revision, or the history would
  need rewriting more than coalescing does; an explicit save keeps the
  history meaningful and its growth bounded.
* **WebP thumbnails** through a decoder outside Go's standard library:
  not worth a new dependency for a thumbnail.
* **`ts_headline`'s default markers** (`<b>` and `</b>`): its own
  documentation says its output is not safe in a web page, and measured,
  it left `<img src=x onerror=alert(1)>` in an excerpt as it was.
* **No asset until someone makes one**: feature 1 shows warranty and age
  for every device, which needs a record for every device.
* **A table per kind of asset**, or every field a column: feature 1's
  four sources per warranty field would multiply the columns; values per
  field and source keep each source's value and date.
* **Letting people edit the agent's values**: a correction would hide
  what the computer itself reports, and feature 1's requirement asks
  that the system "clearly distinguish verified warranty information from
  estimated or manually entered information". Each source keeps its own
  value instead.
* **Attachments as files on the data root**: a second store to back up
  and restore in step with the database, outside row-level security, and
  files without rows after a partial restore.
* **Archives, HTML and executables as attachments**, and **SVG or PDF
  shown in the console**: above.
* **Drafts kept in the browser**: `PRIVACY.md` keeps the browser's
  storage to the theme.
* **A diagram editor in the console**: above.

### What this does not fix
* **Super Administrators and the host's operator read everything**,
  credentials included through the keystore's limits, as the threat
  model trusts them.
* **Backups keep what was deleted or redacted** until they expire,
  bulk redaction included.
* **Read-Only users see contacts**, which are personal data; an MSP that
  gives customers' staff Read-Only at their organization shows them the
  organization's contacts and pages. Restricted pages are for what they
  must not see.
* **Device control reaches what is on devices.** A Technician with
  `script.run` or `device.terminal` can read secrets stored on a
  computer; documentation adds no limit there.
* **Attachments are not scanned for malware.** The allow-list keeps out
  what runs by itself; a document with macros is still a document. The
  guide says so.
* **Search finds words, not substrings**: `fire` finds *firewall*; *wall*
  does not; nor does a prefix shorter than three characters.
* **Merges cannot be undone**; the proposal and its confirmation are
  the guard.

## The requirements
Feature 4 of the owner's requirements, bullet by bullet.

| Requirement | Where | Status after this ADR |
|---|---|---|
| **Customer information** | | |
| Customer name and contact information | The customer record (slice 1) | Name exists; main phone, email, website and contacts new |
| Customer locations and physical addresses | The customer record: sites' address fields, places (slice 1) | New; sites are the locations |
| Primary and secondary contacts | Contacts (slice 1) | New |
| Emergency contacts | Contacts (slice 1) | New |
| Business hours | The customer record (slice 1) | New, per site or organization, in its time zone |
| Customer-specific notes | Pages; notes moved into them (slice 1) | With history and Technicians' edits |
| Customer-specific custom fields | Custom fields for organizations (slice 6) | New |
| **Infrastructure documentation** | | |
| Servers, workstations | The asset record, made for every device with an inventory (slice 2) | New |
| Network equipment, firewalls, switches, wireless access points | Asset kinds (slice 2); network documentation (slice 5) | New |
| Printers, UPS systems, storage systems, virtualization hosts | Asset kinds (slice 2) | New |
| Internet connections | The kind *internet connection* (slice 2) and its fields (slice 5) | New |
| Other infrastructure assets | The kind *other*, custom fields (slices 2 and 6) | New |
| **Network documentation** | | |
| IP address assignments | Address assignments; managed devices' addresses shown from the inventory (slice 5) | New |
| Subnets, VLANs | Network documentation (slice 5) | New |
| DNS information | Subnets' DNS servers (slice 5); pages and references for the rest | Partly structured |
| DHCP information | Subnets (slice 5) | New |
| Gateway information | Subnets; reported gateways shown (slice 5) | New |
| ISP information, circuit identifiers | Internet connections' fields (slice 5) | New |
| Network equipment details | Assets and their pages (slice 2) | New |
| Network diagrams and attachments | Attachments and diagrams (slice 3) | New; no editor |
| **Asset records** | | |
| Manufacturer, model, serial number | Fields with sources (slice 2) | Agent-reported and entered, side by side |
| Purchase date, warranty expiration | Feature 1's slice 1 on this record (step 14) | Through the extension points |
| Assigned user | The assigned contact (slice 2) | New |
| Physical location | Site and place (slices 1 and 2) | New |
| Asset status | Status (slice 2) | New |
| Replacement history | History, replacement and merges (slice 2); component history in feature 1's slice 6 | New |
| Associated documentation | Page links (slice 2), attachments (slice 3) | New |
| **Documentation management** | | |
| Technicians create and edit | `doc.manage` (slice 1) | New |
| Notes and rich-text documentation | Markdown or plain text (slice 1) | New |
| File attachments | Slice 3 | New |
| Associate with customers, sites, devices and assets | Levels (slice 1); links (slice 2) | New |
| Searchable documentation | Search (slice 1) | New |
| Revision history | Revisions, a person's saves within 10 minutes coalesced (slice 1) | New |
| Who created or modified it | Revisions' authors; the audit log (slice 1) | New |
| Organization-specific documentation | Every row belongs to one organization (all slices) | New |
| **Special considerations** | | |
| Isolated between organizations | Row-level security and composite foreign keys (all slices) | Enforced by the database |
| Sensitive information restricted | Restricted pages, hidden by row-level security (slice 4); credentials (slice 7); site-scoped people see their sites only | New |
| Credentials not casually stored | The warning, redaction, references (slice 1); credentials only in the keystore (slice 7) | New |
| References or integrations with password managers | References (slice 1) | Integrations deferred to an ADR of their own |
| Accessible when the device is offline | Everything is on the server | Exists |

## Slices
Each merges and is verified on its own, at every level it touches.

1. **The customer record, pages and references** (step 13; needs
   nothing). Three pull requests: the customer record (contact
   information, contacts, addresses, places, hours, `doc.view` and
   `doc.manage`, `PRIVACY.md` in the owner's words); pages (revisions
   and coalescing, trash, redaction one at a time and at once, the
   export, notes moved, search with its excerpts, the quota and the
   deployment's limit for revisions, `react-markdown` and `remark-gfm` in
   `THIRD_PARTY_NOTICES.md`); references and the warning. Worth shipping
   alone: the requirement's aim is a picture of each customer without a
   separate documentation system.
2. **The asset record** (step 14), on F1's SMBIOS identifiers and slice
   1's places, with feature 1's slices 1 and 2 built on it. Its own pull
   request first: the record, sources and their states, assets for every
   device and the backfill from Go, link and merge proposals, the move
   trigger, history, page and reference links, the *Assets* report and
   assets in the export. If feature 1's ADR is not accepted when step 14
   starts, this slice merges alone; the extension points do not wait for
   it.
3. **Attachments and diagrams**: uploads received before their short
   transaction, downloads recorded first and streamed without one, the
   limits on reads, thumbnails, attachments in the quota and the export.
4. **Restricted pages**: the scope settings and the policies'
   condition.
5. **Network documentation.**
6. **Custom fields and CSV import.**
7. **Credentials**, after the keystore's reads (step 19) and step-up
   (step 17), if the owner wants them.

Slices 3 to 7 are at step 28 of the plan's order, "the later slices of
the twelve", each when its inputs exist.

## Consequences
* MSPs keep customers' contacts, locations, hours, documentation and
  equipment in EasyRMM, beside the devices, readable when a device is
  offline.
* Organization and site notes become pages; the API's `notes` fields go.
* Every device with an inventory has an asset record, which outlives it;
  feature 1 adds warranty to it without a second record.
* The console gains `react-markdown` and `remark-gfm` (102 packages).
* The database grows with pages, revisions and attachments; dumps,
  restores and the updater's copies take longer, within the quotas and
  the deployment's limit.
* `applyScope` sets two more settings in every transaction, for
  restricted pages.
* Credentials are not stored before the keystore, and only if the owner
  wants them; until then the warning and references.
* Contacts and documentation are personal data the operator holds:
  `PRIVACY.md` changes.
* `devices` gains two unique keys and a trigger; `assets` a trigger
  that follows a device's move.
* The audit log gains the actions in *Audit*.

## Testing
* **Integration tests** in Go against real PostgreSQL through `testdb`
  (`make test-db`), no mocks: the new services and the console's API in
  `server/internal/app`.
  * **Row-level security, per table**: each role at an organization, at a
    site and at another organization reads and writes only what it
    should; a site-scoped role sees no organization-level row; a page,
    asset, link, contact, place, reference or credential of another
    organization refused by the foreign keys through direct SQL as the
    application role (measured above).
  * **Pages**: a save with an old `baseVersion` refused, also after a
    coalesced save; revisions numbered, each with ID, author and
    SHA-256; coalescing within 10 minutes for the same author only, ended
    by a colleague's save, a restore or a redaction; the application role
    unable to update or delete a revision except through the two
    functions, and each function refusing what it must (the coalescing
    one anything but the author's current revision within the window,
    the redaction one the current revision), called directly as the
    application role; redaction one at a time and at once by an
    Organization Administrator only; the trash, its purge and emptying it
    early; control characters removed on save; notes moved by the
    migration and back by its `Down`; a marker in a title and a body, and
    the body's SHA-256, absent from every audit record; redaction
    clearing the text and the hash.
  * **`SECURITY DEFINER` functions**: ADR-0063's catalog test covers the
    new ones, failing when a `search_path` does not end with `pg_temp`.
  * **The export**: the ZIP's contents for an organization with every
    kind of record; restricted pages only for a caller who may read them;
    no credential's username or secret; one record before it starts.
  * **Search**: `EXPLAIN` as the application role at an organization's
    scope, a site's and the platform's, failing on a sequential scan of
    `doc_search_terms`; prefixes of three characters and more, shorter
    ones refused; several words; a subject's terms gone with it by the
    foreign key's cascade; no term from a line that looks like a secret,
    acknowledged or not; no credential's username or secret as a term;
    restricted pages left out without the permission, by the policy,
    through direct SQL as the application role.
  * **Excerpts**: a corpus of markup in page bodies (including
    `<img src=x onerror=…>`, which `ts_headline` keeps) comes back as
    text with only the two control characters as markers; a body over
    16 KiB excerpted from its first 16 KiB.
  * **The warning**: each pattern, line numbers only, acknowledged and
    not; only lines new or changed since `baseVersion`.
  * **Restricted pages**: with and without the scope settings, as the
    application role through direct SQL, the page, its revisions, links,
    attachments, chunks and terms invisible and visible together; the
    device's *Documentation* tab and the export without them.
  * **Assets**: made in the inventory's transaction and by the backfill
    from Go, with the same keys as an upload makes; agent and manual
    values never overwriting each other, the effective value by the
    catalogue's order; an agent field not *reported* never effective and
    never *differs*; a link proposal on a matching serial with the same
    or an empty manufacturer, none for another manufacturer or another
    organization; a device removed with its asset kept, the history
    recording it; a device enrolled again before the old one is removed
    giving a merge proposal when the old one goes; a merge moving every
    link and recording both IDs; no link or merge without an answer,
    even with equal SMBIOS UUIDs; a device moved to another site taking
    its asset along and clearing its place; replacement; the 2,000-agent
    drill with the copy, against the release before.
  * **Attachments**: the size cap, four uploads at once and two per
    person; the quota and the deployment's limit, with two uploads
    racing for the last of a quota; each allowed type, a mismatched one,
    a Markdown file beginning with `<!--` accepted, SVG never previewed,
    HTML refused; a name with path segments, control characters and
    non-ASCII letters cleaned and written by `mime.FormatMediaType`;
    the download's headers exactly; thumbnails bounded, none over 24
    megapixels or for WebP.
  * **Downloads hold nothing open**: a client that reads one chunk and
    pauses leaves no transaction open (`pg_stat_activity` shows none
    for the server) while another request appends an audit record
    without waiting; the record written before the first byte, and with
    appends made to fail, nothing sent; a chunk deleted mid-stream and a
    changed chunk each ending the stream short and logging the ID; the
    limits on reads answering `429`.
  * **Storage**: usage counted in the same transaction as what it
    counts; notices at 80% and 100%; saves refused past 110%; redaction
    and emptying the trash still allowed.
  * **Credentials**: every role, with and without step-up, stale step-up,
    no second factor; one record per read in the same transaction, and
    with appends made to fail, no secret answered; the rate limits and
    their notice; bounded refusals; a marker secret searched for in
    every list and answer, search terms, the CSV export, reports, the
    audit log, the server's log and errors; `Cache-Control: no-store`.
* **Page tests** (`vitest`): the renderer against a corpus of cross-site
  scripting vectors (OWASP's
  [XSS Filter Evasion Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html))
  leaving no `script` element, no `on*` attribute, no `javascript:`,
  `data:` or `vbscript:` URL and no image from outside; raw HTML shown as
  text; the editor's toolbar; the conflict view; controls hidden by
  permission.
* **The browser end-to-end test** (`make e2e`, `web/e2e/console.spec.ts`)
  against a real server:
  * slice 1: a Technician makes a page with a cross-site scripting
    payload and a `javascript:` link, saves it twice, sees two revisions
    and a diff, and finds it by search; no dialog opens and a flag the
    payload would set stays unset; a Read-Only user reads it with no
    *Edit*;
  * slice 1: links to `//host`, `/\host` and `/api/v1/…` in a page
    render as text, and a link to another page opens it;
  * slice 2: the simulated agent (`web/e2e/agent.ts`) reports a serial
    that matches an asset entered by hand, and the proposal is accepted;
  * slice 4: a Technician and a Site Administrator at the same site; the
    Technician finds no trace of a restricted page in lists, search, the
    device's tab or the export, and the Site Administrator reads it, one
    `doc_page.view_restricted` record per opening;
  * **slice 7, reveal and audit**: an Organization Administrator makes a
    credential whose secret is a random marker. A Read-Only user sees its
    name and no *Reveal* or *Copy*, and the API answers `403` to a direct
    request, recorded as `denied`. A Technician clicks *Reveal*, is asked
    to step up, enters the code from the test's authenticator
    (`web/e2e/authenticator.ts`), and sees the marker; clicks *Copy*, and
    the clipboard holds the marker while the page's DOM never does. The
    audit log page shows `credential.reveal` and `credential.copy` by the
    Technician, and none of its details holds the marker; search for the
    marker finds nothing; the CSV export lacks it.
* **Real systems**: slice 2 on the owner's test instance with its real
  devices, before the guide calls it verified; slice 3's previews in
  Chromium, Firefox and Safari; slice 7's *Copy* in the same three.
* The coverage floors in `scripts/ci/check-coverage.sh` hold for the
  packages touched.

## Owner questions
1. **Credentials in EasyRMM.** Should EasyRMM store customers'
   credentials at all (slice 7), which makes the keystore planned for
   feature 8 hold a second kind of secret beside BitLocker and LUKS
   recovery keys, under a key pair of its own, read daily by Technicians
   with step-up? Or should EasyRMM keep references to a password manager
   only, and leave the secrets there? The security survey behind the
   plan advised against storing them: "Feature 4's documentation
   credentials should stay out. The requirements ask that credentials
   are not stored casually and that password managers are integrated. A
   general password vault is a different product, with sharing, folders
   and user secrets", and at most "a narrow interface for a field or
   two, if the owner asks" (`survey-security.md:496-501`, one of the four
   surveys the plan was written from, which are not in the repository;
   the plan records the same advice,
   `docs/architecture/feature-plan-msp.md:568-570`). For storing them:
   Technicians would find a customer's firewall login beside the
   firewall's record, with every read recorded, instead of in a second
   product. Slice 7 is built only on a yes.
2. **`PRIVACY.md`'s wording** for contacts (the plan's question 11), and
   now for documentation and attachments, which the operator holds about
   customers' staff.
3. **Password manager integrations.** Which managers do the MSPs you
   have in mind use, and is an integration that reads from them worth
   an ADR of its own after references?
4. **Moving in from other tools.** Is importing from another
   documentation product's export (pages, assets, contacts) wanted, beyond
   slice 6's CSV?
