# ADR-0066: Customer documentation and asset records

* Status: Proposed (2026-11-21). Not implemented.
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
  across restores). ADR-0063 (who sees a job's output) is on a branch of
  its own and not merged, so it is cited without a link; this ADR reuses
  its bound on recorded refusals. The plan's
  [keystore](../feature-plan-msp.md#the-keystore-for-bitlocker-and-luks-recovery-keys)
  has no ADR yet.
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
  transaction at the system scope (`server/internal/inventory/service.go:65-87`).
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
  are capped at 16 KiB (`server/internal/audit/audit.go:69-73,112-114`);
  writers serialize on one lock (ADR-0007), so one record per action, not
  per click.
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
  35-37 and 49-56). The updater's backup holds both (ADR-0052).
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
  ([pkg.go.dev](https://pkg.go.dev/net/http#DetectContentType)).
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
  save a revision with its author; a trash; redaction of one revision by
  an administrator; search through a table of terms. Organization and
  site notes become pages.
* **Secrets in text** are warned about, never refused, and pointed at a
  password manager reference (slice 1), which holds where the secret is,
  never the secret.
* **The asset record** (slice 2, step 14): one record per piece of
  equipment or service, with or without an agent, made for every device
  that reports an inventory. Each identifying field keeps a value per
  source (the agent, entered by hand; feature 1 adds its own sources),
  and neither overwrites the other. A device links to at most one asset;
  a match by serial is proposed, never made silently. Assets outlive
  devices.
* **Credentials are not stored under `EASYRMM_SECRET_KEY`**, which sits
  beside every backup's dumps. If the owner wants them stored, they go
  into the keystore (slice 7), revealed under a permission of their own
  with step-up and one audit record per reveal, copied without display,
  and never in lists, search, exports or the audit log.
* **New permissions**: `doc.view` (all roles), `doc.manage` (Technician
  and above), `doc.view_restricted` (Site Administrator and above),
  `doc.credential_reveal` (Technician and above, with step-up).
* **Everything is in PostgreSQL**, attachments too, under row-level
  security with composite foreign keys, so backups and restores need no
  new step.

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
  does. Exports are the source.
* **The console renders with `react-markdown` and `remark-gfm`**, pinned,
  with these settings, each covered by tests:
  * no `rehype-raw` and no plugin that passes HTML through: HTML in a
    page is shown as text;
  * a `urlTransform` of EasyRMM's own: links only to `https`, `http`,
    `mailto` and the console's own paths (other pages, devices, assets);
    anything else becomes plain text. External links open in a new tab
    with `rel="noopener noreferrer"`;
  * images: none in slice 1 (`disallowedElements`); from slice 3, only
    the page's own image attachments, by an `attachment:` reference the
    transform maps to the preview endpoint. The content security policy
    already refuses images from anywhere but the console (`img-src 'self'
    data:`), so a page cannot carry a tracking image;
  * no custom component that writes HTML.

  The console's `script-src 'self'` stays as it is, so an inline handler
  or a `javascript:` URL that got through would still not run (MDN,
  above). The 102 packages are a cost, weighed under *Not chosen*.
* **Size**: a body of at most 256 KiB in UTF-8, a title of at most 200
  characters, an optional section name of at most 100 that groups pages
  on the organization's and site's lists, and a *pinned* flag.

**Revisions.**

* **Every save is a revision**, in `doc_page_revisions`: the page, its
  number, the title, format and body as saved, the body's SHA-256, the
  author's ID and name as they were then, the time and an optional note
  of up to 500 characters. The SHA-256 is shown with the revision, to
  whoever can read its text, and nowhere else: not in the audit log,
  which is forwarded and outlives pages, since a hash of a page that
  holds a short secret confirms a guess at it offline (ADR-0064's reason
  for one-off commands). The runtime role holds `INSERT` and `SELECT`
  only; revisions leave with their page, through the foreign key's
  cascade (measured above). The page row keeps the current title, body
  and revision number, so lists and reads do not touch revisions.
* **A save names the revision it was made from** (`baseRevision`). If the
  page has moved on, the save is refused (`409 page_changed`) with the
  newer revision's author and time, and the console shows both texts
  for the person to merge. Nothing is merged automatically.
* **History**: the console lists revisions, shows any one, and shows a
  line diff between two, computed in the browser. *Restore this
  revision* saves its text as a new revision; history is never rewritten.
* **Unsaved edits stay in the page only.** The console warns before
  leaving a page with changes and keeps no drafts in the browser's
  storage, which `PRIVACY.md` limits to the theme.
* **Saves are rate-limited** to 60 a minute per person, by the limiter
  per key the server already has (`server/internal/auth/ratelimit.go:13-35`).

**The trash, and redaction.**

* **Deleting a page moves it to the trash** for 30 days, restorable by
  `doc.manage` holders at its level; then a sweeper at the system scope
  deletes it with its revisions, recorded once per organization with the
  count.
* **Redacting a revision** empties its body, title and SHA-256 and marks
  it redacted, keeping its number, author, time and size: for a secret
  pasted into a page, which would otherwise stay in its history. A
  `SECURITY DEFINER` function owned by the owner role does it, since the
  runtime role cannot update revisions. Only `org.manage` holders at the
  page's organization (Organization Administrators and Super
  Administrators) may, with a reason, audited. The current revision
  cannot be redacted; the person saves a corrected revision first.
  Backups made before keep the text until they expire; the console and
  the guide say so.

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
Slice 1. *Decided in review*, on the measurement in *Context*.

* **A table of terms**, `doc_search_terms`: the organization, the site,
  what the row is about (a page, contact, site, place, reference; later
  an asset, subnet, VLAN, attachment name, custom field value, credential
  name), its ID, a `restricted` flag, and one term per row, `text COLLATE
  "C"`, with a btree on `(term, organization_id)` and one on the subject.
* **Terms are PostgreSQL's own**: `tsvector_to_array(to_tsvector('simple',
  …))` of the subject's searchable text, in the same transaction as the
  save that changed it. `simple` lower-cases and splits without stemming,
  so it serves every language that separates words with spaces. At most
  10,000 distinct terms per subject; terms over 64 bytes are skipped.
* **A query** (at most 200 characters and 8 words) matches subjects that
  have every word, each as a prefix: a range from the word to the word
  followed by the highest code point, which the index answers under
  row-level security at any scope. Results are read back under
  row-level security and the permission checks below, titles matched
  first, then the most recently changed; at most 50 a page, with a short
  excerpt from `ts_headline` for pages the caller can read.
* **Scope**: the caller's organizations, narrowed by organization, site
  or kind. Restricted pages are left out for callers without
  `doc.view_restricted` there (slice 4). A credential's secret, a
  reference's item and attachments' contents are never terms.
* **Not logged**: the query travels in the query string, which the
  request log leaves out.
* Slice 1's tests run `EXPLAIN` as the application role at an
  organization's scope and the platform's and fail on a sequential scan
  of the terms table, as ADR-0060's tests do.

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
else, so that lists sort and filter on indexed columns.

**Fields and their sources.**

* **One value per field and source**, in `asset_field_values`: the
  asset, the organization, the field, the source, the value as text in
  the field's form (dates as `YYYY-MM-DD`), when the source said it
  (`observed_at`), when and by whom it was recorded, and `detail`, JSON of
  at most 4 KiB for what a source wants to keep with it. Primary key
  `(asset_id, field, source)`.
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
  linked asset is therefore at its device's site, and follows it if
  devices can one day move between sites. A move between organizations
  is refused by the foreign keys while links exist; that feature's ADR
  decides what moves.
* **Every device that reports an inventory gets an asset**, made in the
  upload's transaction, linked, with the agent's values, unless a match
  is proposed (below). Slice 2's migration does the same for every
  device that has an inventory already, at the system scope as
  migrations that write rows do (`00023_retire_connector.sql:15`).
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
  same hardware gets a proposal for it.
* **Linking and unlinking by hand**: `doc.manage` and `device.edit` at
  the device's site; linking moves the asset to that site (and clears
  its place if the site changed). Unlinking keeps the agent's values as
  they were.

**History and replacement.**

* **`asset_events`**, append-only (the runtime role inserts and reads):
  the asset, the organization, the time, who (a person, the agent or the
  system), the kind (`created`, `field_changed`, `status_changed`,
  `linked`, `unlinked`, `device_removed`, `replaced`, `moved`), and for a
  field change the field, the source and the old and new values. Every
  change made by a person is also in the audit log; the agent's are only
  here, since they are not anyone's action.
* **Replacement**: *Replace with…* links a new asset to the old
  (`replaces_asset_id`), sets the old to *retired* and records both. A
  change of the agent's serial on a linked device (a new motherboard) is
  a `field_changed` event the asset's page shows as *the hardware's serial
  changed*. What counts as the same hardware beyond that, with F1's SMBIOS
  UUID, is feature 1's slice 6.
* **Deleting an asset** is for mistakes: only without a device, with a
  confirmation, audited with its identifying values; its history goes
  with it. Retired and disposed assets are kept.

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

1. **Fields**: feature 1 adds to the catalogue, for example the purchase
   date, warranty start, warranty end, warranty type and notes, ship
   date, each with its form, kinds and the order of its sources.
2. **Sources**: feature 1's migration extends the `source` check with its
   four labels from the plan (vendor API, vendor tool on the device,
   firmware estimate, entered by hand, which is `manual`). Each value's
   `observed_at` holds the source's own date (a vendor tool's last
   refresh), and `detail` a reference to the vendor's raw answer, which
   feature 1 keeps in a table of its own.
3. **Precedence** is per field, so feature 1 can put `manual` first for
   warranty dates, as the plan says ("A technician's correction is kept
   and labelled, never overwritten by a lookup").
4. **Status and age are computed by feature 1**, not stored here.
5. **History kinds**: `asset_events.kind` is checked against a list
   feature 1 extends (a lookup, for example).
6. **Identity**: `serial_key`, `maker_key` and F1's SMBIOS UUID as an
   agent value, for feature 1's replacement detection and its lookups,
   which key on the serial and, for some vendors, the product number
   (F1's SKU).
7. **Reports**: the *Assets* report's columns come from the catalogue,
   and feature 1's *Warranty and lifecycle* report reads the same tables.
8. **Alerts** are per device today (`alerts_active_key`,
   `00006_monitoring.sql:118`). An asset with a device can alert through
   it; feature 1's ADR decides what an asset without one does.
9. **Virtual machines** are the kind *virtual machine*, which feature 1
   skips.

### Attachments and diagrams
Slice 3. *Decided in review.*

* **What they attach to**: a page, an asset, or the organization or a
  site directly (contracts, diagrams). Immutable: a new version is a new
  upload marked as replacing the old.
* **Stored in PostgreSQL**, as signed builds are, in chunks of 1 MiB
  (`doc_attachment_chunks`) beside a metadata row (`doc_attachments`:
  the file name as given, the type found, the size, the SHA-256, who
  uploaded it and when, the subject). Chunks let the server stream an
  upload into one transaction and a download out of it without holding a
  whole file in memory, and keep lists from reading content. Row-level
  security on both, the chunks through their attachment. Backups and
  restores carry them with no new step, and a restore never leaves a
  file without its row or a row without its file. Files on the data root
  are under *Not chosen*.
* **Limits**: 25 MiB per file (read under `http.MaxBytesReader`, as
  signed builds are); a quota per organization, 1 GiB by default, which a
  Super Administrator changes per organization; at most four uploads at
  once per server process. Usage is shown on the organization's page and
  to Super Administrators across organizations.
* **Types, by allow-list**, checked twice: the extension, and the first
  bytes by `http.DetectContentType` and a few signatures of EasyRMM's own
  (ZIP-based Office and Visio files, PDF); a file whose bytes contradict
  its extension is refused. The list: PDF; PNG, JPEG, GIF, WebP; plain
  text, CSV, Markdown, log, JSON, XML, YAML and configuration files
  (`.conf`, `.cfg`, `.ini`); Word, Excel, PowerPoint and Visio
  (`.docx`, `.xlsx`, `.pptx`, `.vsdx`) and OpenDocument; diagrams
  (`.drawio`); SVG as a download only. Not executables, scripts, HTML or
  archives: an archive can carry any of those, and EasyRMM has no
  malware scanner to look inside.
* **Served only as downloads**: `GET /api/v1/attachments/{id}/content`
  answers `Content-Type: application/octet-stream`, `Content-Disposition:
  attachment` with the name sanitized (path segments, control characters,
  leading dots and `..` removed) in `filename` and `filename*` (RFC
  6266), `X-Content-Type-Options: nosniff`, `Content-Security-Policy:
  default-src 'none'; sandbox`, `Cache-Control: private, no-store`.
  Nothing is ever served as HTML or SVG on the console's origin.
* **Image previews**: PNG, JPEG, GIF and WebP whose first bytes say so,
  through `/preview` with their own type and the same headers, for the
  `attachment:` images in pages and a thumbnail on lists. Whether every
  supported browser shows an `<img>` whose answer says `attachment` is
  **to be confirmed** by slice 3's browser test; if one does not,
  previews answer `inline` with everything else the same.
* **Diagrams** are attachments (Visio, `.drawio`, PDF, images). An editor
  inside the console is not built: the usual embeddable one loads its
  code from its own site, which the content security policy refuses.
* **Deletion** moves to the trash for 30 days, as pages do; then the
  chunks go.
* **Every upload, download and deletion is audited** (file name, type,
  size, subject; the SHA-256 stays on the attachment's row, for the same
  reason as a revision's); previews are not, since a page shows them
  whenever it is read.

### Restricted pages
Slice 4. *Decided in review.*

* A page can be marked **restricted** by `doc.manage` holders who also
  hold `doc.view_restricted` there. Its title, body, revisions,
  attachments and search terms are then read only with
  `doc.view_restricted`: Site Administrators and above. Others see
  neither the page nor that it exists, in lists, search and links.
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
  policy of its own: its permission, step-up, rate limits, no two-person
  rule by default, no notice per read. Whether the console seals to the
  organization's public key, so that the main server never holds a new
  credential's plaintext, is that ADR's choice. Its on-host protection
  applies unchanged.
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
  the credential's organization and site, with its ID and name and who;
  if the record cannot be written, nothing is answered.
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
  reports, notifications, the audit log's details, logs or errors. A
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
* Redacting a revision needs `org.manage`; custom field definitions
  `org.manage` or `settings.manage`; an organization's attachment quota
  `settings.manage`.
* **Exports** (the *Assets* report, contacts as CSV) need `doc.view` and
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
  `asset_events`, `asset_link_proposals`): a policy that reads through
  the parent (`EXISTS (SELECT 1 FROM parent WHERE id = …)`), as
  `device_removals` does. They still carry `organization_id` for their
  composite foreign keys.
* **Shared custom field definitions** (no organization): read by anyone
  who holds `doc.view` anywhere, as the shared script library is read,
  and written at the platform scope only.
* **Every link names its organization** in a composite foreign key, so
  that the database refuses a page, asset, contact, place, reference,
  credential or device of another organization, whatever the server
  asks (measured above).
* **The restricted flag and permissions are the service's**, as roles
  always are (`docs/security/rbac.md:37-38`); row-level security is the
  tenant wall beneath them.

### Audit
*Decided in review.* Every change and every read of a secret or a
restricted page is recorded, in the change's transaction. Details carry
identifiers, names and titles, field names and sizes; never page text
or its hash, contact details, addresses, notes, field values typed by
people, file contents or secrets, since records are forwarded as written
(ADR-0023).

| Action | When | Details |
|---|---|---|
| `organization.details_update`, `site.details_update` | Contact information, address, hours | Field names |
| `site_place.create`, `.update`, `.delete` | Places | Name, kind |
| `contact.create`, `.update`, `.delete` | Contacts | Contact's name, field names, priority and emergency |
| `doc_page.create`, `.update` | Each save | Title, revision number, body size, whether a secret warning was acknowledged and on how many lines |
| `doc_page.move`, `.delete`, `.restore`, `.purge` | Level changes, trash | Title, from and to; purge counted per organization |
| `doc_page.revision_redact` | Redaction | Title, revision number, reason |
| `doc_page.view_restricted` | Each read of a restricted page | Title, revision number |
| `credential_reference.create`, `.update`, `.delete` | References | Name, manager |
| `asset.create`, `.update`, `.delete`, `.link`, `.unlink`, `.replace` | Asset changes by people | Asset's name, kind, field names; device for links |
| `asset.link_proposal_answer` | Proposals answered | Asset, device, the answer |
| `asset.import`, `contact.import` | CSV imports | Counts created and changed |
| `report.export` | Asset and contact exports | As today |
| `doc_attachment.upload`, `.download`, `.delete` | Attachments | File name, type, size, subject |
| `custom_field.create`, `.update`, `.delete` | Definitions | Label, type, subject |
| `credential.create`, `.update`, `.delete` | Credentials | Name, kind, whether the secret changed |
| `credential.reveal`, `credential.copy` | Each read of a secret, and each refusal (`denied`) | Credential's ID and name |

The agent's changes to an asset are in its history, not the audit log.
Searches and ordinary page reads are not audited: there are too many and
they reveal nothing beyond what `doc.view` already allows.

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
| 1 | `doc_pages` (with `deleted_at`, `restricted` from slice 4) | all |
| 1 | `doc_page_revisions`; the redaction function | `INSERT`, `SELECT`; execute the function |
| 1 | `doc_search_terms` | all |
| 1 | `credential_references` | all |
| 2 | `devices`: `UNIQUE (organization_id, id)`, `UNIQUE (organization_id, site_id, id)`; a `BEFORE DELETE` trigger | as today |
| 2 | `assets`, `asset_field_values`, `asset_link_proposals`, `doc_page_links`, links from references to assets | all |
| 2 | `asset_events` | `INSERT`, `SELECT` |
| 3 | `doc_attachments`, `doc_attachment_chunks`; quota per organization | all |
| 4 | `doc_pages.restricted` | as above |
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
  /organizations/{id}/pages` (`?siteId=&section=&deleted=`); `GET`, `PUT`,
  `DELETE /pages/{id}`; `POST /pages/{id}/restore`; `POST
  /pages/{id}/move`; `GET /pages/{id}/revisions`; `GET
  /pages/{id}/revisions/{n}`; `POST /pages/{id}/revisions/{n}/redact`;
  `GET /documentation/search?q=&organizationId=&siteId=&kind=`; `GET`,
  `POST /organizations/{id}/credential-references`; `PATCH`, `DELETE
  /credential-references/{id}`.
* **Slice 2**: `GET`, `POST /organizations/{id}/assets` (filters by site,
  kind, status, linked or not); `GET`, `PATCH`, `DELETE /assets/{id}`;
  `GET /assets/{id}/history`; `POST /assets/{id}/link`, `/unlink`,
  `/replace`; `GET /devices/{id}/asset`; `POST
  /devices/{id}/asset-proposal` with the answer; `PUT /pages/{id}/links`;
  the *Assets* report through `/reports`.
* **Slice 3**: `POST /attachments?subject=page:{id}` (or `asset:`,
  `site:`, `organization:`), the raw body, the name in `X-File-Name`;
  `GET /attachments/{id}`, `/content`, `/preview`; `DELETE
  /attachments/{id}`; `POST /attachments/{id}/restore`.
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
* **A device's page**: an *Asset* card on *Overview*, with any proposal,
  and a *Documentation* tab (slice 2).
* **An asset's page**: each field with its effective value, its source
  and the other sources' values; status, location, assigned contact;
  history; pages, attachments, references and credentials.
* Controls hidden where the permission is missing; the server decides
  regardless.

### Backups and restore
*Decided in review.*

* **No new backup part.** Everything is in the `easyrmm` database, which
  the guide's `pg_dump` already copies, attachments included; nothing is
  written to the data root. The guide's table keeps its rows. It gains a
  note that attachments grow the dumps, the restore and the updater's
  copy of the data root before each upgrade (ADR-0052), with the
  quota's numbers.
* **Credentials** (slice 7) follow the keystore's backup rules: each
  key-encryption key version apart from the data and kept as long as a
  backup needs it. A restore without the version its data needs starts
  with reveals turned off and says so, as the keystore's restore does.
* **After a restore**, documentation changed after the backup is lost.
  If the audit log was forwarded (ADR-0023), it names each lost revision
  by its page, number, author, time and size, never its text. ADR-0062
  keeps the audit IDs from repeating.
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
* **Linking a device to an asset by serial without asking**: serials
  repeat; a wrong link would put one computer's warranty and history on
  another.
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
* **Backups keep what was deleted or redacted** until they expire.
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
  does not.

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
| Replacement history | History and replacement (slice 2); feature 1's slice 6 | New |
| Associated documentation | Page links (slice 2), attachments (slice 3) | New |
| **Documentation management** | | |
| Technicians create and edit | `doc.manage` (slice 1) | New |
| Notes and rich-text documentation | Markdown or plain text (slice 1) | New |
| File attachments | Slice 3 | New |
| Associate with customers, sites, devices and assets | Levels (slice 1); links (slice 2) | New |
| Searchable documentation | Search (slice 1) | New |
| Revision history | Revisions (slice 1) | New |
| Who created or modified it | Revisions' authors; the audit log (slice 1) | New |
| Organization-specific documentation | Every row belongs to one organization (all slices) | New |
| **Special considerations** | | |
| Isolated between organizations | Row-level security and composite foreign keys (all slices) | Enforced by the database |
| Sensitive information restricted | Restricted pages (slice 4); credentials (slice 7); site-scoped people see their sites only | New |
| Credentials not casually stored | The warning, redaction, references (slice 1); credentials only in the keystore (slice 7) | New |
| References or integrations with password managers | References (slice 1) | Integrations deferred to an ADR of their own |
| Accessible when the device is offline | Everything is on the server | Exists |

## Slices
Each merges and is verified on its own, at every level it touches.

1. **The customer record, pages and references** (step 13; needs
   nothing). Three pull requests: the customer record (contact
   information, contacts, addresses, places, hours, `doc.view` and
   `doc.manage`, `PRIVACY.md` in the owner's words); pages (revisions,
   trash, redaction, notes moved, search); references and the warning.
   Worth shipping alone: MSPs keep this in a second product today.
2. **The asset record** (step 14), on F1's SMBIOS identifiers and slice
   1's places, with feature 1's slices 1 and 2 built on it. Its own pull
   request first: the record, sources, assets for every device and the
   backfill, proposals, history, page and reference links, the *Assets*
   report. If feature 1's ADR is not accepted when step 14 starts, this
   slice merges alone; the extension points do not wait for it.
3. **Attachments and diagrams.**
4. **Restricted pages.**
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
  restores and the updater's copies take longer, within the quota.
* Credentials are not stored before the keystore, and only if the owner
  wants them; until then the warning and references.
* Contacts and documentation are personal data the operator holds:
  `PRIVACY.md` changes.
* `devices` gains two unique keys and a trigger.
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
  * **Pages**: a save with an old `baseRevision` refused; revisions
    numbered, each with author and SHA-256; the application role unable
    to update or delete a revision; redaction by an Organization
    Administrator only, never the current revision; the trash and its
    purge; notes moved by the migration and back by its `Down`; a marker
    in a body, and the body's SHA-256, absent from every audit record;
    redaction clearing the text and the hash.
  * **Search**: `EXPLAIN` as the application role at an organization's
    scope and the platform's, failing on a sequential scan of
    `doc_search_terms`; prefixes; several words; restricted pages left
    out without the permission; a credential's marker never a term.
  * **The warning**: each pattern, line numbers only, acknowledged and
    not.
  * **Assets**: made in the inventory's transaction and by the backfill;
    agent and manual values never overwriting each other, the effective
    value by the catalogue's order; a proposal on a matching serial with
    the same or an empty manufacturer, none for another manufacturer or
    another organization; a device removed with its asset kept, the
    history recording it; replacement; the 2,000-agent drill with the
    copy, against the release before.
  * **Attachments**: the size cap, the quota, four uploads at once; each
    allowed type, a mismatched one, SVG never previewed, HTML refused;
    the download's headers exactly; chunks streamed, the SHA-256 checked
    after; every role.
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
  * slice 2: the simulated agent (`web/e2e/agent.ts`) reports a serial
    that matches an asset entered by hand, and the proposal is accepted;
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
   recovery keys, read
   daily by Technicians with step-up? Or should EasyRMM keep references
   to a password manager only, and leave the secrets there?
2. **`PRIVACY.md`'s wording** for contacts (the plan's question 11), and
   now for documentation and attachments, which the operator holds about
   customers' staff.
3. **Password manager integrations.** Which managers do the MSPs you
   have in mind use, and is an integration that reads from them worth
   an ADR of its own after references?
4. **Moving in from other tools.** Is importing from another
   documentation product's export (pages, assets, contacts) wanted, beyond
   slice 6's CSV?
