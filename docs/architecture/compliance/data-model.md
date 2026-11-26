# Compliance engine: data model, mappings, licence metadata, packs

Appendix to [ADR-0078](../adr/0078-compliance-engine.md). Design only. The SQL
is the shape the slices build, not a file that exists yet; column details can
change in review, the relationships and constraints should not. Table
conventions follow `server/migrations/00001_core.sql` and `00027_hardening.sql`:
goose up and down, row-level security forced, `easyrmm_scope_all()` for
system writes, `easyrmm_scope_ids('easyrmm.scope_orgs')` for organization
reads.

## 3. The security control data model

Deliverable 3. A control is one technical setting or condition. It is global
and read-only to the application role.

| Field | Meaning |
|---|---|
| `id` | stable internal id, `<platform>.<area>.<setting>`, for example `win.accounts.password-history`; never reused |
| `version` | integer; bumped when detection, expected value or applicability changes |
| `title`, `description` | our own words |
| `platforms` | `{"os":"windows","editions":["workstation","server"],"min_build":19045}` and similar |
| `scopes` | which computers: `workstation`, `member_server`, `domain_controller`, `any` |
| `severity` | `info`, `low`, `medium`, `high`, `critical`, our judgement with a stated reason |
| `executor` | `hardening` (ADR-0054 or 0051 script setting), `winmod` (ADR-0073 read action), `facts` (stored Facts or inventory), `server` (EasyRMM's own data), `attestation` (manual) |
| `executor_ref` | for `hardening`: `{"module":"accounts","setting":"accounts-history"}` (the id in `windows-settings.json`); for `winmod`: `{"module","action"}` |
| `detect` | our description of the detection logic, in words, and the structured parameters the executor needs |
| `expected` | the expected value as data: `{"op":">=","value":24}`, a set, a range, or `"absent"` |
| `applicability` | conditions (role, edition, domain joined, feature present); a control not applicable returns `not_applicable` with the reason |
| `remediation_text` | our own manual steps, for the console when there is no apply |
| `apply_supported`, `undo_kind` | whether the fix exists, and `restore_backup`, `reverse_action` or `none` |
| `risk_tier` | `T0` to `T3` (ADR-0078 section 6) |
| `warning_id` | which versioned warning text the agreement shows |
| `needs_restart`, `preconditions` | for the console and the server's precheck |
| `author`, `provenance`, `licence_class`, `review_state`, `pack_id` | section 5 |
| `references` | authoritative public documentation, as rows below |

```sql
CREATE TABLE compliance_sources (
    id              text PRIMARY KEY,   -- 'nist-800-171r2', 'stig-win11-v2r11', 'ms-baseline-2025'
    title           text NOT NULL,
    publisher       text NOT NULL,
    url             text NOT NULL,
    licence_class   text NOT NULL CHECK (licence_class IN ('ORIGINAL','PUBLIC_DOMAIN','OPEN_LICENSE',
                        'ATTRIBUTION_REQUIRED','NONCOMMERCIAL','COMMERCIAL_LICENSE_REQUIRED','RESTRICTED')),
    licence_spdx    text,               -- 'CC-BY-4.0', 'MIT', null for government works
    licence_note    text NOT NULL,      -- why this class, citing the licence page and its retrieval date
    attribution     text,               -- exact required text when ATTRIBUTION_REQUIRED
    retrieved_at    date NOT NULL,
    sha256          text,               -- of the file used when it is a file
    review_state    text NOT NULL DEFAULT 'none' CHECK (review_state IN ('none','needed','cleared')),
    review_ref      text,               -- required when 'cleared'
    CHECK (review_state <> 'cleared' OR review_ref IS NOT NULL)
);

CREATE TABLE compliance_packs (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    key             text NOT NULL,      -- 'cmmc-l2', 'cis-xref', 'library-windows'
    version         text NOT NULL,
    kind            text NOT NULL CHECK (kind IN ('library','framework','profile','xref','customer')),
    title           text NOT NULL,
    origin          text NOT NULL CHECK (origin IN ('builtin','customer')),
    organization_id uuid REFERENCES organizations (id) ON DELETE CASCADE,  -- customer packs only
    licence_class   text NOT NULL,      -- the most restrictive class of anything inside
    source_id       text REFERENCES compliance_sources (id),
    review_state    text NOT NULL DEFAULT 'none' CHECK (review_state IN ('none','needed','cleared')),
    review_ref      text,
    manifest_sha256 text NOT NULL,
    signature       bytea,              -- release key; null for customer packs
    enabled         boolean NOT NULL DEFAULT true,
    installed_by    uuid REFERENCES users (id),
    installed_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (key, version, organization_id),
    CHECK (origin = 'builtin' OR kind = 'customer')   -- a customer can install mappings and text, not a library
);

CREATE TABLE compliance_controls (
    id              text NOT NULL CHECK (id ~ '^[a-z][a-z0-9.-]{2,95}$'),
    version         integer NOT NULL CHECK (version >= 1),
    pack_id         uuid NOT NULL REFERENCES compliance_packs (id) ON DELETE CASCADE,
    title           text NOT NULL,
    description     text NOT NULL,
    platforms       jsonb NOT NULL,
    scopes          text[] NOT NULL,
    severity        text NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
    executor        text NOT NULL CHECK (executor IN ('hardening','winmod','facts','server','attestation')),
    executor_ref    jsonb NOT NULL,
    detect          jsonb NOT NULL,
    expected        jsonb NOT NULL,
    applicability   jsonb NOT NULL DEFAULT '{}',
    remediation_text text NOT NULL,
    apply_supported boolean NOT NULL,
    undo_kind       text NOT NULL CHECK (undo_kind IN ('restore_backup','reverse_action','none')),
    risk_tier       text NOT NULL CHECK (risk_tier IN ('T0','T1','T2','T3')),
    warning_id      text,
    needs_restart   boolean NOT NULL DEFAULT false,
    preconditions   jsonb NOT NULL DEFAULT '[]',
    author          text NOT NULL,
    provenance      jsonb NOT NULL,     -- see section 5
    licence_class   text NOT NULL,
    review_state    text NOT NULL DEFAULT 'none',
    PRIMARY KEY (id, version),
    CHECK (risk_tier = 'T0' OR apply_supported OR remediation_text <> ''),
    CHECK (NOT apply_supported OR warning_id IS NOT NULL),
    CHECK (risk_tier <> 'T0' OR NOT apply_supported)
);

CREATE TABLE compliance_control_refs (
    control_id   text NOT NULL,
    version      integer NOT NULL,
    kind         text NOT NULL CHECK (kind IN ('stig','ms_baseline','nist','vendor_doc','rfc','man_page','cve')),
    ref          text NOT NULL,        -- 'WN11-AC-000020', 'sshd_config(5)'
    url          text,
    meets        text CHECK (meets IN ('meets','differs','not_set')),  -- STIG relation, as cites.json
    FOREIGN KEY (control_id, version) REFERENCES compliance_controls (id, version) ON DELETE CASCADE
);
```

The controls table has **no framework column**. `cites.json` (module to STIG
rule: meets, differs, not set) and `related.json` stay as they are for the
"related controls" panel and become the source for generating `references`.

### Profiles

```sql
CREATE TABLE compliance_profiles (
    key         text NOT NULL,         -- 'win11-baseline', 'cmmc-l2-assessment'
    version     text NOT NULL,
    pack_id     uuid NOT NULL REFERENCES compliance_packs (id) ON DELETE CASCADE,
    title       text NOT NULL,
    platform    jsonb NOT NULL,
    framework_key text,                -- set when the profile drives a framework assessment
    PRIMARY KEY (key, version)
);
CREATE TABLE compliance_profile_controls (
    profile_key text NOT NULL, profile_version text NOT NULL,
    control_id  text NOT NULL,
    params      jsonb NOT NULL DEFAULT '{}',   -- a stricter value for this profile (PCI: length 12)
    PRIMARY KEY (profile_key, profile_version, control_id),
    FOREIGN KEY (profile_key, profile_version) REFERENCES compliance_profiles (key, version) ON DELETE CASCADE
);
```

A profile may override `expected` through `params` only within the control's
declared bounds; the override is recorded on the result so the report says
which value the computer was measured against.

## 4. The framework mapping model

Deliverable 4. A framework is data; a mapping is a separate row that belongs
to a pack.

```sql
CREATE TABLE compliance_frameworks (
    key           text NOT NULL,       -- 'nist-800-171r2', 'cmmc-l2', 'hipaa-security', 'cis-benchmark-xref'
    version       text NOT NULL,
    title         text NOT NULL,
    publisher     text NOT NULL,
    source_id     text NOT NULL REFERENCES compliance_sources (id),
    licence_class text NOT NULL,
    text_policy   text NOT NULL CHECK (text_policy IN ('full','ids_and_own_titles','ids_only')),
    pack_id       uuid NOT NULL REFERENCES compliance_packs (id) ON DELETE CASCADE,
    PRIMARY KEY (key, version)
);

CREATE TABLE compliance_requirements (
    framework_key text NOT NULL, framework_version text NOT NULL,
    req_id        text NOT NULL,        -- '3.5.8', '164.312(a)(2)(iii)', 'CC6.1', 'CIS 1.1.1'
    parent_id     text,
    title_own     text NOT NULL,        -- our short title, always
    text_full     text,                 -- only if text_policy = 'full' (NIST, eCFR)
    class         text NOT NULL CHECK (class IN ('technical','partly','organisational')),
    weight        integer,              -- DoD methodology; null elsewhere
    flags         jsonb NOT NULL DEFAULT '{}',  -- {"l1":true,"basic":true,"poam_barred":false}
    PRIMARY KEY (framework_key, framework_version, req_id),
    FOREIGN KEY (framework_key, framework_version) REFERENCES compliance_frameworks (key, version) ON DELETE CASCADE
);
-- text_full is allowed only when the framework's text_policy is 'full'; the loader enforces it
-- and a deferred constraint trigger repeats it.

CREATE TABLE compliance_objectives (       -- SP 800-171A objectives, where a framework has them
    framework_key text NOT NULL, framework_version text NOT NULL,
    req_id text NOT NULL, obj_id text NOT NULL,   -- '3.5.8[a]'
    text text, methods text[] NOT NULL DEFAULT '{}',   -- examine, interview, test
    PRIMARY KEY (framework_key, framework_version, req_id, obj_id),
    FOREIGN KEY (framework_key, framework_version, req_id)
        REFERENCES compliance_requirements ON DELETE CASCADE
);

CREATE TABLE compliance_mappings (
    pack_id        uuid NOT NULL REFERENCES compliance_packs (id) ON DELETE CASCADE,
    framework_key  text NOT NULL, framework_version text NOT NULL,
    req_id         text NOT NULL,
    obj_id         text,                  -- null = the requirement as a whole
    control_id     text NOT NULL,
    relation       text NOT NULL CHECK (relation IN ('satisfies_objective','evidence_for','related')),
    note           text,                  -- our words: what this control shows and what it does not
    licence_class  text NOT NULL,
    provenance     jsonb NOT NULL,
    FOREIGN KEY (framework_key, framework_version, req_id) REFERENCES compliance_requirements ON DELETE CASCADE
);
CREATE UNIQUE INDEX compliance_mappings_unique ON compliance_mappings
    (pack_id, framework_key, framework_version, req_id, coalesce(obj_id, ''), control_id);
CREATE INDEX compliance_mappings_control ON compliance_mappings (control_id);
```

* **A control maps to many requirements, a requirement to many controls.**
  One password-history control maps to 800-171 3.5.8, a CMMC practice, a
  STIG rule, a HIPAA specification and a CIS recommendation number, each in
  its own pack. Nothing is duplicated.
* **`relation` is the guard against over-claiming.** Only
  `satisfies_objective` lets a passing control count toward an objective, and
  only for the objective named. `evidence_for` attaches the result as
  evidence without moving a determination. `related` is for the "related
  controls" panel only. A requirement with only `related` mappings can never
  show as checked.
* **Each framework keeps its own criteria.** Objectives are per framework;
  the engine never copies a determination from one framework to another. A
  host that meets the control meets *that framework's objective* only if
  the pack says `satisfies_objective` for that objective.
* **CIS is a framework like any other**, with `text_policy = ids_only`: the
  requirement row holds the recommendation number and *our* title, never
  CIS's title, description or rationale. The pack's licence is
  `RESTRICTED`-adjacent in effect, so it carries `review_state = needed`
  (ADR-0078 section 10).
* **Generated mappings.** `related.json` (STIG to CCI to 800-53 to 800-171)
  remains generated and feeds `related` mappings only. `satisfies_objective`
  mappings are hand-written, reviewed, in our words (the research's
  recommendation).

## 5. The licensing metadata model

Deliverable 5.

### Classes (the requirements' list)

| Class | Meaning | In a commercial build |
|---|---|---|
| `ORIGINAL` | independently authored by EasyRMM | yes |
| `PUBLIC_DOMAIN` | verified public-domain content (US government works, 17 U.S.C. 105; NIST publications) | yes |
| `OPEN_LICENSE` | an identified permissive licence (MIT, BSD, Apache-2.0) | yes, with its NOTICE |
| `ATTRIBUTION_REQUIRED` | requires attribution (for example CC BY 4.0) | yes, with attribution text in the product and `NOTICE` |
| `NONCOMMERCIAL` | restricted to non-commercial use | **no** |
| `COMMERCIAL_LICENSE_REQUIRED` | needs additional permission | **no** |
| `RESTRICTED` | cannot be redistributed without authorization | **no** |

The class of a pack is the most restrictive class of any item it contains
(ordered `ORIGINAL`, `PUBLIC_DOMAIN`, `OPEN_LICENSE`, `ATTRIBUTION_REQUIRED`,
then the three restricted classes). The loader computes it and refuses a pack
that declares a less restrictive one.

Copyleft is deliberately not a class that can be embedded: GPL and AGPL
content (Wazuh) and ShareAlike content (CC BY-SA, CC BY-NC-SA) are classified
`RESTRICTED` for our purposes, and the build refuses them. ShareAlike is not
`OPEN_LICENSE` here (*decided in review*), because it would make the embedding
product an adaptation of the content; whether that is so is a question for
counsel, so we avoid it.

### Review state

Independent of the class: `none`, `needed` (a person must decide before a
commercial release), `cleared` (with `review_ref`, an opinion or agreement id
the record points to). Items flagged `needed` fail the commercial build until
cleared. This is requirement 10 of section 3 of the requirements.

### Provenance (on every control and mapping)

```json
{
  "author": "EasyRMM",
  "authored_on": "2026-12-03",
  "method": "written from vendor documentation and observed behaviour",
  "sources": [
    {"source_id": "ms-docs-password-policy", "locator": "Password must meet complexity requirements"},
    {"source_id": "stig-win11-v2r11", "locator": "WN11-AC-000020"}
  ],
  "derived_from_content": false,
  "reviewer": "name or id of the person who checked it",
  "reviewed_on": "2026-12-04",
  "licence_class": "ORIGINAL"
}
```

* `derived_from_content` is **false** for every embedded control and must be
  asserted by the author. The check refuses `true` for restricted sources.
* **The independence rule for authors.** An author writes a check from the
  setting's vendor documentation and the framework's public requirement, not
  from a benchmark document. The review confirms that the title,
  description, remediation text and expected value are in our own words and
  that the value is a fact (Microsoft's, DISA's or a vendor's) rather than a
  benchmark's selection. A second person checks wording distance (a
  checklist in the PR template, not an automated claim of originality).
* **Attribution metadata** (`attribution` on the source) is shown in the
  console's "About this content" panel and in `NOTICE`.

## 6. The content package architecture

Deliverable 6.

### Layout

```
server/internal/compliance/content/
  manifest.json                 every file: path, kind, licence_class, source_id,
                                review_state, review_ref, sha256, author
  sources.json                  the compliance_sources rows
  controls/win-*.json, linux-*.json
  packs/<key>-<version>.json    a pack: kind, mappings, frameworks, requirements, profiles
  warnings/*.json               fix warning texts, versioned
  templates/                    SSP, POA&M, policy skeletons (C5)
  NOTICE.generated              from sources with attribution or open licences
```

### Pack file (data only, never code)

```json
{
  "pack": {"key": "nist-800-171r2", "version": "2025.1", "kind": "framework",
           "licence_class": "PUBLIC_DOMAIN", "source_id": "nist-800-171r2"},
  "framework": {"key": "nist-800-171r2", "version": "r2", "text_policy": "full"},
  "requirements": [ {"req_id": "3.5.8", "title_own": "...", "class": "technical", "weight": 1} ],
  "objectives":   [ {"req_id": "3.5.8", "obj_id": "3.5.8[a]", "methods": ["examine","test"]} ],
  "mappings":     [ {"req_id": "3.5.8", "obj_id": "3.5.8[b]", "control_id": "win.accounts.password-history",
                     "relation": "satisfies_objective", "note": "..."} ],
  "profiles":     []
}
```

A pack can add frameworks, requirements, mappings and profiles. It **cannot
add a control with an executor of its own**: controls come from the library
pack (`kind = library`), which is code-reviewed and signed with the release.
A customer pack can include requirement text and mappings to library
controls; it cannot include a script, a detection command or a fix.

### Lifecycle

1. **Load**: at startup the loader reads the manifest, verifies each hash and
   signature, checks classes against the edition, and inserts or updates the
   pack by `(key, version)`. A failure stops the pack, not the server, and is
   logged and shown in Settings.
2. **Enable per organization**: a pack must be enabled for an organization to
   be offered (`compliance_org_packs`).
3. **Update**: a new version is a new row; old results keep the control
   version they ran. Removing a pack removes its mappings, not results.
4. **Customer packs**: installed from Settings (`compliance.admin`), validated
   (schema, no executable fields, size cap), stored with `origin = customer`,
   the installer's recorded statement "I hold a licence that permits this
   content to be used here", scope server or one organization, excluded from
   exports and OSCAL by default, and never merged into embedded content. The
   product does not parse CIS-CAT output or any member product's files in
   this ADR; that is a later pack kind, after counsel (research option C).

### Per-organization state

```sql
CREATE TABLE compliance_org_settings (
    organization_id uuid PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
    enabled         boolean NOT NULL DEFAULT false,
    freshness_days  integer NOT NULL DEFAULT 30 CHECK (freshness_days BETWEEN 1 AND 365),
    scan_schedule   text,                         -- cron-like, null = manual only
    require_approval jsonb NOT NULL DEFAULT '{"T2":false,"T3":false}',
    retention_years integer NOT NULL DEFAULT 6 CHECK (retention_years BETWEEN 1 AND 50),  -- pending owner confirmation
    updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE compliance_org_packs (
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    pack_id         uuid NOT NULL REFERENCES compliance_packs (id) ON DELETE CASCADE,
    enabled_by      uuid REFERENCES users (id), enabled_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, pack_id)
);
```

## Results (C1) and the fix queue (C2)

```sql
CREATE TABLE compliance_scans (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    started_by uuid REFERENCES users (id), trigger text NOT NULL CHECK (trigger IN ('schedule','manual','verify')),
    selection jsonb NOT NULL,                 -- profile or framework, devices
    state text NOT NULL CHECK (state IN ('planned','running','done','partial','failed')),
    started_at timestamptz NOT NULL DEFAULT now(), finished_at timestamptz,
    result_hash text                           -- hash of the result rows, evidence for C5
);
CREATE TABLE compliance_scan_jobs (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    scan_id         uuid NOT NULL REFERENCES compliance_scans ON DELETE CASCADE,
    device_id       uuid NOT NULL REFERENCES devices ON DELETE CASCADE,
    job_id          uuid REFERENCES jobs ON DELETE SET NULL,   -- nullable, not part of any key
    modules         text[] NOT NULL DEFAULT '{}',               -- the re-run unit when a result was truncated
    UNIQUE (scan_id, device_id, modules));

-- Append-only: one row per scan, device and control. A scan's rows are never changed,
-- so a snapshot hash over them is reproducible (C5 evidence).
CREATE TABLE compliance_results_history (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    scan_id         uuid NOT NULL REFERENCES compliance_scans (id) ON DELETE CASCADE,
    device_id       uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    control_id      text NOT NULL, control_version integer NOT NULL,
    state text NOT NULL CHECK (state IN ('in_place','partly','not_in_place','not_applicable',
                  'managed_elsewhere','not_supported','half_applied','failed','unknown')),
    observed jsonb, expected jsonb, owner jsonb, param_override jsonb,
    job_id uuid REFERENCES jobs (id) ON DELETE SET NULL,
    checked_at timestamptz NOT NULL,
    UNIQUE (scan_id, device_id, control_id)
);   -- insert-only (trigger refuses UPDATE and DELETE except by retention purge)

-- The latest result per device and control, as a view over the history (no second copy).
-- Reading it is the compliance tab's query; 'stale' is computed from checked_at.
CREATE VIEW compliance_results WITH (security_invoker = true) AS
    SELECT DISTINCT ON (device_id, control_id) *
      FROM compliance_results_history ORDER BY device_id, control_id, checked_at DESC, id DESC;


CREATE TABLE compliance_fix_items (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    device_id uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    control_id text NOT NULL, control_version integer NOT NULL, risk_tier text NOT NULL,
    current_value jsonb, target_value jsonb, warnings jsonb NOT NULL, preconditions jsonb NOT NULL,
    state text NOT NULL CHECK (state IN ('open','awaiting_approval','agreed','dispatched','applied',
          'verified','not_verified','failed','undone','declined','expired')),
    job_id uuid REFERENCES jobs (id) ON DELETE SET NULL, result jsonb,
    created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX compliance_fix_open ON compliance_fix_items (device_id, control_id)
    WHERE state IN ('open','awaiting_approval','agreed','dispatched');

CREATE TABLE compliance_agreements (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    item_id uuid NOT NULL REFERENCES compliance_fix_items (id) ON DELETE CASCADE,
    role text NOT NULL CHECK (role IN ('requester','approver')),
    user_id uuid NOT NULL REFERENCES users (id),
    warning_id text NOT NULL, warning_sha256 text NOT NULL, control_version integer NOT NULL,
    typed_text text, stepup_proof text, preconditions_shown jsonb NOT NULL,
    lifted_guards text[] NOT NULL DEFAULT '{}',   -- ADR-0054 guards the agreement lifts
    agreed_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE compliance_declines (
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    item_id uuid PRIMARY KEY REFERENCES compliance_fix_items ON DELETE CASCADE,
    user_id uuid NOT NULL, reason text NOT NULL, kind text NOT NULL CHECK (kind IN ('accepted_risk','deferred')),
    expires_at timestamptz, declined_at timestamptz NOT NULL DEFAULT now());
```

**Every per-organization table has `organization_id NOT NULL`**, including
children such as agreements, declines, evidence links, scan jobs and every
assessment child. It is denormalized on purpose: row-level security uses
that column everywhere, with no join to a parent. Consistency with the parent
is enforced by a composite foreign key `(parent_id, organization_id)` to
the parent's `UNIQUE (id, organization_id)` (a child cannot name another
organization's parent), and, where a row has several optional parents
(evidence links), by a constraint trigger. An integration test inserts a
mismatched child and expects the error.

All per-organization tables have forced RLS: read when
`organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs'))` or
`easyrmm_scope_all()`; writes by the system scope only (the server writes on
behalf of users, as `device_hardening` does). `compliance_agreements` rows
are insert-only (a trigger like `easyrmm_audit_immutable`), as is
`compliance_results_history`.

## The assessment workspace (C5)

```sql
CREATE TABLE compliance_assessments (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations ON DELETE CASCADE,
    UNIQUE (id, organization_id),     -- target of the children's composite foreign keys
    framework_key text NOT NULL, framework_version text NOT NULL, profile_key text,
    title text NOT NULL, assessor text,
    state text NOT NULL CHECK (state IN ('draft','in_review','approved','archived')),
    approved_by uuid REFERENCES users, approved_at timestamptz,
    supersedes uuid REFERENCES compliance_assessments,   -- copy-on-write: a new draft after approval
    created_at timestamptz NOT NULL DEFAULT now());

CREATE TABLE compliance_scope_assets (
    organization_id uuid NOT NULL,
    assessment_id uuid NOT NULL,
    FOREIGN KEY (assessment_id, organization_id) REFERENCES compliance_assessments (id, organization_id) ON DELETE CASCADE,
    device_id uuid REFERENCES devices ON DELETE CASCADE, group_id uuid REFERENCES device_groups ON DELETE CASCADE,
    category text NOT NULL CHECK (category IN ('cui','security_protection','contractor_risk_managed',
                                               'specialized','out_of_scope')),
    reason text,
    CHECK ((device_id IS NULL) <> (group_id IS NULL)));

CREATE TABLE compliance_implementations (
    organization_id uuid NOT NULL,
    assessment_id uuid NOT NULL,
    FOREIGN KEY (assessment_id, organization_id) REFERENCES compliance_assessments (id, organization_id) ON DELETE CASCADE,
    req_id text NOT NULL,
    status text NOT NULL CHECK (status IN ('met','not_met','not_applicable','not_assessed')),
    origin text NOT NULL CHECK (origin IN ('scan','attested','manual')),
    statement text NOT NULL DEFAULT '',
    responsibility text NOT NULL CHECK (responsibility IN ('customer','msp','inherited','shared')),
    owner_user uuid REFERENCES users, reviewed_at timestamptz, next_review date,
    PRIMARY KEY (assessment_id, req_id));

CREATE TABLE compliance_objective_results (
    organization_id uuid NOT NULL,
    assessment_id uuid NOT NULL, req_id text NOT NULL, obj_id text NOT NULL,
    determination text NOT NULL CHECK (determination IN ('met','not_met','not_applicable','not_assessed')),
    method text, source text NOT NULL CHECK (source IN ('scan','attestation','upload','interview')),
    decided_by uuid, decided_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (assessment_id, req_id, obj_id),
    FOREIGN KEY (assessment_id, organization_id) REFERENCES compliance_assessments (id, organization_id) ON DELETE CASCADE);

CREATE TABLE compliance_evidence (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('scan_snapshot','upload','link','attestation','screenshot')),
    UNIQUE (id, organization_id),
    title text NOT NULL, media_type text, size_bytes bigint CHECK (size_bytes <= 67108864),  -- plaintext size
    body bytea,                       -- AES-256-GCM ciphertext (ADR-0078, Evidence storage); kept in the database so backups hold it
    nonce bytea, key_id text,         -- 96-bit nonce; the data key version
    url text, sha256 text NOT NULL,   -- SHA-256 of the plaintext, checked on download
    collected_at timestamptz NOT NULL, collector uuid REFERENCES users,
    expires_at timestamptz, superseded_by uuid REFERENCES compliance_evidence,
    scan_id uuid REFERENCES compliance_scans);   -- never deleted, only superseded
CREATE TABLE compliance_evidence_links (
    organization_id uuid NOT NULL REFERENCES organizations ON DELETE CASCADE,
    evidence_id uuid NOT NULL,
    assessment_id uuid, req_id text, obj_id text, fix_item_id uuid, poam_id uuid,
    FOREIGN KEY (evidence_id, organization_id) REFERENCES compliance_evidence (id, organization_id) ON DELETE CASCADE);
-- The other end (assessment, fix item, POA&M item) is checked to be in the same organization
-- by a constraint trigger, since a link row has several optional parents.

CREATE TABLE compliance_org_keys (   -- the per-organization data key, wrapped by secrets.Sealer
    organization_id uuid NOT NULL REFERENCES organizations ON DELETE CASCADE,
    key_id text NOT NULL, wrapped text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, key_id));

CREATE TABLE compliance_attestations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL,
    assessment_id uuid NOT NULL, req_id text NOT NULL,
    FOREIGN KEY (assessment_id, organization_id) REFERENCES compliance_assessments (id, organization_id),
    objectives text[] NOT NULL DEFAULT '{}', statement text NOT NULL, statement_sha256 text NOT NULL,
    signer uuid NOT NULL REFERENCES users, stepup_proof text NOT NULL,
    signed_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL);

CREATE TABLE compliance_poam_items (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL,
    assessment_id uuid NOT NULL,
    FOREIGN KEY (assessment_id, organization_id) REFERENCES compliance_assessments (id, organization_id) ON DELETE CASCADE,
    UNIQUE (id, organization_id),
    req_id text NOT NULL, weakness text NOT NULL, point_value integer NOT NULL,
    owner_user uuid REFERENCES users, resources text, scheduled_completion date,
    status text NOT NULL CHECK (status IN ('draft','open','in_progress','closed','accepted')),
    eligible boolean NOT NULL, eligibility_reason text NOT NULL,    -- computed, shown
    opened_on date NOT NULL DEFAULT current_date, closes_by date);   -- 180-day clock
CREATE TABLE compliance_poam_milestones (id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL,
    poam_id uuid NOT NULL,
    FOREIGN KEY (poam_id, organization_id) REFERENCES compliance_poam_items (id, organization_id) ON DELETE CASCADE,
    title text NOT NULL, due date, status text NOT NULL, evidence_id uuid REFERENCES compliance_evidence);

CREATE TABLE compliance_documents (id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL,
    assessment_id uuid NOT NULL,
    FOREIGN KEY (assessment_id, organization_id) REFERENCES compliance_assessments (id, organization_id) ON DELETE CASCADE,
    UNIQUE (id, organization_id),
    kind text NOT NULL CHECK (kind IN ('ssp','policy','procedure','plan')), template_id text NOT NULL,
    version integer NOT NULL, approver uuid REFERENCES users, approved_at timestamptz);
CREATE TABLE compliance_document_sections (organization_id uuid NOT NULL,
    document_id uuid NOT NULL,
    FOREIGN KEY (document_id, organization_id) REFERENCES compliance_documents (id, organization_id) ON DELETE CASCADE,
    position integer, heading text NOT NULL, body text NOT NULL, generated boolean NOT NULL,
    PRIMARY KEY (document_id, position));

CREATE TABLE compliance_score_snapshots (id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL,
    assessment_id uuid NOT NULL,
    FOREIGN KEY (assessment_id, organization_id) REFERENCES compliance_assessments (id, organization_id) ON DELETE CASCADE,
    taken_at timestamptz NOT NULL DEFAULT now(),
    sprs_low integer NOT NULL, sprs_high integer NOT NULL,
    l2_gate jsonb NOT NULL, l1_count integer, basis jsonb NOT NULL);
```

Audit is the existing hash-chained log: events `compliance.*` for status
changes (before, after, origin), attestations (who, step-up proof, text
hash), evidence add and supersede (hash), scope changes, POA&M edits,
approvals, exports (who, what, hash), snapshots and every fix event. No
second chain is added.

## Migrations

| File (placeholder number) | Slice | Contents | Down |
|---|---|---|---|
| `90780_compliance_library.sql` | C1 | sources, packs, controls, refs, profiles, frameworks, requirements, objectives, mappings, org settings and org packs | drop in reverse order |
| `90781_compliance_results.sql` | C1 | scans, scan jobs, results history and the latest-result view | drop; no data outside the compliance tables is touched |
| `90782_compliance_fix_queue.sql` | C2 | fix items, agreements, declines; new audit event names need no schema | drop |
| `90783_compliance_assessment.sql` | C5 | assessment workspace tables | drop |

The integrator renumbers these. C3 and C4 add content, not tables.
