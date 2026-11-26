# ADR-0078: The compliance engine

* Status: Accepted (2026-11-26, after an independent review; two owner questions stay open, below). Design only; no code is changed by this ADR.
* Asked for by the owner on 2026-11-24
  ([requirements](../requirements/2026-11-24-compliance-engine.md), verbatim
  and binding) and again on 2026-11-26 (the end goal, below). Everything
  marked *decided in review* is the writer's call and the owner can overturn
  it. Everything marked *owner decision* is open.
* Builds on: [ADR-0054](0054-hardening-windows-computers-and-servers.md)
  (Windows hardening: check, apply, undo; its W1 is built, its W2 is
  planned), [ADR-0051](0051-hardening-linux-computers.md),
  [ADR-0073](0073-windows-management-modules.md) (the `winmod` job kind,
  typed actions, step-up), [ADR-0072](0072-what-each-page-shows.md) (where
  pages go), [ADR-0007](0007-hash-chained-audit-log.md) (audit),
  [ADR-0066](0066-customer-documentation-and-assets.md) (stored files), and
  `server/internal/devscope`.
* Amends ADR-0054 (its *Basis* wording rule and its *Lock-out guards*; see
  *Amendments to ADR-0054*).
* The detail lives in four appendices under
  [`docs/architecture/compliance/`](../compliance/):
  [data model](../compliance/data-model.md) (deliverables 3 to 6 and the
  migrations), [examples](../compliance/examples.md) (7 to 9),
  [licensing and legal](../compliance/licensing-and-legal.md) (1, 10 and 11).

## The end goal (owner, 2026-11-24 and 2026-11-26)

Pick a framework (HIPAA, GDPR, NIST, SOC 2 TSC, CMMC, and others that are
useful). EasyRMM checks each computer against what a computer can verify. For
every gap it offers a fix, and the administrator applies it item by item. CMMC
also gets a full SSP, POA&M and evidence workflow in the console, written by
us. CIS settings are included, as our own checks cross-referenced by CIS
recommendation number.

The owner's words on fixes: *"No if they want to enable something they can,
its there fault if they screw it up. We warn them, and make them do it by
having to agree."* So there is **no check-only list**. Every fix is offered
with a warning and an explicit agreement; the riskiest need a typed one.

## Deliverables of the requirements document, section 8

| # | Deliverable | Where |
|---|---|---|
| 1 | Assessment of the CIS licensing implications | [licensing and legal](../compliance/licensing-and-legal.md#1-assessment-of-the-cis-licensing-implications) |
| 2 | Recommended architecture | this ADR, [section 2](#2-recommended-architecture) |
| 3 | Security control data model | [data model](../compliance/data-model.md#3-the-security-control-data-model) |
| 4 | Framework mapping model | [data model](../compliance/data-model.md#4-the-framework-mapping-model) |
| 5 | Licensing metadata model | [data model](../compliance/data-model.md#5-the-licensing-metadata-model) |
| 6 | Content package architecture | [data model](../compliance/data-model.md#6-the-content-package-architecture) |
| 7 | Independently authored Windows check | [examples](../compliance/examples.md#7-a-windows-check) |
| 8 | Independently authored Linux check | [examples](../compliance/examples.md#8-a-linux-check) |
| 9 | One check mapped to CIS, NIST 800-171 and CMMC | [examples](../compliance/examples.md#9-one-check-three-frameworks) |
| 10 | Commercial distribution strategy | [licensing and legal](../compliance/licensing-and-legal.md#10-commercial-distribution-strategy) and [section 10](#10-commercial-builds-and-the-build-time-check) below |
| 11 | Licensing and legal risks needing review | [licensing and legal](../compliance/licensing-and-legal.md#11-licensing-and-legal-risks-needing-review) |

The requirements document asks for these *before any structural change*. This
ADR is that proposal; nothing structural is built until it is accepted.

## Context

* **What exists.** The Windows hardening script and its 140 or so settings
  (`server/internal/jobs/hardening/windows-settings.json`), the Linux script,
  the generated "related controls" tables (`controls/related.json`: STIG,
  CCI, NIST 800-53, 800-171, ISO), `device_hardening` (a state per device and
  module), the `hardening` job kind, and `device.harden`. ADR-0054's W1
  (check) is built. W2 (apply and undo, with read-back) is planned and is the
  base of every fix here.
* **What does not exist.** Anything that says what a *framework requirement*
  needs, the licence of a piece of content, a result per control rather than
  per module, a queue of fixes, or an assessment record (scope, statements,
  evidence, POA&M).
* **Constraints that bind the design.**
  * ADR-0054 *Basis*: no CIS text, no Wazuh content, no claim of compliance.
    The owner has since asked for CIS cross-references and for the word
    "CMMC"; both need the amendments below and a legal review gate.
  * The product is source-available (FSL-1.1-ALv2) and sold to MSPs; it must
    be distributable commercially without inheriting a non-commercial or
    copyleft licence from any content.
  * ADR-0037 allows only permissive dependencies. nealfennimore/cmmc (Elastic
    License 2.0) and the Wazuh policies (GPL) are therefore ideas at most.
  * Every row is per organization with row-level security
    (`00001_core.sql`), and every new automatic behaviour obeys
    `devscope.Allowed`.

## Decision

### 1. In short

1. **One control library, written by us.** A *control* is one technical
   setting or condition, named by what it is (`win.accounts.password-history`),
   with a detector, a fix, an undo, a risk tier, and provenance. It carries
   no framework text.
2. **Frameworks are data packs.** A pack maps a framework's requirement ids
   to controls. One control maps to many frameworks, and a mapping says how
   far it goes (`satisfies_objective`, `evidence_for`, `related`), so a
   passing control never implies a passing requirement.
3. **Every piece of content has a licence class and provenance**, checked at
   load and at build. Restricted content cannot enter a commercial build.
4. **Scans reuse the existing executors** (hardening script, `winmod`
   actions, Linux script, stored facts); the engine adds the library,
   per-control results, scope and roll-ups.
5. **The fix queue** turns each failed control on each host into an item that
   an administrator agrees to individually, with a risk tier, a warning,
   typed confirmation for tier 3, undo, optional second-person approval, and
   audit.
6. **CMMC gets an assessment workspace**: scope, statements, objective
   determinations, evidence, attestations, POA&M, SSP, a SPRS range (never a
   single figure unless fully assessed), and OSCAL export.
7. **The word "compliant" is never used.** Wording rules are in section 9.

### 2. Recommended architecture

Deliverable 2. Six parts, all in the server; the agent does not change
except for the new check scripts of C3 (the agent runs scripts it is sent).

```
 packs (data)              library (our checks)             executors (exist)
 framework, profile,       control: detect/fix/undo,        hardening job (ADR-0054/0051)
 mapping, xref,            tier, provenance, licence        winmod actions (ADR-0073)
 customer-licensed         ---------------------------      Facts / stored snapshots
        |                           |                       server-side data (e.g. MFA state)
        v                           v                               ^
   Pack loader --------> Control library <---- Scan planner ---------+
   (licence check)             |                    |
                               v                    v
                        Results (per device, control)  --> Roll-up per requirement,
                               |                           objective, org (scope-aware)
                               v                                   |
                          Fix queue --> hardening apply/undo   Assessment workspace
                          (agreement, approval, audit)         (C5: SSP, POA&M, evidence,
                                                                SPRS range, OSCAL)
```

* **A. Compliance engine** (`server/internal/compliance`): the scan
  planner, result ingester, roll-up and the fix queue. It never runs a
  script of its own. It asks an *executor* to read or change one control and
  stores the typed answer.
* **B. Control library** (`compliance/library`, embedded data): controls as
  data plus, for Windows, entries in the existing hardening settings file
  (a control with `executor = hardening` names a setting id there). Each
  control has an implementation, detection logic, expected value, our own
  remediation text, severity, applicability, references and provenance.
* **C. Framework mapping layer**: packs of mappings, many-to-many, each with
  a relation strength. The framework's own assessment criteria (objectives)
  are kept; a mapping to a requirement is never a determination.
* **D. Assessment profiles**: a profile is a named list of controls and
  parameters for a platform ("Windows 11 Security Baseline", "Windows Server
  2022 Security Baseline", "Ubuntu Server", "Debian Server", "RHEL", "Network
  infrastructure", "CMMC Level 2 Assessment", "NIST 800-171 Assessment").
  Profiles reference controls; they never copy them.
* **E. Remediation engine**: the fix queue over ADR-0054 W2 apply and undo,
  with before-and-after reads, rollback, logging and approval (section 6).
  Manual remediation text is shown where no apply exists.
* **F. Licensing layer**: classification, provenance, the pack loader's
  checks and the build-time check (section 10).

*Network infrastructure* (the profile in the requirements) has no executor:
EasyRMM has no collector for switches or firewalls. The profile exists as a
manual-assessment profile (attestation per control) until a collector does
(*decided in review*; no agent or network scanner is promised here).

### 3. Data model, mapping model, licence metadata, packs

Deliverables 3 to 6 are in the [data model appendix](../compliance/data-model.md),
with the SQL of every migration. The decisions this ADR rests on:

* **Controls are global and read-only** (like `controls/data` today); they
  ship in the server image and are loaded by migration or at startup. Per
  organization rows (results, queue, assessments) have `organization_id` and
  row-level security.
* **A control has two ids.** An internal stable id (`win.accounts.password-history`)
  that never changes meaning, and a `version`. A change to detection or the
  expected value bumps the version; results record the version they ran.
* **Mappings are their own rows**, belonging to a pack, so removing a pack
  removes its mappings and nothing else. The control library has no column
  for a framework id.
* **Licence class is on every control, mapping, pack and source**, plus a
  separate `review_state` (`none`, `needed`, `cleared` with a reference).
  Seven classes as the requirements ask: `ORIGINAL`, `PUBLIC_DOMAIN`,
  `OPEN_LICENSE`, `ATTRIBUTION_REQUIRED`, `NONCOMMERCIAL`,
  `COMMERCIAL_LICENSE_REQUIRED`, `RESTRICTED`.
* **Customer-licensed packs** are installed at run time into the database,
  scoped to one organization or to the server, never embedded in the image
  and never redistributed (section 10).

### 4. Scans and results

* **Scan planner.** A scan names an organization, a profile or framework, and
  the devices (by site, group or list). The planner collects the controls
  those select, groups them by executor, and creates *one job per device per
  executor kind*, not one per control: the hardening script already checks
  several settings per run, and the `winmod` kind reads per action. It reuses
  the existing job kinds, their limits (four slots on the agent) and their
  signing. The scan is a row; its jobs are normal jobs.
* **No new job kind.** Scans use `hardening` (check mode), `winmod` read
  actions, and the Linux hardening script. Server-side and stored data
  (software inventory, hardware facts, EasyRMM's own settings such as "MFA is
  required") are read by the engine without a job.
* **Per-control results.** The hardening `device_hardening` table holds a
  state per module. The compliance tables hold a result per device and
  *control*, with every scan's results kept (append-only history; see the
  data model). Where the setting ids come from (verified in the code):
  * **Windows:** the check's result already lists each setting by the id in
    `windows-settings.json` (`HardeningSetting.ID`, `WindowsFinding.Settings`,
    `server/internal/jobs/windows_hardening.go`). The ingester maps setting
    ids to control ids through the control's `executor_ref`.
  * **Linux:** the finding has only `Missing`, `Changes` and `Done` lists of
    free text (`HardeningFinding`, `server/internal/jobs/hardening.go`).
    **Slice C0** gives Linux settings ids and a typed per-setting list.
* **Truncated results are never a pass.** The Windows result is limited in
  size; when it is too long the script drops settings that are in place
  (`settingsOmitted = in_place`) and then all settings (`all`)
  (`windows.ps1`, the result-size code). The ingester treats any control
  whose setting is absent from a truncated result as `unknown`, **never
  `in_place`**. The planner then re-runs only the affected modules (one
  module per job, then smaller groups) until the result is complete, and
  marks the scan `partial` if it cannot. A control whose module could not
  complete stays `unknown` and counts as not assessed.
* **State vocabulary** is ADR-0054's (`in_place`, `partly`, `not_in_place`,
  `not_applicable`, `managed_elsewhere`, `not_supported`, `half_applied`,
  `failed`) plus `unknown` and `stale` (older than the organization's
  freshness window, default 30 days). `unknown` and `stale` never count as
  passing, as in the posture feature.
* **Managed elsewhere.** When Group Policy, MDM or another owner decides a
  value, the result says so, names the owner and whether *that* value meets
  the control; the fix queue offers no write (ADR-0054's reader decides).
* **Roll-up** (server-side, from results and scope):
  * per requirement and objective: devices in scope passing or total, worst
    case; a requirement is *met by the scan* only if every in-scope asset
    passes every control mapped as `satisfies_objective`; `unknown`, `stale`
    and `not_supported` give *not assessed*; `not_applicable` everywhere
    gives *not applicable* only with a stated reason;
  * requirements whose class is `organisational`, or whose objectives need
    non-technical evidence, are *not assessed* until an attestation or
    evidence covers them (C5). A scan alone never makes a requirement
    "met". Passing is necessary, not sufficient.
* **Evidence per scan.** Each scan stores a snapshot row (job ids, device
  ids, time, a hash of the result rows) that C5 links as evidence.
* **Scheduling.** Scheduled scans (default weekly, per organization, off
  until the organization enables the module) run through the ADR-0073
  scheduling gate. Both scheduled and hand-started scans and fixes check
  `devscope.Allowed(orgID)` once per request or tick (*decided in review*: a
  new feature must not reach other organizations until phase 6, so the
  hand-started case is gated too).

### 5. Frameworks offered and what a host can verify

Hosts can verify only part of each framework. The console shows, per pack,
how many requirements are *checked by controls*, *partly*, and
*organisational (not assessed)*. The figures below are the research's
estimates and are unverified except where marked.

| Framework | Source of requirement ids | Licence of the data we ship | Pack kind |
|---|---|---|---|
| NIST SP 800-171 r2 | NIST (public domain) | `PUBLIC_DOMAIN`, full text and 171A objectives | framework, full text |
| CMMC 2.0 Level 1 and 2 | 32 CFR 170 (US government) | `PUBLIC_DOMAIN` | framework, full text |
| NIST SP 800-53 r5 | NIST catalogue | `PUBLIC_DOMAIN` | framework, full text, a *view* by related controls |
| NIST CSF 2.0 | NIST | `PUBLIC_DOMAIN` | framework |
| HIPAA Security Rule | 45 CFR 164 (federal regulation); HHS and NIST SP 800-66r2 mappings | `PUBLIC_DOMAIN` (to confirm) | framework; technical safeguards only |
| DISA STIG | DISA ids and CCIs | `PUBLIC_DOMAIN`, ids only | framework, ids and our titles |
| GDPR Art. 5(1)(f) and 32 | the regulation | to confirm (reuse terms unverified) | **indicative** pack, our own mapping |
| SOC 2 TSC | AICPA | text is AICPA's: ids and our titles only | **indicative** pack |
| PCI DSS v4.0.1 | PCI SSC | ids and our titles only; reuse terms unread | pack, later |
| ISO/IEC 27001:2022 Annex A | ISO | numbers only, via NIST's OLIR crosswalk | pack, numbers only |
| Essential Eight, Cyber Essentials | ASD, NCSC | to confirm | packs, later (good host fit) |
| CIS Controls and CIS Benchmarks | CIS | **cross-reference numbers only, in our own words** | `cis-xref` pack, gated (section 10) |

A pack that stores only ids and our own short titles is how every
non-public-domain framework is carried (`text_policy = ids_and_own_titles`).
GDPR and SOC 2 are labelled "indicative mapping by EasyRMM, not an audit
criterion" in the console and every report, because neither has an
authoritative technical checklist.

### 6. The fix queue

Deliverable 4E and the owner's rule: every fix has a warning and explicit
agreement. Per the owner, nothing is check-only for policy reasons; what
remains are *technical* limits, which the console states beside the fix.

**An item** is one failed control on one host. It is created by the scan (or
re-created, never duplicated: unique on host and control while open). It
carries host, control and its version, current and target value, tier,
whether undo exists, warnings, preconditions, whether a restart is needed,
who owns the value if managed elsewhere, and the requirements it would help
(a link, for the user's benefit; never a claim).

**Risk tiers** (research proposal, adopted, *decided in review*):

| Tier | Meaning | Examples | Agreement |
|---|---|---|---|
| T0 | Report only: there is no setting to change (information) | TPM present, Secure Boot state | none; no Apply button |
| T1 | Reversible, no service effect | AutoRun off, WDigest off, SMBv1 off where unused | per-item checkbox with the warning shown on the row |
| T2 | Can break a workflow or a user's access | SMB signing, NTLM level, TLS versions, RDP idle limits, removable-storage deny, UAC, ASR block, SSH timeouts | per-item agreement in a dialog that shows the warning and the affected host |
| T3 | Can lock out access, lose data, or cannot be undone remotely | firewall profile changes, RDP disable, NLA changes, account lockout, disable or rename an account, deny-logon rights, BitLocker enable, FIPS mode, AppLocker or WDAC enforce, LDAP signing, Credential Guard, domain GPO changes | typed confirmation, step-up authentication, preconditions displayed |

**Agreement rules.**

1. An agreement is recorded per item: user, time, the warning text's id and
   hash, the control version, the typed text (T3), the step-up proof (T3),
   and the preconditions displayed. It is stored in `compliance_agreements`
   and written to the audit log.
2. **T1**: several items may be selected; each still gets its own agreement
   row, and the warning of each is visible in its row.
3. **T2**: one control may be applied to several hosts in one dialog that
   lists every host; each host gets its own agreement row (*decided in
   review*, because an MSP cannot click through 200 computers one by one;
   the owner can tighten it).
4. **T3**: one item at a time. The user types the host's name (the typed
   text) after the dialog shows the preconditions and, for account items,
   the exposure scan's named accounts. Step-up authentication within 10
   minutes. **Step-up is a named prerequisite** (ADR-0073 slice 4, or F5 if it
   lands first): until it ships, T3 fixes and attestations are disabled, not
   offered without it (see the slice order).
5. **No "fix all"** above T1, and no default selection of any item.
6. **Preconditions** are checked on the server before dispatch and again by
   the script: BitLocker enable needs a protector and the recovery key in
   the keystore (the keystore plan, step 19), or the user types that no key
   is kept (data-loss warning); an item that needs a restart reports
   *restart needed* and EasyRMM never restarts; a domain-wide item (LDAP
   signing, domain password policy) needs the `domain-controller` option and
   shows ADR-0054's audit-period advice; Credential Guard or VBS locked in
   firmware is shown as not undoable remotely.
7. **Approvals.** An organization setting `require_approval` (default off,
   per tier, T3 suggested) makes an item wait for a second person with
   `compliance.fix_approve`, who is not the requester. The approver's
   agreement is a second row. This is the "approval workflow" of the
   requirements, optional because the owner's rule is that the administrator
   agrees.
8. **The access guard** ("a fix must not cut our own way in"). Any fix that
   could cut access to the computer or to its agents (RDP, WinRM, a firewall
   profile or rule that the EasyRMM agent, MeshAgent or the patching agent
   need) shows that risk in its warning, is T3 whatever its other
   properties, and **runs a post-apply connectivity check**: after the change
   the server waits for the agent's next check-in (a bounded window set per
   control). If the agent has not reported by then, the script's own timer
   (set before the change, on the computer) **undoes the change
   automatically**, and the item is `failed` with that reason. Because the
   undo is local and timed, it does not depend on the agent being
   reachable. A control that cannot offer this safety net (no timer undo)
   is not offered at all (`apply_supported = false`, manual text only).
9. **Declining** is recorded: an item can be *accepted as a risk* or
   *deferred* with a reason and an expiry; a declined item feeds a draft
   POA&M item in C5. It stays visible; it is never silently hidden.

**Execution.**

* The queue builds a normal hardening job per device (`device.harden`'s
  existing path, one change at a time per device), carrying only the
  control ids the user agreed to. The compliance module never writes
  settings itself and has no script of its own (one undo owner).
* Each change is read back; a value not as intended is put back and the item
  is `failed` (ADR-0054). **A requirement's status is never changed by the
  fix**: the engine queues a single-control re-scan, and only that result
  can move anything. The item then shows `applied and verified` or
  `applied, not verified`.
* **Undo** uses ADR-0054's undo (restore from the backup the apply made).
  An item's undo is offered while the backup exists; a control whose
  `undo_kind` is `none` says so in the warning *before* agreement.
* **Audit and logging.** Created, agreed, approved, dispatched, applied,
  read back, failed, undone and declined are each an audit event
  (`compliance.fix.*`) through the existing hash-chained audit append, with
  organization, user, host, control, version, tier and agreement id. There
  is no second audit chain (*decided in review*; the research proposed one).
  The job result (before and after values, change time) is kept with the
  item.
* **Audit log versus POA&M.** The audit log records what happened; the POA&M
  records what remains.
* **Log collection** (ADR-0060) owns audit-policy values: the audit-policy
  control's fix calls its configure step instead of writing a second copy.
* **Linux** fixes use the Linux hardening script's apply and undo
  (ADR-0051); the queue is the same.

### 7. Where it shows (ADR-0072)

Compliance is a "Compliance" tab. It is hidden, never greyed, when the module
is off for the organization or the user lacks `compliance.view`, and it uses
the existing scope query parameters. Permissions are in section 8.

| Level | What it shows | Source |
|---|---|---|
| **Everything** (`/reports`) | a Compliance table in Reports: one row per organization with selected pack, last scan, controls checked, failing count; links to each organization's tab | stored results; never a job |
| **Organization** (`/organizations/:id`) | **"Compliance" tab**: the frameworks selected, scope (C5), per-pack counts (checked, partly, not assessed), the failing requirements, the fix queue for the organization, scan schedule and the module switch. The CMMC workspace (C5) is a sub-view of this tab | results, roll-ups |
| **Site** (`/sites/:id`) | a **result card** on Overview: pass and fail counts for the site's hosts for the selected packs, link to the filtered organization tab. No separate tab | results |
| **Group** | nothing of its own; the device list filter "Compliance: failing" works on a group's list; a group can be a scope member (C5) | results |
| **Device** (`/devices/:id`) | **"Compliance" inside the Security tab** (ADR-0072/0073): controls by state with the requirements each helps, fix items for this host (the queue filtered to the host), the scan time and staleness, a "Scan now" and "Apply" per item | results, queue |
| **Devices list** | a column and filter "Compliance" (failing count), hidden if the module is off | results |
| **Settings** | server-wide: the pack list (installed packs with licence class and review state, add a customer pack), the build edition, and the CIS cross-reference switch (section 10) | `compliance.admin` |

Alerts: a new alert kind `compliance.fix_failed` and `compliance.scan_stale`
use the existing alert and policy levels. They are automatic behaviour and are
gated by `devscope.Allowed`. Rules from ADR-0072: a site or organization page
never sends a job to draw a card.

### 8. Permissions

New in `server/internal/rbac/rbac.go`, added at the end of the existing lists
(a small additive edit; never reorder):

| Permission | Allows | Step-up |
|---|---|---|
| `compliance.view` | see results, queue, assessments | no |
| `compliance.scan` | start a scan | no |
| `compliance.fix` | agree to and apply T1 and T2 items | no (T2 shows the dialog) |
| `compliance.fix_high` | agree to T3 items | yes |
| `compliance.fix_approve` | second-person approval | yes |
| `compliance.edit` | scope, statements, evidence, POA&M (C5) | no |
| `compliance.attest` | sign an attestation (C5) | yes |
| `compliance.approve` | approve and freeze an assessment (C5) | yes |
| `compliance.export` | export reports, OSCAL, evidence bundles | no |
| `compliance.admin` | packs, edition switches (server-wide) | yes |

Rows marked step-up are **disabled until step-up ships** (ADR-0073 slice 4 or F5): the permission exists but the action is refused. Fix permissions also need `device.harden` on the device. Defaults (*decided in
review*): Organization Administrators hold all but `compliance.admin`;
Technicians hold view, scan and `compliance.fix`; Read-Only holds none
(evidence may hold sensitive configuration). Super administrators hold
`compliance.admin`.

### 9. Wording rules (amending ADR-0054's)

* Results say a control **"meets"**, **"does not meet"** or **"cannot tell"**;
  a requirement is **"checked: all in-scope computers meet"**, **"checked:
  does not meet"** or **"not assessed"**. Never "compliant", "certified",
  "passes CMMC", "CIS compliant", "audit-ready" or "you will pass".
* Every compliance screen and report carries: "Assessment aid. It reports
  what EasyRMM could check on the computers in scope. It is not an
  assessment, an audit, a certification or legal advice."
* CIS: "Cross-reference to CIS recommendation numbers. EasyRMM's checks are
  independently written and are not CIS content. EasyRMM is not CIS
  certified." Never "CIS Level 1".
* The CMMC marks are used descriptively (the program's name, practice ids);
  see the risks appendix on trademarks.
* SPRS is a **range with its basis**, labelled "estimate"; EasyRMM never
  submits to SPRS and never implies it does.

### 10. Commercial builds and the build-time check

The aim is that restricted content cannot be in a commercial image by
accident.

* **Edition.** The server has a build edition, `commercial` (releases) or
  `dev` (everything else), set at build with a linker variable and recorded
  in the image's manifest. There is no runtime switch to change it.
* **Where content lives.** Only `server/internal/compliance/content/` is
  embedded in the server. Every content file is declared in
  `content/manifest.json` with its licence class, source id, review state,
  author, and SHA-256. There is **no** directory for restricted content in
  the repository; `.gitignore` and a lint refuse files outside the manifest.
* **The check** is `cmd/packlint`, run by `make lint`, by CI and by the
  release script:
  1. every embedded file is in the manifest with a matching hash;
  2. in the `commercial` edition, the allowed classes are `ORIGINAL`,
     `PUBLIC_DOMAIN`, `OPEN_LICENSE` and `ATTRIBUTION_REQUIRED`. Any
     `NONCOMMERCIAL`, `COMMERCIAL_LICENSE_REQUIRED` or `RESTRICTED` entry
     fails the build;
  3. any entry with `review_state` of `needed` fails the commercial build
     until it is `cleared` with a reference (a counsel's opinion or a
     membership agreement id) recorded in the manifest;
  4. every `ATTRIBUTION_REQUIRED` and `OPEN_LICENSE` source must appear in
     the generated `NOTICE` file (the check regenerates it and fails on a
     diff);
  5. a content string scan (**a plain string match**, so it is a backstop,
     not the control: the primary gate is the required provenance and licence
     class on every file, with a named author asserting
     `derived_from_content: false`, and a second person's review) fails on a banned marker: "Center for Internet
     Security" or "CIS Benchmark" in a description, rationale or
     remediation text field (the cross-reference number field is exempt),
     a Wazuh header, a GPL header;
  6. **after the build**, the release script reads the manifest *out of the
     built image* and repeats 1 to 3, so a file added by another route is
     caught.
* **Runtime.** The pack loader repeats the class check for any pack, so an
  edition's rule holds even if a pack is installed by hand. In the
  `commercial` edition a customer pack is loaded only as `customer_licensed`
  (below) and never merged with embedded content.
* **The CIS cross-reference pack** is in the repository with `review_state =
  needed`. In a `dev` build it loads. In a `commercial` build it fails step 3
  until the owner records clearance. That is the one switch with the legal
  question behind it (*owner decision 1*).
* **Customer-licensed content.** A customer with their own CIS licence
  (or any licensed benchmark) may install a pack file into their
  installation. It can contain requirement text and mappings only; it cannot
  contain checks or scripts (executable content is only what we ship and
  sign). It is stored per organization (or per server), marked
  `origin = customer`, excluded from every export and OSCAL file by default,
  and never merged into the embedded library. EasyRMM does not assume their
  licence lets us redistribute anything.
* **Official pack signing.** Packs EasyRMM ships are signed with the release
  key; customer packs are unsigned and shown as such.

### 11. Slices

*Amended 2026-11-26 (decided in review, after independent review):* slice C0 added; W2 and step-up made explicit prerequisites; C2 changes the scripts to take setting ids; truncated results are `unknown`; firewall, RDP and NLA fixes are T3 with a post-apply connectivity check and automatic undo; per-scan result history; evidence encrypted at rest; OSCAL pinned.

In order, for parallel builders:

1. **C0** (Linux per-setting ids) first; C1 after C0.
2. C2, C3 and C4 can start from C1's interfaces in parallel; C5 needs C1 and
   C2.
3. **Prerequisites that gate fixes** (they are other slices, not compliance
   work):
   * **ADR-0054 W2** (apply and undo). Today the Windows script refuses any
     mode but `check` (`windows.ps1`, `Read-ErArguments`: "this release has
     check only"). **No fix button ships before W2's first modules**, and
     each fix control ships only with its module's W2 apply and undo.
   * **Step-up** (ADR-0073 slice 4, or F5). T3 fixes, attestations and
     approvals are disabled until it ships.
   * **The keystore** (plan step 19) for BitLocker enable.
   * ADR-0075's collector for C4.
4. C1 and C5 are read-only and can ship without W2 and step-up, except that
   C5's attestations wait for step-up.

Each slice is merged only when the gates in the builder rules pass.
Migration numbers below are reserved for the slices and are renumbered by the
integrator (design placeholder; the brief named none).

#### C0: Linux per-setting ids

*Goal:* the Linux hardening check reports a typed result per setting, as the
Windows check does, so a control can name a setting. This is an additive
change to ADR-0051's script and result; nothing else in compliance starts
before it.

Files:
* `server/internal/jobs/hardening/linux.sh`: each module's check prints its
  settings by id (`ssh-permit-root-login`, `ssh-password-authentication`, ...) with
  state, value and wanted value.
* `server/internal/jobs/hardening.go`: a `Settings []HardeningSetting` list
  on `HardeningFinding` (the Windows type, shared), parsing and validation.
* `server/internal/jobs/hardening/linux-settings.json` (new): the id list
  per module, the counterpart of `windows-settings.json`.
* `web`: the existing Linux hardening panel keeps its text lists; nothing
  new is shown yet.

Tests: a table test per module of the check output to the setting list; the
existing SSH integration harness (`hardening_script_ssh_integration_test.go`)
asserts ids and states; an old script's result without the list still parses
(compatibility); `go vet -tags integration,vm`.

*Built (C0):* `linux-settings.json` lists 106 ids, each starting with its
module (`ssh-x11-forwarding`, `kernel-net-ipv4-tcp-syncookies`,
`permissions-etc-shadow`, `services-telnet`, `audit-rules-sudoers`, ...). The
script's `set_ok` and `set_bad` record a setting beside the text line, and a
result lists `{id, state, value, want}` per setting (`HardeningFinding`
embeds the Windows `WindowsFinding`, so `settings` and `settingsOmitted` are
the Windows fields). States are `in_place`, `not_in_place`, `reported` (built
into the kernel, a Kubernetes node) and `not_applicable`. Where several
things share one line of text (open firewall ports, AppArmor profiles in
complain mode, trusted ranges, container storage excluded from AIDE) one
setting stands for the group. A check that did not run (module not
applicable, sshd missing, auditd not installed) lists no setting for what it
did not read.

*How a mixed fleet reads.* The server embeds the script and sends it with
each job, so a new server never receives a new result from an old script and
an old server never sees `settings`; results already stored have the text
lists only, and the stored JSON and the API only gain an optional field. A
reader that needs a setting by id treats a module whose result has no
`settings` (stored before C0) as `unknown`, never `in_place`, and a setting
absent from a result as `unknown`; the text lists keep working for the
console. When the result is too long the script drops the settings in place
first (`settingsOmitted = in_place`), then all (`all`), as Windows does.

#### C1: the library, packs and scan

*Goal:* the content model, the pack loader with licence checks, the build
check, the first packs, per-control results, and a scan that reuses the
executors. No fixes.

Files:
* `server/migrations/90780_compliance_library.sql` (global tables) and
  `90781_compliance_results.sql` (per-organization tables), goose up and
  down.
* `server/internal/compliance/` : `model.go`, `library/` (control loader,
  embedded content), `packs/` (loader, licence class checks, signature
  check), `scan/` (planner, ingester), `rollup/`, `store.go`.
* `server/internal/compliance/content/` : `manifest.json`, `controls/*.json`
  (the ~140 existing Windows settings expressed as controls, generated from
  `windows-settings.json`; the Linux settings), `packs/nist-800-171r2.json`,
  `cmmc-l1.json`, `cmmc-l2.json`, `nist-800-53r5.json` (a view),
  `nist-csf-2.json`, `hipaa-security.json`, `stig-*.json`, `gdpr-indicative.json`,
  `soc2-tsc-indicative.json`, `cis-xref.json` (numbers only).
* `server/cmd/packlint/` : the build check (section 10), and `make` and CI
  wiring.
* `server/internal/httpapi/complianceapi/` : list packs, profiles, start
  scan, read results (hand-written API in the repo's style).
* `server/internal/rbac/rbac.go` : the permissions (additive).
* `server/internal/app/app.go` : wiring (additive).
* `web/src/pages/organizations/CompliancePage.tsx` (counts and results; no
  queue), a device's Compliance panel (read-only), the Settings pack list.

Tests:
* Unit: loader rejects each class in the `commercial` edition; unknown
  control id in a mapping; a `technical` requirement with no control and no
  explicit "no check yet"; control versions; manifest hash mismatch; banned
  marker scan; weights sum to 313 (data check for C5's use, loaded here).
* Table test of the ingester: setting ids to control ids; each state; managed
  elsewhere; stale and unknown.
* Roll-up table tests: one failing in-scope device fails the requirement; an
  out-of-scope failing device does not, and is listed; `unknown` never
  counts as passing; a requirement mapped only as `related` is never
  *checked*.
* Integration (real PostgreSQL, own database name): RLS (an organization
  cannot read another's results; the library is read-only to the app role),
  scan creates the expected jobs and nothing for a `devscope`-disallowed
  organization, migration down.
* `packlint` golden tests with a deliberately restricted fixture pack.
* Web: vitest for the counts, the hidden tab, wording ("compliant" never
  appears: a test greps the rendered strings).

#### C2: results and the fix queue

*Goal:* fixes with agreement. **Needs ADR-0054 W2** (apply and undo) for
every module it fixes, and step-up for T3 (see the slice order). T1 first,
then T2, then T3 one module at a time, each after its machine test;
BitLocker waits for the keystore.

*Script change (new, part of C2).* Today both scripts take **module names**
(`Hardening.Modules` in `hardening.go`; `Read-ErArguments` in `windows.ps1`).
A fix must change **one control**, not a whole module, or the agreement does
not match what runs. C2 extends both scripts to accept **setting ids**
(`--settings id,id` and the Windows equivalent), validated against the
settings file, and signed in the job like the module list. A job carries
either modules (as now) or setting ids (from the queue), never both. Windows
and Linux scripts apply only the listed settings, read each back, and return
the typed per-setting result.

Files:
* `server/migrations/90782_compliance_fix_queue.sql` (items, agreements,
  approvals, declines, org settings).
* `server/internal/compliance/fix/` : `queue.go`, `tier.go` (the tier
  table), `agreement.go` (warning ids, hash, typed text), `dispatch.go`
  (builds the hardening job, calls `modules.Allowed`/`devscope.Allowed`),
  `verify.go` (single-control re-scan), `approval.go`.
* `server/internal/compliance/content/warnings/*.json` (our own warning
  text, versioned, hashed).
* `server/internal/httpapi/complianceapi/fix.go`.
* `server/internal/jobs/hardening.go` : accept a control-id list from the
  queue (additive, at the existing apply entry point).
* Web: the organization's fix queue, the device's item list, the T2 and T3
  dialogs, decline and approval screens, alert kinds.

Tests:
* Unit: tier table has every control; T3 dialog refuses a wrong typed text;
  agreement hash covers the warning version; no bulk path above T1 (an API
  test sends a bulk T2 and T3 request and gets 400); requester cannot
  approve their own item.
* Integration: apply writes an agreement and audit row for each item; step-up
  required for T3 (without it, 403); precondition failure blocks dispatch;
  disallowed organization gets no job; failed read-back marks `failed`;
  fix does not change a requirement status until a re-scan; undo.
* Runner tests on the Windows runner (ADR-0054's matrix) for each module
  added; machine test recorded per T3 module.
* e2e: agree and apply a T1 item, type-confirm a T3 item (Playwright, under
  the e2e lock).

#### C3: about 15 new endpoint checks

*Goal:* the A-class requirements that have no check today, each as a
control with detect, fix and undo, written by us from public documentation.

The 15 (from the research): user-rights assignments and local administrators
(3.1.2, 3.1.5), legal notice (3.1.9), inactivity lock (3.1.10), RDP idle and
disconnect limits (3.1.11, 3.13.9), removable-storage policy (3.1.21, 3.8.7),
time source and synchronisation (3.3.7), who holds audit and security-log
rights (3.3.9), AppLocker or WDAC (3.4.8, audit-mode generation first),
installed software against an allow-list (3.4.9, from the inventory),
credential feedback (3.5.11), FIPS mode (3.13.11), mobile code and Office
macro policy (3.13.13), plus Linux equivalents for SSH session limits and
account lockout.

Files:
* `server/internal/jobs/hardening/windows-settings.json` and `windows.ps1`:
  new modules (additive), their undo.
* `server/internal/jobs/hardening/linux.sh`: Linux equivalents.
* `server/internal/compliance/content/controls/…` and the 800-171 mapping
  additions.
* `server/internal/jobs/hardening/controls/` : cites for the new settings.

Tests: the persistence test and runner tests per module (write, read back,
undo, restart-pending, managed-elsewhere); Linux tests in the existing SSH
integration harness; a static test that every new setting has a control, a
tier and a warning; STIG-id-in-release check as ADR-0054.

#### C4: domain controller checks

*Goal:* checks that read the directory, not the member computer. Depends on
ADR-0075's collector (reuse it, do not add one) and on the domain-controller
option.

Controls: Default Domain Policy password and lockout; LDAP signing and
channel binding; Kerberos encryption types and RC4; `krbtgt` age; DSRM;
Print Spooler on DCs; SMB signing required; membership of Domain, Schema and
Enterprise Admins and Administrators; stale and password-never-expires
accounts; AD audit subcategories; time hierarchy via the PDC emulator;
SYSVOL and AD backup recency; replication health. File servers: shares and
permissions on shares, SMB encryption, shadow copies, data-volume BitLocker.

Files: `server/internal/compliance/content/controls/ad-*.json`,
winmod read actions in ADR-0075's catalogue (names agreed with that
ADR; no write action here that ADR-0075 does not own), the domain
tier-3 items (fix through a Group Policy object only with the option and
typed agreement), `server/internal/compliance/scan` (a `domain_controller`
scope).

Tests: the Proxmox domain-controller VM scenario of ADR-0073's test plan;
every item that edits a GPO is in the T3 table; protected-account guard
(ADR-0073) is honoured by every fix; read-only controls pass the
`winmod` lint.

#### C5: CMMC SSP, POA&M, evidence, OSCAL export, SPRS range

*Goal:* the assessment workspace, as our own build modelled on the ideas of
Open-CMMC (coverage by who delivers each requirement) and Kell Engineering's
stack and similar; nothing copied (licences in the appendix).

Files:
* `server/migrations/90783_compliance_assessment.sql` (assessments, scope,
  implementations, objective results, evidence, links, attestations,
  POA&M items and milestones, documents, sections, score snapshots).
* `server/internal/compliance/assess/` : `workflow.go` (draft, in review,
  approved, archived; copy-on-write freeze), `rollup.go` (scan to objective
  determination, rule in section 12), `sprs.go` (weights, range, gate),
  `poam.go` (eligibility), `ssp.go` (templates, generated sections),
  `evidence.go` (envelope-encrypted blobs, 64 MiB cap, SHA-256, never
  deleted, superseded, download audit; see *Evidence storage*), `oscal/` (export), `export/` (CSV, ZIP bundle, PDF).
* `server/internal/compliance/content/templates/` : SSP, POA&M, policy and
  procedure skeletons, **in our own wording**. There is **no DoD template** for
  an SSP or a POA&M (research, "DoD POA&M spreadsheet template ... not
  located"), so the fields follow the NIST OSCAL SSP and POA&M models and
  the CMMC Assessment Guide. Where CC BY 4.0 skeletons are reused, attribution
  is kept (*decided in review*).
* `server/internal/httpapi/complianceapi/assess.go`.
* Web: the CMMC workspace (scope editor, per-requirement view with
  objectives, statements, evidence attach, attestation, POA&M board, SSP
  editor, exports).

Tests: SPRS weights sum to 313 and the table matches the DoD methodology
(a fixture of the published weights, our own transcription, reviewed against
the PDF); range logic (lower bound with unassessed failing, upper bound with
unassessed passing; a number only when equal); the L2 conditional gate (at
least 88 and no POA&M item above 1 point, with the 3.13.11 exception, the
six practices barred from a POA&M, 180 days); freeze (approved records
cannot change); attestation requires step-up and a statement and expires;
evidence immutability and hash; OSCAL output validates against NIST's
published schema in CI (the schema is fetched at a pinned version and
checksum, or vendored as public-domain data); RLS across organizations;
audit event per state change; export hash recorded.

### Evidence storage

*Amended 2026-11-26 (decided in review):* evidence is **encrypted at rest**.
ADR-0066's plain `bytea` pattern is not used for compliance evidence,
because it may hold CUI.

* **What exists and is reused.** `server/internal/secrets` (`Sealer`)
  already seals small values with AES-256-GCM under a master key carrying a
  key id, supports rotation (`NeedsReseal`), takes associated data, and
  derives keys (`DeriveKeys`). Evidence reuses it as the **key-wrapping
  layer**. The `Sealer` is for small secrets, so it is not used to seal a
  64 MiB body directly.
* **Envelope encryption.**
  * Each organization has one **data key** (32 random bytes) in
    `compliance_org_keys`, **wrapped** by `Sealer.Seal` with associated data
    `easyrmm:compliance:dek:<organization_id>`; created on first use,
    never stored in clear.
  * Each evidence file is encrypted with **AES-256-GCM** under that data key
    with a fresh 96-bit nonce per file and associated data
    `easyrmm:compliance:evidence:<organization_id>:<evidence_id>`, so a
    blob cannot be moved to another organization or row. The ciphertext
    and nonce are stored (`body`, `nonce`, `key_id`).
  * The SHA-256 recorded is of the **plaintext**, computed before
    encryption, and is checked on every download.
  * Rotation: when the server master key rotates, only the wrapped data
    keys are re-sealed (`NeedsReseal`); blobs are untouched. A data-key
    rotation (new `key_id`) re-encrypts in the background and is a later
    task, not in C5.
  * The 64 MiB cap stays (with `http.MaxBytesReader`, ADR-0066's pattern).
    The body is held in the database so backups contain it, as ADR-0066
    does, now as ciphertext. **A backup that holds the evidence also holds
    the wrapped keys, and the master key is kept apart** (the existing
    backup guide's rule for `EASYRMM_SECRET_KEY`).
  * If the plan's keystore (step 19) lands, wrapping moves to it; until
    then this depends only on what `secrets` already provides.
* **Access.** Per-organization RBAC: reading or downloading needs
  `compliance.view` for that organization (a user of another organization
  gets 404, and the row-level policy agrees); upload needs
  `compliance.edit`. **Every download and every upload writes an audit row**
  (`compliance.evidence.download`, `.upload`): user, organization, evidence
  id, hash, time, source address.
* **Retention.** Evidence is never deleted, only superseded; a retention
  period, **default 6 years, configurable per organization**
  (`compliance_org_settings.retention_years`), decides when a superseded
  or expired item may be purged by an administrator action that is itself
  audited. **Pending owner confirmation** (owner decision 2); the CMMC
  rule's own period was not verified.

### 12. The CMMC workspace (C5 in outline)

The data model is in the appendix. The rules the code follows:

* **Scope is recorded, not inferred.** Per assessment, devices and groups are
  tagged CUI asset, security protection asset, contractor risk managed asset,
  specialized asset or out of scope. Out-of-scope devices are listed on the
  report, never dropped silently. (The scoping categories' exact wording is
  unverified; the table's labels are ours.)
* **Scan to objective**: all in-scope assets pass the objective's mapped
  controls gives *met by scan*; any `not_in_place` or `failed` gives *not
  met*; `unknown`, `stale`, `not_supported` gives *not assessed*. A
  requirement is *met* only when every objective is met, by scan, attestation
  or upload alike. Automatic determinations never go beyond objective level
  for a requirement with a non-technical objective.
* **Attestation** is evidence, never a scan result: a named person states
  "implemented", with scope, text, date and expiry (default one year),
  signed with step-up.
* **Responsibility**: customer, MSP, inherited or shared, with an owner per
  requirement (EasyRMM's own contribution is one such owner).
* **POA&M**: a failing requirement creates a draft item with the failing
  hosts, the fix-queue items, the weight and the 180-day clock; the owner
  confirms. Eligibility follows 32 CFR 170.21 as the research read it (**the exact
  paragraph text should be re-read when C5 starts**): at most one point per
  item (single exception: 3.13.11 where encryption is used but not
  FIPS-validated), closeout within 180 days, and **these may never be on a
  POA&M**: 3.1.20 (external connections), 3.1.22 (publicly accessible
  content), 3.12.4 (the SSP), 3.10.3 (visitors), 3.10.4 (physical access
  logs) and 3.10.5 (physical access devices). The six are data
  (`flags.poam_barred`) and a test.
* **SPRS**: start at 110, subtract the weights of requirements that are not
  met (the DoD methodology's 5, 3 and 1 point values and the two partial
  credit cases). Show *score if unassessed fail* and *score if unassessed
  pass*; show a single number only when they are equal. Never post to SPRS.
* **Assessment freeze.** Approval freezes the record; a later scan opens a
  new draft.
* **OSCAL** (system security plan, assessment results, POA&M).
  * **Catalogue:** NIST publishes an OSCAL catalogue only for 800-171 r3.
    The r2 catalogue and profile are **generated by us** from NIST's r2
    publication and its 171A objectives XLSX/CSV (public domain), by a
    checked-in generator that records the source checksums
    (like `controls/extract`).
  * **Validation:** the generated catalogue, and every exported SSP,
    assessment-results and POA&M file, is validated in CI against NIST's
    **OSCAL JSON schema** for the pinned version, with the schema file
    vendored at a pinned checksum (public domain).
  * **Pinned version:** OSCAL **1.1.2** (`oscalVersion` constant in
    `oscal/`; C5 confirms it against NIST's release page before use and
    changes it only by an ADR amendment).
* **Evidence may hold CUI.** Per organization access control only, no
  cross-organization aggregates without `compliance.view` at the root. The
  appendix lists the external-service-provider question as a risk for
  counsel, not as settled.

### 13. Amendments to ADR-0054

*Amended 2026-11-26 (decided in review, at the owner's direction of
2026-11-24):*

1. **Basis, wording.** ADR-0054 says the console never says "compliant",
   "CIS Level 1", "STIG compliant" or "CMMC", and makes no claim about CIS.
   That is replaced by section 9 above: the console may name frameworks and
   show *meets* and *does not meet* for what it can check, with the
   assessment-aid disclaimer. It still never says "compliant", "certified"
   or "CIS certified", and it makes no claim about any CIS certification.
   CIS numbers appear only as cross-references, only when the pack's review
   gate (section 10) allows, and never with CIS wording.
2. **Basis, CIS content.** ADR-0054's "No CIS numbers, titles or text"
   becomes: no CIS titles, descriptions, rationale, remediation or values as
   content; cross-reference numbers only, in our own checks, behind the gate.
   Nothing from Wazuh, ever.
3. **Lock-out guards.** The guards stay as the **defaults**. A *typed
   agreement* may lift these, item by item (the owner's rule): the firewall
   two-step and its block rules, NLA before the RDP test, the lockout
   exposure option, deny-logon rights, disabling or renaming an account,
   NTLM on a domain controller (still with the `domain-controller` option),
   removing the built-in Administrator's network rights without 30 days of
   evidence. The agreement dialog names the guard being lifted.
4. **What stays, because it is technical, not policy:** a value is read back
   after writing, and put back if wrong; restarts are reported, never
   performed; one change at a time on a device; the EasyRMM agent, MeshAgent
   and EasyPatch agent services are never stopped, disabled or blocked, and
   no control that would cut their outbound connection exists in the library
   (an undo depends on the agent, so this cannot be recovered remotely;
   *decided in review*, the owner can overturn). Credential Guard or VBS
   locked in firmware is reported as not undoable.

## Tests (whole feature)

* A hostile-content test: a pack that claims `ORIGINAL` but contains a
  banned marker fails the loader.
* A test that nothing under `content/` is imported by `agent/` (packs are
  server data).
* Wording test: no UI string or report template contains "compliant" except
  in a negation fixture.
* `devscope`: a test that no code path in `compliance` dispatches a job or
  evaluates an alert without `devscope.Allowed(orgID)` (a catalogue lint, as
  in ADR-0073).
* Coverage floors set per package in `check-coverage.sh` once each slice
  lands.

## Organization scope

Every automatic behaviour here (scheduled scans, hand-started scans, fixes,
alerts, default policies) checks `devscope.Allowed(orgID)` once per tick or
request, through the ADR-0073 framework gate where that exists and
`devscope.Allowed` directly until it does. The guard has landed
(`server/internal/devscope`).

## Consequences

* One check serves many frameworks; adding a framework adds a pack, not
  code.
* The product can ship commercially because the embedded content is
  independently written or public domain, and the build refuses anything
  else. The cost is writing and maintaining our own checks, titles and
  warnings; the CIS recommendation list is not a shortcut.
* The CIS cross-references remain a legal question until counsel or CIS
  answers; the build gate makes that visible.
* Fixes are the product's most dangerous feature. Tiers, agreement, undo and
  audit are the defence, and T3 modules each need a machine test before they
  ship.
* GDPR, SOC 2 and PCI results are indicative; the console says so.
* Evidence uploads grow the database and its backups (ADR-0066's pattern).
* The assessment workspace may put EasyRMM inside a customer's CMMC boundary;
  that is a risk for counsel, not decided here.

## Owner decisions

Only these are open. Everything else above is decided in review.

1. **CIS cross-references in commercial releases.** Choose one: (a) ship the
   `cis-xref` pack only after counsel's written opinion or a CIS membership
   agreement is recorded as clearance; (b) buy CIS SecureSuite Product Vendor
   membership and certification, which allows CIS wording and the claim; (c)
   leave the pack out of commercial builds and keep it in `dev`. The engine
   works with any. The owner has said to include them; this is who clears
   them and what evidence counts.
2. **Retention of compliance records** (assessments, attestations, evidence,
   the audit rows): the design defaults to **6 years, configurable per
   organization, pending owner confirmation**. The CMMC rule's retention
   period was not verified.

Not owner questions (stated so they are not asked again): the Elastic
License 2.0 project is ideas only and nothing is reused; CC BY 4.0 skeleton
templates may be used with attribution (decided in review); step-up
authentication is a scheduling dependency (slice order), not a decision.

## References

* [Requirements, 2026-11-24](../requirements/2026-11-24-compliance-engine.md).
* Research: `/var/tmp/easyrmm-research-2026-11-24/cmmc-research.md`
  (CMMC, NIST 800-171, CIS, Wazuh, SCF, and the six linked projects).
* `server/internal/jobs/hardening/` (script, settings file, `controls/`),
  `server/internal/jobs/hardening.go`, `server/migrations/00027_hardening.sql`,
  `server/internal/devscope/devscope.go`, `server/internal/rbac/rbac.go`.
* Appendices: [data model](../compliance/data-model.md),
  [examples](../compliance/examples.md),
  [licensing and legal](../compliance/licensing-and-legal.md).
