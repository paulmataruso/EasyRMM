# Compliance engine: licensing, distribution and legal risk

Appendix to [ADR-0078](../adr/0078-compliance-engine.md), deliverables 1, 10
and 11 of the requirements. **This is an engineering assessment, not legal
advice, and it settles no legal question.** Where the terms need a lawyer, it
says so. Facts are separated from assumptions, and each fact names where it
was read.

Key for the tables: **V** = verified (a primary source was read during the
2026-11-24 research or while writing this ADR; the source is named);
**A** = assumption, memory or secondary summary, not re-read; **Q** = a
question for counsel.

## 1. Assessment of the CIS licensing implications

Deliverable 1. The research (`cmmc-research.md` sections 5, 10.1 to 10.3)
read the following.

### What is verified

| # | Fact | Basis |
|---|---|---|
| 1.1 | CIS Benchmark publications are distributed under CC BY-NC-SA 4.0, with CIS's own terms for non-members. **V for the licence name in ADR-0054's reading of the CIS pages; the licence line was not re-read on 2026-11-24**: the fetched `cisecurity.org/cis-benchmarks` page showed a 2026 copyright and the SecureSuite tailoring offer but not the licence line. Re-read before relying on it | ADR-0054 *Basis*; research 10.1 |
| 1.2 | CC BY-NC-SA 4.0 (**A**, see basis) forbids commercial use of the licensed material and requires adaptations to be shared under the same licence | Creative Commons, *Attribution-NonCommercial-ShareAlike 4.0 International* legal code, <https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode> (sections on NonCommercial and ShareAlike); stated here from knowledge of the licence and **not re-read in this session (A)** |
| 1.3 | CIS's non-member terms, as ADR-0054 read them, forbid selling or exploiting a non-member product, creating derivative works and claiming a level of compliance; "Incorporating CIS-CAT Pro or other CIS tools into a product ... is not permitted under the CIS SecureSuite Membership" | ADR-0054 *Basis* and *Open questions* (CIS terms pages at the time) |
| 1.4 | CIS offers a SecureSuite **Product Vendor Membership** giving "licensing rights to the CIS Benchmarks and/or CIS Critical Security Controls for commercial use", and requires **Benchmarks Certification** when benchmarks are integrated; certified logo only after award; no "certification pending" wording | CIS Product Vendor pages (research 10.3) |
| 1.5 | The Product Vendor fee is **not published today** ("Contact Us for Pricing"); ADR-0054 quoted a range from $6,000 to $80,000 a year by revenue, not re-confirmed | research 10.3 |
| 1.6 | Wazuh's Windows SCA files carry CIS's text (name, description, rationale, impact, remediation) in a file headed GNU GPL version 2, "Copyright (C) Wazuh Inc." The repository LICENSE puts "everything else" under GPL-2.0 and the engine under AGPL-3.0-or-later | `wazuh/wazuh`, `ruleset/sca/windows/cis_win11_enterprise.yml` and `LICENSE`, read in research 10.1 |
| 1.7 | No CIS permission statement, NOTICE or membership claim was found in the Wazuh repository; whether Wazuh holds a CIS vendor membership is **unverified** | research 10.1 |
| 1.8 | Wazuh's compliance mapping arrays sit in those same GPL files and are Wazuh's selection; their origin is not stated in the files | research 10.2 |

### What follows for the design (engineering, not legal, conclusions)

1. **Do not ship CIS expressive content**: titles, descriptions, rationale,
   impact, remediation text, and any benchmark PDF or XCCDF/OVAL file. The
   control library contains none. The build refuses it (ADR-0078 section 10).
2. **Do not copy Wazuh.** Its files are CIS text under GPL; copying even
   their mapping arrays risks GPL obligations on EasyRMM (FSL-1.1-ALv2 is not
   GPL-compatible in that direction) and carries CIS's derivative problem.
3. **The GPL of Wazuh, or any open licence on a repository that reproduces
   CIS text, does not override CIS's terms.** The requirements say so
   explicitly. We do not infer a CIS grant from Wazuh's packaging.
4. **Independently written checks of the same technical settings are the
   design.** The setting, its registry key and a vendor-recommended value are
   facts or vendor documentation, not CIS's expression. The owner's decision
   (2026-11-24) is to include CIS coverage by this route, cross-referenced by
   recommendation number.

### What is not settled (assumptions and questions)

| # | Question | Status |
|---|---|---|
| 1.9 | Whether *independently written* checks of the same settings are derivative works of the benchmark under CC BY-NC-SA 4.0 or CIS's terms | **Q**. Background authorities counsel will know: 17 U.S.C. 102(b) (ideas, procedures and methods are not protected), *Feist Publications v. Rural Telephone*, 499 U.S. 340 (1991) (facts are not copyrightable; selection and arrangement can be), *Baker v. Selden*, 101 U.S. 99 (1879). These are cited from memory (**A**) and not re-read. The research found no CIS statement and no case on point |
| 1.10 | Whether CIS recommendation **numbers**, level (L1/L2) assignments and the *ordering* of a benchmark are protectable, or a trademark or contract matter | **Q**. The numbers may be facts; the selection and ordering and the level assignment are CIS's judgement. The ADR therefore stores only numbers, never levels, titles or order |
| 1.11 | Whether CIS's non-member terms bind a person who only *reads* a benchmark to write checks (contract by browse-wrap), or only a person who redistributes | **Q** |
| 1.12 | Whether naming "CIS" in a cross-reference counts as a claim "of a level of compliance" under CIS's terms | **Q**. Mitigation: the fixed wording of ADR-0078 section 9 |
| 1.13 | CIS trademarks ("CIS", "CIS Benchmarks", the certified logo) and the certification rules | **V** that CIS requires certification before a certified claim and bars "certification pending" (1.4); **Q** whether a plain cross-reference needs any of that |

## 10. Commercial distribution strategy

Deliverable 10. (The mechanics are in ADR-0078 section 10; this is the
strategy.)

1. **Ship what is ours or public.** The commercial image embeds: our
   controls, warnings and templates (`ORIGINAL`); NIST, DoD, eCFR, HHS,
   DISA ids and CCI data (`PUBLIC_DOMAIN`, 17 U.S.C. 105 for US government
   works; NIST's OSCAL repository states its licence in `LICENSE.md`, read in
   research); attribution-licensed templates with their `NOTICE` (for
   example Kell-style or collingeorge's CC BY 4.0 `docs/`, with attribution
   kept and changes noted). Nothing else.
2. **Sell the engine, the library and the workflow**, not frameworks. The
   subscription value is our checks, fixes, mappings in our words, and the
   assessment workspace, none of which depend on a benchmark's text.
3. **Frameworks whose text is not free** (SOC 2 criteria, PCI DSS, ISO 27001,
   CIS) are carried as ids and our own short titles only, and the console
   tells the customer to use their licensed copy of the standard for the
   criteria themselves.
4. **CIS is an optional, gated layer.** The `cis-xref` pack (numbers only)
   is in the repository and loads in `dev`; it ships in a commercial build
   only after clearance is recorded (owner decision 1 in the ADR). Routes, in
   the order the research ranked them:
   * (D) *Do not offer CIS*: nothing to clear; STIG, Microsoft baseline and
     other frameworks stay. Valid fallback.
   * (A) *Product Vendor Membership and certification*: the only clean way to
     use CIS wording and claim "CIS". A business decision for the owner; fee
     and timeline unknown.
   * (B, now the owner's chosen design) *own checks, numbers only*: free,
     with the legal risk of 1.9 to 1.12; clearance means counsel's opinion.
   * (C) *Import a customer's CIS-CAT results*: possible later; whether
     CIS-CAT's terms allow third-party ingestion is **unverified**.
5. **Customer-licensed packs.** A customer with their own CIS (or other)
   licence may install content into their own installation. EasyRMM never
   assumes that their licence lets us redistribute, so customer content is
   never embedded, never shared between organizations, excluded from exports
   by default, and carries no executable code. The installer attests that they
   hold the licence (a record, not a legal check).
6. **No copyleft and no Elastic License code.** Wazuh (GPL/AGPL) content and
   nealfennimore/cmmc (Elastic License 2.0, which forbids offering the
   software as a hosted or managed service) are ideas only. Open-CMMC
   (Apache-2.0) and ComplianceAsCode (BSD-3-Clause) are permissive, but
   nothing from them is needed. ADR-0037 allows only permissive
   dependencies.
7. **A review loop.** Every pack carries a `review_state`; a quarterly
   re-read of the licences in `compliance_sources` (the `retrieved_at` date
   makes stale ones visible) and a re-run of `packlint` on each release.
8. **Marketing wording** follows ADR-0078 section 9: assessment aid, never
   "compliant" or "certified", never "CIS Level 1", and no claim that
   EasyRMM files or can file anything with SPRS.

## 11. Licensing and legal risks needing review

Deliverable 11. Ordered by what blocks what. "Blocks" says which release the
item holds back until reviewed.

| # | Risk | Status | Why it matters and what to ask | Mitigation in the design | Blocks |
|---|---|---|---|---|---|
| R1 | Independent checks and cross-reference numbers as derivatives of CIS benchmarks | **Q** (see 1.9 to 1.12); no authority found either way | Could CIS or a court treat our checks, the numbers or the selection as a derivative or a breach of terms? Ask for a written opinion on numbers-only cross-references | numbers only, no levels, titles or order; our wording; `review_state = needed` gate | commercial release of `cis-xref` |
| R2 | Claims: "CIS", "meets CIS", certification | **V** that CIS requires certification for claims (1.4); **Q** for plain mentions | Does naming CIS in a cross-reference require a licence? Is the disclaimer enough? | fixed wording; never "CIS Level 1" or "certified" | `cis-xref` |
| R3 | Wazuh content or mappings in our library by accident | **V** that they are GPL and carry CIS text (1.6) | contamination of a source-available product | never copied; `packlint` banned markers; reviewer checklist (the author states `derived_from_content: false`) | all builds |
| R4 | Mappings: ours from public requirements, versus third-party crosswalks (SCF, AICPA, CIS white papers) | **V** that SCF's official terms say CC BY-ND 4.0 and its commercial licence starts at $200,000 a year (search summaries; a test site contradicts, do not rely); **A** for the rest | Do our own mappings overlap a protected selection and arrangement? Is a reviewer using SCF as a cross-check a risk? | build from NIST, HHS, DoD, DISA mappings; cite requirement numbers; never import SCF, Wazuh or CIS tables; SCF may be read by a reviewer only | all packs |
| R5 | Free but not freely reusable frameworks: SOC 2 TSC (AICPA), PCI DSS (PCI SSC), ISO 27001, GDPR text reuse, Essential Eight (ASD), Cyber Essentials (NCSC) | **A**: licences not read for any of them (research 10.6) | can we store even ids and our short titles? may we quote criteria? | ids and our own titles only; "indicative" labels; the customer's licensed copy is the criterion | each pack's release |
| R6 | "CMMC" and "Cyber AB" marks; DoD and NIST names | **A** (status of the marks unverified); descriptive use of a program name may be nominative use (15 U.S.C. 1125; **A**) | can the product name CMMC, show practice ids, say "assessment aid"? | descriptive use only; disclaimer on every screen; no logo, no "certified" | any release that names CMMC |
| R7 | The assessment workspace may put EasyRMM inside a customer's CMMC boundary as an external service provider when an MSP hosts an SSP or CUI-bearing evidence | **A**: the rule's ESP treatment (32 CFR 170) was not read (research 8.4) | scope, FedRAMP-equivalence, flow-down; also whether uploads can hold CUI | per-organization access control and encryption; a statement in the UI that uploads may become CUI; evidence is never cross-organization | C5 release, any CUI hosting claim |
| R8 | Reuse of the SSP, POA&M and policy skeletons from collingeorge (CC BY 4.0 `docs/`, MIT code) | **V** for the licence names (research 6, 8.2); **A** that the repo's licence applies to every file | attribution wording, whether our rewritten skeleton is an adaptation | write our own wording by default; where reused, keep attribution and note changes in `NOTICE` and the `ATTRIBUTION_REQUIRED` class | C5 release |
| R9 | The DoD assessment methodology weights and the CMMC Assessment Guide | **V** for the methodology v1.2.1 read from a university-hosted copy; the DoD original failed TLS from the research environment; **A** for the Assessment Guide licence (research 9) | provenance of our weights table; whether the guide may be redistributed | our own transcription, verified against the DoD PDF by a person, and a test that the weights sum to 313; the guide is linked, not bundled | C5 release |
| R10 | nealfennimore/cmmc is Elastic License 2.0 (forbids hosted or managed use) | **V** (LICENSE.md read in research) | none if we copy nothing | ideas only (field names, status set); no code or data | all builds |
| R11 | Kell Engineering's stack and Open-CMMC: licence and provenance | Kell: site says MIT, repo unopened (**A**); Open-CMMC: Apache-2.0 (**V**, LICENSE read) | whether any text or table is reused | ideas only (coverage by who delivers each requirement); nothing reused | all builds |
| R12 | US-government material: NIST, DISA, eCFR, DoD | **V** NIST publications and OSCAL content state public domain or CC0 (`LICENSE.md` read for oscal-content); 17 U.S.C. 105 for federal government works; DISA STIG files carry no distribution statement (ADR-0054 found none; the Windows 11 overview points to `public.cyber.mil`) | DISA's terms for the STIG files themselves; foreign copyright where applicable | ids and our own words only (as ADR-0054) | all builds |
| R13 | Microsoft baselines, LGPO and Security Compliance Toolkit terms | **V** that ADR-0054 found no licence file and LGPO terms restrict redistribution; **A** for the rest | whether using a recommended value is only using a fact | values as facts, nothing shipped | all builds |
| R14 | Remediation that causes damage (lock-out, data loss) | not a licence risk but a liability risk | warranty disclaimers, terms of service, and whether the agreement record is enough evidence that the administrator chose the change | per-item agreement, typed confirmation for T3, undo, audit; the product's terms must cover it | first customer release with fixes |
| R15 | Personal data in results and evidence (usernames, hostnames, SSP text); GDPR and similar | **A** | retention, access, subject rights, processor role of an MSP | per-organization scope, retention as owner decision 2, redaction of sensitive values as ADR-0063 | any release |
| R16 | Statements that look like legal or audit conclusions ("meets HIPAA", "SPRS score") | design risk | misleading claims; US False Claims Act exposure for a contractor who relies on an inflated SPRS score (**A**; for counsel) | range not number, "estimate", never posting to SPRS, fixed disclaimers | any release |
| R17 | Customer-installed packs: a customer uploads text they do not hold rights to | **A** | our liability as host | installer's attestation, isolation, no redistribution, removal on request | customer packs |
| R18 | Trademark and licence terms of the CIS-CAT, STIG viewer and other member tools (option C) | **A** unverified | whether ingesting their output is allowed | not built in this ADR | any option-C slice |

### How to read the status column

* A **V** row means a primary source was read and is named in the section
  where that source appears, or in the research file's *Sources* list. The
  research notes which pages could not be fetched (acq.osd.mil failed TLS;
  ASD and NCSC timed out or returned 404).
* Every legal-authority citation in 1.9 is from memory and has **not** been
  re-read; counsel should treat them as pointers.
* The CIS licence line itself, today's CIS fee, Wazuh's CIS position, SCF's
  position on crosswalk derivatives, AICPA, PCI SSC, ISO, GDPR-text, ASD and
  NCSC terms, the CMMC Assessment Guide licence, the OSCAL version to target,
  and the CMMC rule's retention and ESP provisions are all **unverified**
  (research sections 9 and 10.6).

### Sources

* Creative Commons, CC BY-NC-SA 4.0 legal code,
  <https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode>.
* CIS, Benchmarks page and SecureSuite Product Vendor pages,
  <https://www.cisecurity.org/cis-benchmarks>; terms as read in ADR-0054.
* Wazuh, <https://github.com/wazuh/wazuh>, `LICENSE`,
  `ruleset/sca/windows/cis_win11_enterprise.yml` (research 10.1).
* NIST, <https://github.com/usnistgov/oscal-content>, `LICENSE.md`; NIST SP
  800-171 Rev. 2 and Appendix D; SP 800-171A; SP 800-66 Rev. 2.
* 32 CFR 170.14, 170.15, 170.21, 170.24 (eCFR).
* DoD, *NIST SP 800-171 DoD Assessment Methodology* v1.2.1 (copy read: see
  research section 4).
* Elastic License 2.0, <https://www.elastic.co/licensing/elastic-license>;
  `nealfennimore/cmmc` `LICENSE.md`.
* `collingeorge/cmmc-l2-reference` (MIT code, CC BY 4.0 docs);
  `TroutSoftware/Open-CMMC` (Apache-2.0); `docs.kellengineering.com`.
* Secure Controls Framework terms and commercial-licence pages,
  <https://securecontrolsframework.com> (search summaries, research 10.4).
* 17 U.S.C. 102(b), 105; 15 U.S.C. 1125; *Feist v. Rural*, 499 U.S. 340
  (1991); *Baker v. Selden*, 101 U.S. 99 (1879) (from memory).
