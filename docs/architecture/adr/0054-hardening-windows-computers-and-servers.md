# ADR-0054: Hardening Windows computers and servers

* Status: Accepted (2026-11-22, after an independent review and its check). Not implemented.
* Revised (2026-11-21) after its independent review and again after that
  review's check. On acceptance, brought up to date with the ADRs merged
  since (ADR-0060, and ADR-0063 to ADR-0068), each where it touches this
  ADR; where one changes something decided here, the section says so.
* Amends: [ADR-0017](0017-scripts-and-jobs.md), with W2: batch IDs, job
  retention per kind, one audit row per organization per daily batch, and
  runs the server cancels (see [The job](#the-job)).
* Builds on: [ADR-0051](0051-hardening-linux-computers.md) (the `hardening`
  job, its modes, results, permission and console),
  [ADR-0017](0017-scripts-and-jobs.md) (scripts and jobs),
  [ADR-0063](0063-who-sees-job-output-and-arguments.md) (implemented: who
  sees a run's output and a job's arguments, and how long output is kept),
  [ADR-0028](0028-software-deployment.md) (a fixed script compiled into the
  server, its input as arguments) and [ADR-0020](0020-windows-agent.md)
  (the Windows agent).
* Shares with [ADR-0060](0060-collecting-logs.md) (log collection;
  proposed, not implemented): Windows audit policy, which log collection
  sets from one table that this ADR's check compares against, and the
  reader of who owns a setting (*policy ownership*), built once, in this
  ADR's W1, for both.
* Used by later ADRs, each accepted; none implemented except ADR-0065's
  slice 1 (PR #86):
  * [ADR-0067](0067-remote-registry-editor.md) (the registry editor, and
    F2): before a write it shows W1's ownership reader's answer and
    whether W2's manifest lists the value; F2 extends W2's job amendments
    per kind; and it amends [One change at a time](#the-job) so that
    registry changes take the same lock.
  * [ADR-0068](0068-remote-event-viewer.md) (the event viewer): before a
    change to a log's settings it shows W1's reader's answer; its queries
    use the server's cancel, as F2 extends it; and it amends One change
    at a time so that `eventlog_manage` takes the same lock.
  * [ADR-0064](0064-remote-powershell-management.md) (remote PowerShell),
    [ADR-0065](0065-hardware-health.md) (hardware health), ADR-0067 and
    ADR-0068 leave their Windows paths that CI's runners cannot show
    unverified until this ADR's Windows machines under KVM, or real
    computers, show them (see [Testing](#testing)). ADR-0064's, ADR-0067's
    and ADR-0068's Windows test jobs run as LocalSystem through a
    scheduled task, as this ADR's tests do.

  This ADR gains an *Amended by* line for ADR-0067 and for ADR-0068 when
  each is implemented, as they say.

## Context
Most computers an MSP manages run Windows. The owner asked for automatic
hardening of Windows computers and Windows Server, on top of the Linux
hardening of ADR-0051, and for research into the best security benchmarks
to base it on, including the frameworks Wazuh reports against ("NIST and
ISO and CIS").

### What exists to base it on
* **CIS Benchmarks.** The best known. Current versions: Windows 11
  Enterprise 5.1.1 and Stand-alone 5.0.1, Windows 10 Enterprise 4.0.0,
  Windows Server 2025 2.1.1, Server 2022 5.1.0, Server 2019 5.0.1, Server
  2016 4.0.0. Each has Level 1 ("a base recommendation that can be
  implemented fairly promptly") and Level 2 ("defense in depth") profiles,
  separate member server and domain controller recommendations, and a STIG
  profile that replaced Level 3. **Their licence rules them out for
  EasyRMM.** The free PDFs are under CC BY-NC-SA 4.0 with CIS's terms for
  non-members, which forbid anyone to "sell, rent, lease, sublicense or
  otherwise transfer or exploit any rights to any Non-Member CIS Product
  in any way or for any purpose", "create any derivative work based
  directly on" one, or "represent or claim a particular level of
  compliance or consistency with" one. Putting them in a product needs the
  CIS SecureSuite Product Vendor Membership, "the only licensing rights to
  integrate" them. CIS's product vendor page lists "Annual membership fees
  based on enrolling organization's annual revenue", from $6,000 below
  $250,000 to $80,000 above $500 million ("Pricing in USD. Subject to
  change."), and asks other uses to contact it. "CIS Benchmarks
  Certification must be awarded ... in advance of any sale, distribution,
  or marketing", every year, per tool and type of certification.
  "Incorporating CIS-CAT Pro or other CIS tools into a product or software
  is not permitted under the CIS SecureSuite Membership". CIS's marks in
  advertising are for members only.
* **Wazuh's security configuration assessment.** Wazuh 4.14.10 (released
  2026-11-09) checks Windows with eight policies (Windows 10 and 11
  Enterprise, Server 2012 to 2025), each "Based on" a CIS Benchmark older
  than CIS's current one (Windows 11 Enterprise 3.0.0, Server 2022 2.0.0,
  Server 2025 1.0.0). In 4.14.10 the policies, like all of Wazuh, are under
  the GPL version 2; on Wazuh's main branch the engine (`src/engine`) has
  since been put under the AGPL version 3 or later. The policies reproduce
  CIS's recommendation numbers, titles, rationale and remediation text word
  for word. **What Wazuh calls frameworks are labels on those CIS checks**:
  in 4.14.10 the checks carry `cis`, `cis_csc_v7` and `cis_csc_v8` (the CIS
  Controls), `pci_dss_v4.0` and `v3.2.1`, `soc_2`, `iso_27001-2013`,
  `cmmc_v2.0`, `hipaa` and `nist_sp_800-53`. Wazuh's development branch
  moves to ISO 27001:2022 numbering and adds NIS2, NIST SP 800-171,
  FedRAMP, GDPR and MITRE ATT&CK. The labels are coarse: on that branch the
  Windows 11 policy's 482 checks share 57 distinct sets, and "Enforce
  password history" is labelled AC-2, IA-2, IA-5, AC-11, AC-7 and AU-6.
  Wazuh's own documentation calls its mappings "indicative" and says they
  "do not by themselves certify compliance". EasyRMM can use none of this:
  the content is GPL and CIS's, and [ADR-0037](0037-one-licence.md) allows
  only permissive dependencies.
* **DISA STIGs.** Current releases: Windows 11 V2R11, Windows 10 V3R6,
  Server 2025 V1R4, Server 2022 V2R11, Server 2019 V3R9, Server 2016 V2R10,
  and the Microsoft Defender Antivirus (V2R10) and Windows Defender
  Firewall (V2R2) STIGs. They are free to download, written by DISA, a
  United States government agency, and "Copyright protection under this
  title is not available for any work of the United States Government"
  (17 U.S.C. 105). Every rule has a stable ID (`WN25-SO-000310`) and names
  Control Correlation Identifiers (CCIs), which DISA's CCI list maps to
  NIST SP 800-53 Rev. 5 and, beside it, Rev. 4. Member server and domain
  controller rules are marked in the ID (`WN25-MS-…`, `WN25-DC-…`). They
  are strict and written for the US Department of Defense: three failed
  sign-ins lock an account, passwords expire, certificates must come from
  the department's own PKI.
* **Microsoft's security baselines**, in the Security Compliance Toolkit:
  Windows 11 26H2 (v2, October 2026), 25H2 and 24H2, Windows Server 2025
  (v2602, February 2026) and 2022, Windows 10 22H2, and older ones. Each is
  Group Policy backups, reports, a spreadsheet of settings and a script
  that applies them with LGPO.exe, for five profiles: domain-joined and
  standalone workstations, member servers, standalone servers and domain
  controllers. Microsoft says other organizations' recommendations
  "closely mirror Microsoft's recommendations" but are not the same, and,
  of its Intune baselines, that they are not CIS or NIST compliant,
  "strictly speaking". The baseline packages carry no licence file. The
  toolkit's standalone use terms, inside the LGPO download, allow its
  tools to be used "to develop and test your programs, and solely for use
  on Windows", and say you will not "share, publish, distribute, or lend
  the software". On Windows Server 2025, OSConfig applies the same baseline
  and corrects drift.
* **The Australian Signals Directorate** publishes *Hardening Microsoft
  Windows 11 workstations*, which the review reports is under CC BY 4.0;
  that would make it the one permissively licensed government guide
  besides the STIGs. cyber.gov.au could not be fetched while this was
  written (every request timed out), so neither its licence nor its
  contents were read, and nothing here relies on it (see Open questions).
* **Frameworks are not benchmarks.** NIST SP 800-53 Rev. 5 (release 5.2.0,
  August 2025), NIST SP 800-171 Rev. 3 (May 2024) and Rev. 2 (February
  2020), ISO/IEC 27001:2022 Annex A, the CIS Controls (v8.1) and the
  Essential Eight say what an organization must achieve, not which
  registry value to set. SP 800-53's CM-6 names STIGs among the "common
  secure configurations" an organization chooses; SP 800-171's 03.04.02
  does the same. NIST's National Checklist Program tells federal civilian
  agencies to look for a checklist from a "Governmental Authority" first
  (DISA's STIGs are there), a "Software Vendor" next and a "Third Party"
  (CIS among them) last.
* **SP 800-171 Rev. 2 is the one defence contractors are held to.** The
  CMMC rule says "The security requirements in CMMC Level 2 are identical
  to the requirements in NIST SP 800-171 R2" (32 CFR 170.14), and the
  Department of Defense's class deviation 2024-O0013 requires contractors
  under DFARS 252.204-7012 "to comply with ... (SP) 800-171 Revision 2,
  instead of the version of NIST SP 800-171 in effect at the time the
  solicitation is issued" (read from the Internet Archive's copy of the
  memorandum: the Department's own site could not be reached). Rev. 2's
  Appendix D maps each requirement to SP
  800-53 controls: "The security controls in Tables D-1 through D-14 are
  taken from NIST Special Publication 800-53, Revision 4."

### What the computers are like
* **Windows' defaults moved a lot.** A clean installation of Windows 10
  1709 or later, Windows 11 or Windows Server 2019 to 2025 has no SMBv1
  server, and no SMBv1 client except on Windows 10 Home (and Pro before
  1809), which keeps the client and removes it after 15 days unused, and
  on Windows 11 Home installed from media older than its February 2023
  release: Microsoft's page on SMBv1 says Windows 11 has no client after
  a clean installation, but its storage team's post says Home stopped
  installing the client only in Insider builds from April 2022, a change
  that "shipped in the February 2023 release", and does not say whether
  Windows 11 Home removes it when unused; computers upgraded in place may
  keep both; Windows 11 24H2 Enterprise,
  Pro and Education require SMB signing both ways, Server 2025 outbound;
  NTLMv1 is
  removed from Windows 11 24H2 and Server 2025; PowerShell 2.0 was removed
  from Windows 11 24H2 in August 2025 and from Server 2025 in September
  2025; added LSA protection is on by default on new, enterprise-joined,
  HVCI-capable installs of Windows 11 22H2 and later, and Credential Guard
  (Enterprise and Education) on domain-joined computers that are not
  domain controllers and meet its requirements (Windows 11 22H2, Server
  2025). On a new Windows 11 much of a baseline is already in place; on an
  upgraded Server 2016 little is.
* **Someone else often owns the settings.** Domain computers get Group
  Policy, which Windows applies again every 90 minutes (every 5 on domain
  controllers) and security settings every 16 hours even when nothing
  changed. Intune and other MDMs set the same settings through the Policy
  CSP; Defender for Endpoint can apply Intune's Defender and firewall
  policies to computers not enrolled in Intune; Configuration Manager's
  baselines, PowerShell DSC and Azure's machine configuration can each put
  a value back on a schedule. Group Policy can also set PowerShell's
  execution policy, which then overrides `-ExecutionPolicy Bypass` "in all
  scopes", and App Control or AppLocker can put PowerShell in Constrained
  Language Mode. A change made underneath any of these is reverted, fights
  the owner, or does not run.
* **MSPs' customers depend on what benchmarks turn off**: multifunction
  printers scanning to SMB shares, NAS boxes opened as guest, line-of-
  business software that speaks NTLM or TLS 1.0, technicians typing an
  administrator's password into a user's UAC prompt during remote support,
  local administrator accounts (the built-in one included) used over the
  network, servers whose firewall someone turned off and whose services
  listen on ports chosen at each start. EasyRMM's own agent is unsigned
  unless the operator signs it
  ([ADR-0049](0049-operators-sign-windows-agents.md)), and Defender
  features that block files "that don't yet have a positive reputation"
  could block its updates, signed or not.
* **Windows Server does not step aside for another antivirus.** On
  Windows Server 2016 and later, "Microsoft Defender Antivirus doesn't
  enter passive mode automatically when you install a non-Microsoft
  antivirus product"; on Windows 10 and 11 it does ("Disabled mode
  (happens automatically)").

## Decision

### Basis: Microsoft's values, DISA's rule IDs, no CIS
* **Values come from Microsoft's security baseline** for the Windows
  version and profile the computer has (workstation or server, joined to a
  domain or not, domain controller), except where this ADR differs from it
  for safety, which the module says. Microsoft is the vendor, publishes a
  baseline for each release (Server 2025's is from February 2026, Windows
  11 26H2's from October 2026), writes for ordinary organizations rather
  than one department, and covers the domain controller and standalone
  profiles an MSP meets. A setting's value is a fact, not text: nothing
  from the packages is copied or shipped.
* **Each setting is cited by the DISA STIG rule that covers it**, by ID and
  STIG release (`Windows Server 2025 STIG V1R4, WN25-SO-000310`), in the
  script's comments and in the console, for the Windows version the
  computer runs, **with whether EasyRMM's value meets the rule, differs
  from it on purpose, or is not set** (see What each module cites).
  Settings no STIG covers (LSA protection, LLMNR, NLA) name Microsoft's
  baseline instead. The IDs are public, stable and tied to NIST SP 800-53
  through the CCIs, which gives the framework reporting below. EasyRMM uses
  the IDs and its own words, never the STIGs' text: no distribution
  statement could be found in the files (the Windows 11 overview sends
  those without a common access card to `public.cyber.mil`).
* **No CIS numbers, titles or text, and no claim about CIS**, unless the
  owner buys the Product Vendor Membership and has the feature certified
  before it is sold, distributed or marketed (see Open questions). Nothing
  from Wazuh either.
* **No claim of compliance with anything.** The check reports what is in
  place on the computer. The console never says "compliant", "CIS Level
  1", "STIG compliant" or "CMMC", and EasyRMM's documentation says why.
* **Keeping current.** A test fails when a STIG ID the script cites is
  not in the STIG release it names; the IDs come from DISA's files, kept in
  the repository as test data (a list of IDs per release, a United States
  government work). New STIG releases and baselines are read when they
  come out, and the script's values and citations follow them.

### Frameworks: related controls, never compliance
For each module the console shows the controls its settings relate to,
built only from published mappings, from the STIG rules the module meets
or differs from on purpose (for a report-only module, the rules it
reports):

* **NIST SP 800-53 Rev. 5**: the controls the CCIs of those rules name in
  DISA's CCI list (version 2025-01-23, whose references are to "NIST SP
  800-53 Revision 5"), shown as base controls (AC-7, not AC-7 a), with
  their titles from NIST's own catalogue (release 5.2.0), a United States
  government work.
* **NIST SP 800-171 Rev. 2**, the version CMMC Level 2 and DFARS
  252.204-7012 use: the requirements whose row in Rev. 2's Appendix D
  lists a control or enhancement that the same CCIs name in their SP
  800-53 Rev. 4 references; requirements that share a row share its
  controls. Appendix D's own caveat goes with it: "The mapping tables are
  included for informational purposes and do not impart additional
  security requirements". The rows are kept in the repository as data
  taken from the appendix's tables.
* **NIST SP 800-171 Rev. 3**: the requirements whose "Source Control" in
  NIST's publication is a control or enhancement the CCIs name in their
  Rev. 5 references (03.04.02 Configuration Settings lists CM-06, for
  example). SP 800-171 Rev. 3 is "derived from the controls in NIST
  Special Publication (SP) 800-53".
* **ISO/IEC 27001:2022 Annex A**: the Annex A controls NIST's crosswalk
  ("800-53-Rev5-to-ISO 27001-2022", version 1.0.0, posted 2023-11-13 in
  NIST's OLIR catalogue) gives for those base controls, as numbers only:
  the crosswalk has no titles, and ISO's text is copyrighted and could not
  be read. NIST's own caveat goes with it: organizations "should not assume
  security requirement and control equivalency based solely on the
  mapping tables".
* **CMMC** is not mapped beyond that: its Level 2 requirements are SP
  800-171 Rev. 2's, which are shown. EasyRMM says nothing about an
  assessment.
* **Not mapped**: the CIS Controls (CC BY-NC-ND 4.0 under the same
  non-member terms, which forbid claiming consistency with them); the
  Essential Eight (the Australian Signals Directorate's site could not be
  read while this was written: see Open questions); PCI DSS, HIPAA, SOC 2,
  GDPR, NIS2 and FedRAMP (no published mapping from STIG rules or SP
  800-53 controls to them was found that EasyRMM may use; PCI DSS's
  standard is behind a licence agreement). PCI DSS v4.0 requirement 2.2.1
  asks for configuration standards "consistent with industry-accepted
  system hardening standards or vendor hardening recommendations"; an MSP
  can point its standard at Microsoft's baseline and the STIG IDs EasyRMM
  shows, but EasyRMM does not map requirements.
* **Wording.** The panel is headed *Related controls*, and says: "Which
  controls these settings relate to, from DISA's and NIST's published
  mappings. It is not an assessment and not a statement of compliance."
  The tables are generated from DISA's and NIST's files by a tool in the
  repository and checked in CI, not written by hand.

Generated from the rules in What each module cites (Windows 11, Server
2025, and the Defender Antivirus and Firewall STIGs), as W3 will show them:

| Module | SP 800-53 Rev. 5 | SP 800-171 Rev. 2 | SP 800-171 Rev. 3 | ISO/IEC 27001:2022 Annex A (NIST's crosswalk) |
|---|---|---|---|---|
| `accounts` | AC-7, CM-6, IA-5, IA-8 | 3.1.8, 3.4.1, 3.4.2, 3.5.7, 3.5.8, 3.5.9, 3.5.10 | 03.01.08, 03.04.02, 03.05.07 | A.5.16, A.5.17, A.8.5, A.8.9 |
| `firewall` | AC-4, AU-5, AU-12, CM-6, CM-7, SC-5, SC-7 | 3.1.3, 3.3.1, 3.3.2, 3.3.4, 3.4.1, 3.4.2, 3.4.6 | 03.01.03, 03.03.03, 03.03.04, 03.04.02, 03.04.06 | A.5.14, A.8.9, A.8.15, A.8.16, A.8.19, A.8.20, A.8.22, A.8.23 |
| `defender` | CM-6, CM-7, SC-18, SI-3 | 3.4.1, 3.4.2, 3.4.6, 3.14.1, 3.14.2, 3.14.3, 3.14.4, 3.14.5 | 03.04.02, 03.04.06, 03.14.02 | A.8.7, A.8.9, A.8.19 |
| `asr` | SC-18 | none | none | none |
| `smb` | CM-7, IA-5 | 3.4.6, 3.5.7, 3.5.8, 3.5.9, 3.5.10 | 03.04.06, 03.05.07 | A.5.16, A.5.17, A.8.19 |
| `smb-signing` | CM-6, SC-8 | 3.4.1, 3.4.2, 3.13.8 | 03.04.02, 03.13.08 | A.5.10, A.5.14, A.5.33, A.8.9, A.8.20, A.8.26 |
| `ntlm` | CM-6, IA-5 | 3.4.1, 3.4.2, 3.5.7, 3.5.8, 3.5.9, 3.5.10 | 03.04.02, 03.05.07 | A.5.16, A.5.17, A.8.9 |
| `wdigest`, `powershell`, `printing`, `features` | CM-7 | 3.4.6 | 03.04.06 | A.8.19 |
| `autoplay` | CM-7 | 3.4.7 | none | A.8.19 |
| `name-resolution` | SC-5 | none | none | none |
| `rdp` | AC-17, IA-11, SC-11 | 3.1.13 | 03.05.01 | A.5.14, A.6.7 |
| `uac` | CM-11, IA-11, SC-3, SC-11 | none | 03.05.01 | A.8.19 |
| `anonymous` | AC-6, CM-6, SC-4 | 3.1.7, 3.4.1, 3.4.2, 3.13.4 | 03.01.07, 03.04.02, 03.13.04 | A.5.15, A.8.2, A.8.9, A.8.18 |
| `winrm` | IA-11, MA-4, SC-11 | 3.7.5 | 03.05.01, 03.07.05 | none |
| `audit` | AC-2, AC-6, AC-17, AU-3, AU-4, AU-9, AU-12, CM-5, MA-3, SI-11 | 3.1.7, 3.1.12, 3.3.1, 3.3.2, 3.3.8 | 03.01.07, 03.03.02, 03.03.03, 03.03.08 | A.5.14, A.5.15, A.5.16, A.5.18, A.5.28, A.5.33, A.6.7, A.8.2, A.8.4, A.8.6, A.8.9, A.8.15, A.8.18, A.8.19, A.8.31, A.8.32 |
| `device-guard` | CM-6 | 3.4.1, 3.4.2 | 03.04.02 | A.8.9 |
| `bitlocker` | IA-8, SC-28 | 3.13.16 | 03.08.05, 03.13.08 | A.5.10, A.5.16, A.5.33 |
| `laps` | IA-5 | 3.5.7, 3.5.8, 3.5.9, 3.5.10 | 03.05.07 | A.5.16, A.5.17 |
| `lsa-protection`, `tls` | none (no STIG rule) | none | none | none |

The table shows how coarse these mappings are (the audit module reaches
A.8.32 through CM-5, and one minimum password length reaches four Rev. 2
requirements that share a row), which is why the console shows them as
related, and why EasyRMM does not add mappings of its own.

**Linux, as a follow-up.** ADR-0051's script already cites the Red Hat
Enterprise Linux 9 STIG by rule ID, so the same panel can be built for
Linux modules from those IDs' CCIs. That is a follow-up to ADR-0051, not
part of this ADR; ADR-0051 carries an amendment note giving the licence
reason above for its not naming CIS recommendations.

### The job
* **The same job kind**, `hardening`, with the same three modes (check,
  apply, undo), result line, tables (`device_hardening_checks`,
  `device_hardening`), states and audit event as ADR-0051. The script is
  `server/internal/jobs/hardening/windows.ps1`, compiled into the server;
  mode, module names and options reach it as arguments, checked by the
  server against fixed lists, never as script text. Each job keeps a copy
  of the script it ran and its hash. **The agent does not change.**
* **Windows PowerShell 5.1**, which every Windows the agent supports
  carries and which the agent already runs jobs with
  (`powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy
  Bypass -File`, as LocalSystem, inside a job object). No PowerShell 7, no
  modules installed from the PowerShell Gallery, no `Add-Type` (it
  compiles C# at run time and is refused in Constrained Language Mode).
  [ADR-0064](0064-remote-powershell-management.md) adds a `pwsh` shell
  that runs PowerShell 7 where it is installed; EasyRMM's own hardening
  script keeps the `powershell` shell, Windows PowerShell 5.1, as
  ADR-0064 says.
  Language-neutral throughout: accounts and groups by SID (Administrators
  `S-1-5-32-544`, the Guest account by its RID, 501, the built-in
  Administrator by 500), audit subcategories by GUID, event fields by their
  XML names, never by their translated names.
* **Module names are per platform.** A request names the modules of one
  platform; the server refuses a Windows module for a Linux device and the
  other way round, and the console sends a mixed selection as one job per
  platform. The script must stay under the job body limit (512 KiB) and its
  worst-case result under the result limit (64 KiB); tests hold both.
* **Results gain** the Windows platform (build and update revision,
  edition, installation type such as Server Core, role: workstation, member
  server, standalone server or domain controller; joined to a domain, to
  Entra ID, or neither; enrolled in MDM or not), a `managed` list per
  module (each setting another owner holds, with the owner and its value),
  `restart` (a change waits for a restart), `step` for modules that work
  in two steps (what the first step started, and when), and each change
  with its time, which log collection reads (see Audit policy). The format
  stays `EASYRMM-HARDENING-RESULT-V1`: the script and the server ship
  together.
* **Only tighter**, as on Linux: a value stricter than EasyRMM's is left
  (UAC that asks for credentials stays; a lockout threshold of 3 stays 3).
* **One change at a time on a device.** ADR-0017 lets the agent run four
  scripts at once. A hardening apply or undo runs alone: the server does
  not send one while another hardening, software or patch job for that
  device is queued or running, and holds those until it ends, so that a
  feature removal and an update never run together. ADR-0051's jobs get
  the same when it is next amended. ADR-0067 and ADR-0068 extend the lock,
  once they are built, to registry changes (`registry_change`) and to a
  log's settings and clearing (`eventlog_manage`): none runs beside a
  hardening apply or undo on the same device; their reads never wait for
  it.
* **A daily check** on every device where EasyRMM's values are in place,
  so that an owner that arrives later is seen (see Managed elsewhere). It
  is an ordinary signed `hardening` job in `check` mode, never apply or
  undo, created by the server:
  * **One device, one job, at its own time.** The server creates each
    device's check at that device's time of day, derived from a hash of
    its device ID, so checks spread over the day without a "not before"
    field. At most one is outstanding per device, its expiry at most 24
    hours after it is created. None is created while an apply or undo
    for the device is queued or running, and a day missed while jobs were
    held or the server was down is not caught up.
  * **An undo comes first.** Creating an undo cancels the device's check
    if it is queued or delivered and not yet running; a running check is
    waited for, as any job is (see One change at a time). The server
    cancels it as a consequence of the undo, so the user needs no
    `job.manage`: the run is `canceled` with `canceled_by` NULL and the
    reason *replaced by an undo* in its `error`, audited with the system
    as actor.
  * **Amendments to ADR-0017**, made with W2: jobs gain a batch id, which
    the day's many small check jobs share and by which **Jobs** groups
    them; this kind of job and its runs are removed after 7 days rather
    than after `EASYRMM_JOB_RETENTION` (the results kept per device and
    module, as in ADR-0051, still hold the last check); it is audited
    with one row per organization per daily batch instead of one
    `device.script_run` per run; and the server may cancel a run itself,
    as above.
  * **Since then.** [ADR-0063](0063-who-sees-job-output-and-arguments.md)
    keeps a run's output for `EASYRMM_JOB_OUTPUT_RETENTION` (30 days by
    default) and leaves retention per kind to the first kind that needs
    it: its purge then gains the kind in its condition and a time per
    kind. [ADR-0067](0067-remote-registry-editor.md)'s F2 extends these
    amendments per kind and adds no second set, and ADR-0068's queries
    use the server's cancel as F2 extends it. **Changed by ADR-0067**: if
    F2 is built before W2, F2 builds job retention per kind and the
    server's cancel, and W2 extends them. The MSP plan's order has W2
    first (its step 8; F2 is step 15).

### Before anything changes
The script first checks, and stops with every module *not supported* and
the reason if:

* PowerShell runs in **Constrained Language Mode** (App Control for
  Business or AppLocker script rules), in any mode: the script cannot read
  or set what it needs, and must not try to get around the computer's own
  control.
* For apply, the platform is check only or not supported (see
  Platforms), or an owner holds the computer's settings in a way EasyRMM
  cannot read yet (see Managed elsewhere).
* The Hardening folder, its manifest, the script's copy or the lock file
  fails the check below (see Backups, undo and interruptions), in any
  mode.

**Undo is never refused for check only, *not supported* or *cannot
tell***, so that a computer that moved to a check-only or untested
version, or gained an owner EasyRMM cannot read, can still be put back
(Constrained Language Mode and a failed folder check still stop it). On
a *not supported* version the result labels it *run on an untested
version*. It restores only values that are still as EasyRMM left them.
Where the reader *cannot tell*, it also leaves, and reports, every value
in a place the unreadable owner may write, which depends on the reason:

* **Group Policy with its record turned off**: every value Group Policy
  can set (registry policy values, security policy, audit policy).
* **Group Policy registry preference items**: every registry value, since
  a preference item can set any.
* **MDM, until its reader is proven**: every setting this ADR writes for
  which the Policy CSP has a policy (W1 lists them).
* **Defender for Endpoint's security settings management**: Defender's,
  attack surface reduction's and the firewall's values.
* **A Configuration Manager client**: Defender's policy key, where its
  endpoint protection writes. Values its configuration baselines may
  remediate are restored, and the result says that it may set them
  again.
* **DSC correcting drift, Azure machine configuration**: nothing is left;
  undo restores, and the result says that the owner may set each value
  again.
* **A policy value none of these explains, or *owner unknown***: that
  value.

**Applying** a module that removes a Windows feature (`smb`, `powershell`,
`features`) is refused, and the others go on, while Windows reports a
restart pending in any of the places Configuration Manager reads for it:
a pending file rename (`PendingFileRenameOperations`), Windows Update's
`RebootRequired` key, or component-based servicing's pending restart key.
**Undo is never refused for a pending restart**: a feature removal
waiting for one is itself a pending restart in component-based servicing,
and undo exists to reverse it. Undo of a removal EasyRMM recorded enables
the feature again before the restart; W2 checks that component-based
servicing accepts that while the removal is pending, and where it does
not, undo keeps the record and reports the feature as *to be restored
after the restart*; after the restart a check shows the module as *undo
needed*, and undo run then restores it. Apply is refused for a module
whose undo is pending. Every script reads every earlier manifest format,
so a pending undo still runs after EasyRMM is upgraded.

If Group Policy sets PowerShell's execution policy to `AllSigned`, the
script does not start at all: Group Policy "overrides the execution
policies set in PowerShell in all scopes". The job fails with PowerShell's
message, which the server recognises and shows as *Group Policy allows only
signed scripts*, in its own words, quoting nothing from the output
([ADR-0063](0063-who-sees-job-output-and-arguments.md)). This is true of
every PowerShell job EasyRMM runs, in either edition (ADR-0064). ADR-0067's
and ADR-0068's builtins, Go code in the agent, are not stopped by it,
though ADR-0067's owner warning, which runs this ADR's reader, then says
*cannot tell*. Signing EasyRMM's scripts depends on code signing, which is
on hold (see Open questions).

### Managed elsewhere
A setting that another owner holds is never written. The check lists it
under `managed`, with the owner and its value: *in place* if that value is
as strict as EasyRMM's, otherwise *managed elsewhere* with what the owner
would have to change. A module whose settings are all held elsewhere is
*managed elsewhere*; one with some is *partly* and apply writes the rest.
Writing underneath an owner would be reverted at its next refresh, or
would win against it and leave the computer different from what its
administrator set; either way the record of the value before would be
wrong.

**Words shared with log collection.** ADR-0060 uses the same: *in place*,
*managed elsewhere* naming the owner and its policy (*set by Group Policy*
with the policy's name, *set by MDM*, *set by OSConfig*, and here also
*set by Defender for Endpoint* and *protected by Tamper Protection*), and
*managed elsewhere (owner unknown)* for a value EasyRMM set that a later
check finds set back twice: it has an owner no reader sees, and is left
from then on. A value no owner holds is changed and its value before
recorded for undo, by both features. A value the reader *cannot tell*
about is shown as *check only*, with the reason.

**Owners that appear later.** An owner can arrive after apply: the
computer is enrolled in Intune, onboarded to Defender for Endpoint, or
given a Group Policy object. Some of EasyRMM's values then win silently:
a Defender value written as policy outranks Intune's (see How settings
are written). So every check, the daily check among them (see The job),
looks for owners that appeared since apply:

* Where EasyRMM's value outranks the new owner's, the setting is shown as
  *EasyRMM's value outranks* the owner (*set by MDM*, for example), with
  both values, and the console offers undo of the module.
* Where the new owner is one the reader *cannot tell* about, the module
  shows *an owner EasyRMM cannot read appeared; EasyRMM's values may
  outrank it*, and the console offers undo.
* Where the owner's value won, it is *managed elsewhere*, and undo leaves
  that value, as it leaves any value changed since apply. Undo also
  leaves a value an owner now holds that happens to equal EasyRMM's.

**Policy ownership: one reader, built here.** The code that finds who owns
a setting is written once, in W1, as a PowerShell script in a Go package
of its own (`internal/winpolicy`, beside `internal/agentproto`). The
server includes it in the hardening script; the agent carries the same file
for *Configure logging*, which builds no reader of its own (ADR-0060).
ADR-0067's registry editor and ADR-0068's log settings show its answer
before a change: ADR-0067's `registry` builtin starts the agent's copy as a
child process of its own, with the values' paths in a file, and shows
*cannot tell* where PowerShell cannot run it. W1 builds the reader so that
it can be started that way.
For each registry value, security setting and audit subcategory it
returns exactly one of three results:

* **Owner and policy**: who holds the value (Group Policy, MDM,
  OSConfig and the others below), the policy's name where there is one,
  and the owner's value.
* **None**: no owner holds it. Only then may either feature change it,
  recording the value before.
* **Cannot tell**, with the reason: an owner may hold it whose settings
  the reader cannot read yet. Today's reasons, from the readers below:
  Group Policy with its record turned off or with registry preference
  items, MDM until its reader is proven, Defender for Endpoint's security
  settings management (for Defender, attack surface reduction and
  firewall values), a Configuration Manager client, DSC correcting drift,
  Azure machine configuration, a policy value (under a `Policies` key)
  that none of these explains and EasyRMM did not write (a tool the
  reader does not know), and *owner unknown* (a value EasyRMM set that
  was set back twice). The list grows
  only by amending this ADR, and each reason is a fixed code that both
  features show.

**Both features treat *cannot tell* as check only**: nothing is written,
and the reason is shown. Both are tested against the same domain machines
and Group Policy objects (see Testing). What it reads, owner by owner:

* **Group Policy, from the domain or the local Group Policy object**: the
  computer's **resultant set of policy** in WMI (`root\rsop\computer`):
  registry-based policy (the `RSOP_RegistryPolicySetting` class: key, value
  name, value, and the winning policy, precedence 1) and the security
  settings Windows records when Group Policy applies security policy.
  `gpresult /scope computer /x` is a cross-check, the source of the
  policy's name, and the source of advanced audit policy, which Group
  Policy applies through an extension of its own rather than as registry
  policy (W1 confirms this against a domain policy). Whether Windows
  records the resultant set of policy on a computer in a workgroup, where
  only local Group Policy applies, is settled in W1; if it does not, the
  local Group Policy object's `Registry.pol` is read instead.
  * **Its record turned off.** Group Policy's *Turn off Resultant Set of
    Policy logging* (`RSoPLogging` 0) stops Windows recording what it
    applied, so the reader cannot tell who owns what. The reader detects
    the value, and the computer gets check only, with the reason. W1 tests
    whether `gpresult` still reports anything then; nothing is assumed.
  * **Group Policy Preferences.** Registry items set through preferences
    are applied by a different extension. Microsoft documents how
    registry-based policy appears in the resultant set of policy, not how
    preference items do. W1 finds how to read them, on the test domain
    with a Group Policy object that sets registry preference items; until
    that reading is proven, a computer whose Group Policy carries registry
    preference items gets check only.
* **MDM** (Intune and others through the Policy CSP): the **MDM Bridge WMI
  provider** (`root\cimv2\mdm\dmmap`), read as Local System, the agent's
  account. **Ownership comes from the Policy CSP's `Config` node** (the
  `MDM_Policy_Config01_*` classes), the "Node for grouping all policies
  configured by one source", and **only the value in effect from its
  `Result` node** (`MDM_Policy_Result01_*`), which "Groups the evaluated
  policies from all providers": a value in `Result` alone may have come
  from Group Policy and is not taken as MDM's. Microsoft notes of `Config`
  that "A query from a different caller could provide a different value",
  so W1 proves that the bridge, read as Local System, shows the MDM's
  values. Group Policy wins over MDM unless the MDM set `MDMWinsOverGP`,
  which "doesn't apply for all settings, such as attack surface reduction
  (ASR) rules in Windows 10", and the reader reads that too. Microsoft's
  class reference gives "None supported" as the minimum server, so an
  MDM-enrolled server is check only. W1 proves the reader on an
  Intune-enrolled Windows 11 (see Open questions); until then, a computer
  enrolled in MDM gets check only.
* **Microsoft Defender for Endpoint's security settings management**,
  which applies Intune's antivirus, attack surface reduction, EDR and
  firewall policies to computers not enrolled in Intune. Microsoft
  documents a troubleshooting registry key
  (`HKLM\SOFTWARE\Microsoft\SenseCM\EnrollmentStatus`), but not the value
  that means enrolled. W1 settles it on a real device; until then, on a
  computer onboarded to Defender for Endpoint, `defender`, `asr` and
  `firewall` are check only.
* **Configuration Manager**: its configuration baselines can be deployed
  with "Remediate noncompliant rules when supported", which "Automatically
  remediates any rules that are noncompliant for Windows Management
  Instrumentation (WMI), the registry, scripts". W1 finds how to detect
  the client and read which values its remediating baselines cover; until
  then, a computer with the Configuration Manager client gets check only.
* **PowerShell DSC**, built into Windows PowerShell 5.1:
  `Get-DscLocalConfigurationManager` shows the configuration mode, and in
  `ApplyAndAutoCorrect`, when the computer drifts, DSC "re-applies the
  current configuration" (checked every 15 minutes by default). W1 reads
  the applied configuration's resources; until then, a computer in
  `ApplyAndAutoCorrect` with a configuration gets check only.
* **Azure machine configuration**: on an Azure Arc server the
  `GCArcService` service "Audits and enforces Azure machine configuration
  policies on the machine" (on Azure virtual machines an extension does),
  and an `ApplyAndAutoCorrect` assignment corrects drift, checked every 15
  minutes. No documented local way to read the assignments was found, so
  a computer running it gets check only until W1 finds one.
* **OSConfig** (Windows Server 2025): a baseline applied through OSConfig
  with drift control is corrected "through a refresh task" (every four
  hours by default, according to Microsoft's announcement). Microsoft
  documents no way to see such a baseline without the OSConfig module, but
  that module must be on the computer for a baseline to be applied there
  ("Before you can apply a security baseline for the first time, you need
  to install the OSConfig module"). So where the module is installed, the
  reader asks it (`Get-OSConfigDesiredConfiguration`), using the
  computer's own copy, which EasyRMM never installs; where it is not, no
  baseline was applied through it on that computer. W1 tests both on a
  Server 2025 guest.
* **Microsoft Defender's own guards**: Tamper Protection blocks changes to
  real-time protection, behaviour monitoring, cloud protection and more
  ("changes made through a management tool, including Group Policy, might
  appear to succeed, but tamper protection blocks the changes"). Settings
  Tamper Protection locks are *protected by Tamper Protection* when they
  differ. EasyRMM never turns Tamper Protection off. Settings someone made
  locally with `Set-MpPreference` "have the lowest precedence. Any
  policy-based method overwrites them on startup", the policy values
  EasyRMM writes included (see How settings are written): the check names
  each local setting apply would outrank, and the manifest records it.
* **Another antivirus or firewall** (see Microsoft Defender and Firewall
  below). On workstations Windows Security Center names them; Microsoft
  says Security Center is not supported on server versions of Windows, so
  on servers they are found by their services and drivers.
* **Remote Desktop's own record**: the Terminal Services WMI provider
  reports, for NLA, the security layer and the encryption level, whether
  Group Policy sets each.

### How settings are written
* **Registry values** (administrative template policies and Windows' own
  settings) with PowerShell's registry provider, under `HKLM`, at the
  path Group Policy would write, after recording the value before (absent,
  or its type and data). They do not appear in the Local Group Policy
  Editor as configured, since they are not in the local Group Policy
  object; the console says EasyRMM set them.
* **Whether they outlive Group Policy is settled by a test, not assumed.**
  Microsoft's protocol specification has the client write the
  instructions in each changed Group Policy object's `registry.pol`, and
  describes no deletion but the ones those instructions name (MS-GPREG
  section 3.2.5.1.2, *New or Changed GPO List Processing*). Its older
  description of Windows Server 2003 says the opposite of the policy
  trees: "all keys and values beneath these paths are erased before
  applying the resultant registry policy settings", and that the extension
  "will run only if there are any changes in any the GPOs". So W2's first
  test, before any module writes an administrative template value, writes
  them all and then, on a domain member: edits an unrelated Group Policy
  object that has registry settings, links one, and unlinks or removes
  one, running `gpupdate /force` after each; and on a workgroup computer
  changes an unrelated setting in the local Group Policy object (in the
  test only, with LGPO.exe downloaded by the test onto the test machine:
  its terms allow use "on your devices to develop and test your
  programs"; it is never committed, cached or shipped; until a hosted
  runner is known to count as one of "your devices", this case runs on
  the fallback in Testing; see Open questions). Each step counts only
  when `Microsoft-Windows-GroupPolicy/Operational` shows, for that
  refresh's activity ID, the registry extension's event 4016 (a
  client-side extension "begins its processing") and 5016 ("completes
  its processing successfully"); a refresh in which the extension did
  not run proves nothing. After each, every value must still be there.
  It runs on at least Windows Server 2016, Windows Server 2025 and
  Windows 11, and on every other version before apply is allowed there.
  If the values do not survive, no administrative template value is
  written until this ADR is amended.
* **Security policy** (password and lockout policy, the Guest account,
  anonymous SID and name translation): read with `secedit /export`,
  written with `secedit /configure` and a template holding only the
  module's settings, read back after. Tests prove the values survive Group
  Policy's 16-hourly re-application on a domain member where no policy
  sets them.
* **Microsoft Defender and attack surface reduction**: as **policy
  registry values** under
  `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\...`, exactly as the
  administrative template policy would write them, like the other
  administrative template values: never through LGPO, and never in the
  local Group Policy object's `registry.pol`. For attack surface reduction
  that is the policy's enabling value
  (`...\Windows Defender Exploit Guard\ASR!ExploitGuard_ASR_Rules`), one
  `REG_SZ` value per rule under `...\ASR\Rules`, named by the rule's GUID,
  whose data is its mode (1 block, 2 audit), each written and removed on
  its own, never replacing the list; and the per-rule exclusions of the
  two reputation rules (see Attack surface reduction) as the policy *Apply
  a list of exclusions to specific attack surface reduction (ASR) rules*
  writes them: the rule's GUID as the value name, the exclusions as
  `Path1\ProcessName1>Path2\ProcessName2`. That policy is in the
  Administrative Templates of Windows 11 24H2 and later; W2 takes its key
  from that ADMX file, and shows each supported Windows version honouring
  it. Why policy values: the Defender STIG's checks read only these; the
  baselines set them there; and per-rule exclusions exist only as policy
  (PowerShell sets only exclusions that "apply to all ASR rules"). This
  key is where Microsoft's table of Defender's settings puts Defender for
  Endpoint's security settings management, Configuration Manager and Group
  Policy, all of which its order of precedence ranks above Intune,
  Configuration Manager's tenant attach and local settings. So:
  * **Never written where another owner may be**: where the reader finds
    any Defender value set by Group Policy, any value under
    `...\Windows Defender\Policy Manager` (where Intune and tenant attach
    write) or enrolment in an MDM, onboarding to Defender for Endpoint, a
    Configuration Manager client, or a Defender policy value that none of
    these explains and EasyRMM did not write (a tool the reader does not
    know), `defender` and `asr` are *managed elsewhere* or check only, and
    nothing is written.
  * **An owner that comes later** is reported by the daily check as
    *EasyRMM's value outranks* it, or, for one the reader cannot read
    (Defender for Endpoint onboarding, a Configuration Manager client), as
    one whose values EasyRMM's may outrank; undo is offered either way
    (see Managed elsewhere).
  * **Before and after**: each value before is recorded (absent, or its
    type and data), and after writing, `Get-MpPreference` must show the
    value in effect and `Get-MpComputerStatus` the running mode
    (`AMRunningMode`) and Tamper Protection (`IsTamperProtected`) as they
    were; otherwise the module is put back and reported.
  * **Persistence** is the test above, for these values as for the rest.
  * **The cost**: settings set by policy cannot be switched in Windows
    Security on the computer (W2 records which switches it locks), so a
    technician who needs one off for a while uses undo, not the switch.
* **Windows Defender Firewall**: the NetSecurity cmdlets, on the local
  store; EasyRMM's rules in a rule group of their own, by port, never by
  program.
* **Windows features**: `Disable-WindowsOptionalFeature` on Windows 10
  and 11 and `Uninstall-WindowsFeature` on servers, never with `-Remove`,
  so the payload stays and undo can add a feature back without
  installation media; removed by apply never while a restart is pending,
  added back by undo even then (see Before anything changes).
* **Services**: start type and state, recorded first.
* **Remote Desktop**: the Terminal Services WMI provider
  (`Win32_TSGeneralSetting`).
* **Not used**: LGPO.exe, whose terms forbid sharing or distributing it,
  so not shipping it is a requirement, not a choice (one test downloads
  it, above); Microsoft's
  `Baseline-LocalInstall.ps1` (it applies a whole baseline with LGPO,
  including the settings this ADR leaves out); PowerShell DSC; and the
  OSConfig module, which EasyRMM never installs (the reader only asks a
  copy already there).

### Evidence over weeks: the harvest
Five guards judge a change by what the computer did over a window: SMB1's
audit (30 days), a server firewall's allowed connections (14 days), the
NTLM versions a domain controller sees (30 days), the built-in
Administrator's network sign-ins (30 days, for `uac-builtin-admin`) and
LSA's audit events (at least 7 days: see LSA protection). On a busy
server or domain controller the logs they read (the firewall's log, at
most 32,767 KB; `Microsoft-Windows-NTLM/Operational`; the SMB server's
audit log; CodeIntegrity's Operational log; the Security log) can wrap in
hours, and a log that reaches back far enough shows neither that the
logging was on throughout nor that nothing was lost. So:

* **Judged at once only from collected events**: where log collection
  (ADR-0060) collects the guard's channel, with no filter dropping the
  guard's events, and its report covers the whole window without a gap
  and with the logging the guard needs on throughout. Of these guards'
  events, it collects today only the Security log's 4624, so only the
  built-in Administrator's guard can be judged at once, and only where
  that report shows the Logon subcategory's success audit on for the 30
  days. Every other guard, and that one otherwise, starts a harvest at
  its first step.
* **The harvest** is a scheduled task that runs as LocalSystem every hour,
  for at most 30 minutes a run. Its action is
  `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`, by full
  path, with `-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass
  -File` and the script's copy in `%ProgramData%\EasyRMM\Hardening\`, in a
  fourth mode, `harvest`, which the server never sends. Each run first
  checks the folder, the manifest and the copy as every mode does (see
  Backups, undo and interruptions), then reads each log from after the
  last event it read and adds to the manifest only what the guard needs,
  as distinct values: the local ports that received an allowed
  connection (firewall); the clients that used NTLMv1 or LM, with counts
  of the sign-ins by each version, never the clients that used only
  NTLMv2, so that a domain of many clients stays far from the limit
  below (NTLM); the clients that used SMB1 (event 3000); the built-in
  Administrator's network sign-ins, with their time and source (event
  4624, logon type 3, by the account's SID: the computer's own account
  domain SID followed by 500, the domain's on a domain controller, never
  any SID that merely ends in 500); the plug-ins in events 3065 and 3066
  (LSA). The task is recorded for undo.
* **Bounded.** At most 4,096 distinct values per guard, each at most 256
  characters; reaching either limit refuses the module, with the count,
  for a person to look at. The result carries each guard's counts and as
  many values as fit its share of the 64 KiB result limit, and a test
  holds the worst case under it.
* **The logging must be in effect, or it is a gap.** Each run records,
  and requires, that the logging its guards depend on is on: the SMB1
  audit (`AuditSmb1Access`), enhanced NTLM logging, `LogAllowed` on the
  profile the firewall's first step turned on, LSA's audit mode (see LSA
  protection), the success audit of the Logon subcategory (for the
  built-in Administrator's sign-ins), and each event channel enabled; and
  that each channel overwrites its oldest events when full (circular). A
  run that finds any of these otherwise, or a log set to keep its events
  that is full, records a gap: silence after logging stopped is not
  evidence. Where an owner holds that logging off (Group Policy turning
  off enhanced NTLM logging, for example), the module is refused and the
  owner named; EasyRMM never writes a value Group Policy holds. Where the
  Logon subcategory's success audit is off with no owner, the result
  names log collection's *Configure logging*, which owns audit policy
  (see Audit policy); hardening never sets it.
* **Coverage comes from the harvest's continuity**, not from how far the
  log reaches. Each run records when it ran and, for each log, the newest
  event it read, by record ID and time. The window counts from the first
  run for as long as each run finds that event, with the same record ID
  and time, still in the log. Otherwise there is a gap (the log wrapped
  or was cleared between runs, after runs failed for example), which
  restarts the window; the check shows it with its times. The firewall's
  log is a text file without record IDs, by default one file for every
  profile, and Microsoft says only that at its limit "old log entries are
  deleted to make room for the newly created ones" (and elsewhere speaks
  of rotation, without saying how). So there each run reads only
  complete lines, and records the last one, with its time, and the byte
  offset at which it ends. The next run must find that line ending at
  that offset, in the log or, where the log is now smaller (it has
  rotated), in a rotated copy beside it, and reads on from there;
  anything else is a gap. W2 records how each version rotates. Days the
  computer is off count toward the window: its logs are not written, so
  nothing is lost.
* **NTLM's log is made larger** at the first step on a domain controller,
  to at least 65,536 KB, with its size before recorded for undo. Log
  collection does not size that log.
* **The task's life.** It is removed when no module on the computer still
  harvests: by the second step, or undo, of the last one. It also ends by
  itself: its trigger has an end date (its start, plus the longest window
  it serves, plus 14 days), moved forward when a gap restarts a window,
  but never past 90 days from the task's start; a run unregisters it
  once that date has passed or once the EasyRMM agent's service is gone,
  and the module shows *harvest ended: apply again*. A refused second
  step leaves it harvesting until then; a later first step starts it
  again. Its findings stay in the manifest until the record is
  consumed.
* **One writer at a time.** Every mode, the harvest included, after the
  folder check, opens `Hardening\lock` with
  `[IO.File]::Open(path, OpenOrCreate, ReadWrite, FileShare.None)` and
  holds it until it ends; the lock file goes through the same check as
  the manifest. It sits in the checked folder, where no one else can
  reach it, and Windows releases it when the process exits, so a run
  that dies leaves no lock behind. A
  harvest run that cannot open it within a minute skips that run (the
  next one carries on from the same event); apply, undo and check wait
  up to five minutes and then fail, saying why.
* **An EDR may flag it.** A task that runs PowerShell from `ProgramData`
  as LocalSystem every hour looks like what attackers leave behind. The
  console says so when an operator starts a first step, and the guide
  tells MSPs to allow the script by its hash (see The rest).

### The modules
*Recommended* ones are preselected; the others must be chosen one by one,
with what they can break stated beside them. What each module's settings
cite, and whether they meet the rule, is in the next section.

| Module | What it does | Recommended |
|---|---|---|
| `accounts` | See **Accounts** below | Yes |
| `firewall` | See **Firewall** below | Yes |
| `defender` | See **Microsoft Defender** below | Yes |
| `asr` | See **Attack surface reduction** below | Yes |
| `smb` | SMBv1 off: the server's SMB1 protocol, the client's SMB1 driver, and the optional feature removed where installed (a restart); passwords never sent unencrypted to third-party SMB servers. Where the server still speaks SMB1, **in two steps**: the first apply turns on Windows' SMB1 access audit (`Set-SmbServerConfiguration -AuditSmb1Access $true`; "Each time a client attempts to use SMBv1 to connect to a server, an entry that has an event ID of 3000 appears" in the `Microsoft-Windows-SMBServer/Audit` log), records it for undo, starts the harvest (see Evidence over weeks) and stops; a later apply turns SMB1 off only when the audit and the harvest have covered 30 days without a gap and found no event 3000, and this computer has no SMB1 connection open to another (the audit covers the server side only). Breaks: scanners, NAS boxes and old systems that speak only SMB1, including ones this computer opens shares on | Yes |
| `smb-signing` | SMB signing required by the client and the server; guest access to SMB shares off. Already the default on Windows 11 24H2 Enterprise, Pro and Education, and outbound on Server 2025. Breaks: multifunction printers that scan to a share and NAS boxes that cannot sign, shares opened as guest (common in small offices); large copies are slower | No |
| `ntlm` | See **NTLM** below | Yes, except on domain controllers |
| `wdigest` | WDigest does not keep passwords in memory (`UseLogonCredential` 0, which is also Windows' behaviour when the value is absent). Breaks nothing current | Yes |
| `lsa-protection` | See **LSA protection** below | Yes on Windows 11 22H2 and later; no elsewhere |
| `name-resolution` | LLMNR off; NetBIOS ignores name release requests except from WINS servers. NetBIOS over TCP/IP stays on and its node type is left (Microsoft's baseline sets P-node, which stops NetBIOS names resolving by broadcast where there is no WINS server). Breaks: on networks without DNS for local devices, names only LLMNR found (`\\NAS`) | Yes on computers in a domain; no in workgroups |
| `powershell` | Windows PowerShell 2.0 removed where it is still installed (Windows 10, Server 2016 to 2022, Windows 11 before August 2025's update), never applied while a restart is pending. Script block logging is reported against log collection's table (see Audit policy). Not transcription, which writes every script's text, secrets included, to files. Breaks: tools that start `powershell -Version 2` | Yes |
| `rdp` | See **Remote Desktop** below | Yes, once W2 proves EasyRMM's RDP sessions work with NLA |
| `uac` | See **User Account Control** below; not applicable on Server Core | Yes, once W2 proves remote support still answers the prompt |
| `autoplay` | AutoPlay off for all drives and for devices that are not volumes, no AutoRun commands. Breaks: CDs and USB drives no longer start anything by themselves | Yes |
| `anonymous` | No anonymous enumeration of accounts or shares, no anonymous SID and name translation, anonymous users not in Everyone, anonymous access to named pipes and shares restricted; remote calls to the account database only for administrators on workstations, member servers and standalone servers (the Server 2025 STIG's rule is for those; on domain controllers it is left). Mostly Windows' defaults. Breaks: very old systems and devices that list shares without signing in | Yes |
| `winrm` | WinRM's client and service: no Basic authentication, no unencrypted traffic, no Digest (client), no stored RunAs credentials (service). These are Windows' defaults; where Basic or unencrypted traffic is on (someone turned it on, often for Ansible or a monitoring tool) it is left and reported, unless the option `winrm-basic-off` is given. WinRM is never stopped and its listeners never removed | Yes |
| `printing` | Only administrators install print drivers (the baseline's setting), drivers are never downloaded over HTTP, no printing over HTTP; on domain controllers the Print Spooler stopped and disabled (Microsoft: "domain controllers and Active Directory admin systems need to have the Print spooler service disabled"); on other servers only with the option `spooler-off`. On any server, domain controllers included, the spooler is left, and the result says why, where the server shares a printer, has the Print Server role or is a Remote Desktop session host. Never on workstations. Breaks: users adding a printer whose driver is not installed yet; on domain controllers, the spooler's pruning of stale print queue objects from Active Directory, which Microsoft calls the trade-off of disabling it (they must then be pruned some other way) | Yes |
| `features` | Removes, where installed, the Telnet and TFTP clients, Simple TCP/IP Services and the Peer Name Resolution Protocol (payload kept), never applied while a restart is pending. An FTP server or Fax server is reported, never removed: it may be there on purpose (the STIG allows FTP where "required by the organization"). Breaks: someone using the Telnet client to test ports | Yes |
| `tls` | Schannel: SSL 2.0 and 3.0 and TLS 1.0 and 1.1 off for clients and servers (a restart). Microsoft's own pages disagree on whether TLS 1.0 and 1.1 are already off on Server 2025 and Windows 11 24H2; the check reads what is in effect. Breaks: older SQL Server clients and drivers, older .NET programs, devices and line-of-business software that speak only TLS 1.0 | No |
| `audit` | Report only: see **Audit policy** below | (report) |
| `device-guard` | Report only: whether virtualization-based security, memory integrity (HVCI) and Credential Guard are running. Turning them on needs hardware and firmware support and a restart, cannot be undone remotely when locked in UEFI, and Credential Guard is not recommended on domain controllers | (report) |
| `bitlocker` | Report only: whether the system volume is protected; by which protectors (TPM only, TPM and PIN, and others), so whether a PIN is asked before Windows starts, and the minimum PIN length policy sets (the Windows 11 STIG's rules ask for a PIN of at least six digits); whether a recovery password exists. Turning BitLocker on before its recovery key is kept somewhere can lose data; escrowing keys is a feature of its own | (report) |
| `laps` | Report only: whether Windows LAPS manages the local administrator's password. Setting it up needs a directory (Active Directory or Entra ID) and a policy. Windows LAPS came with April 2023's updates to Windows 10 and 11 and Server 2019 and 2022, and is in Server 2025; Microsoft does not list Server 2016 | (report) |

Not offered: a maximum password age (NIST SP 800-63B, as in ADR-0051);
renaming the Administrator or Guest account (scripts and tools use the
names); user rights that deny network or Remote Desktop sign-in to local
accounts (the baselines' and STIGs' setting for domain computers, which
cuts off MSPs that use local administrator accounts; a later option could
refuse it while the Security log shows such sign-ins, event 4624 with
logon type 3 or 10, in the last 30 days); Administrator protection (new in
Windows 11 26H2's baseline v2; it changes how administrators work);
turning on Credential Guard, virtualization-based security, memory
integrity or BitLocker, and configuring LAPS (reported above); App Control
and AppLocker (allow-lists need per-site design); Windows Update and
Defender update settings (the patching engine's); FIPS mode; SMB
encryption and the baselines' minimum SMB dialect 3.0 (NAS boxes on SMB 2
stop working); LDAP signing and channel binding on domain controllers
(devices that bind without signing, such as copiers' address books, stop
working; it needs an audit period and its own decision); blocking NTLM;
PowerShell transcription and Constrained Language Mode; Remote Desktop's
"always prompt for password", drive redirection and Remote Assistance;
turning NetBIOS over TCP/IP off; logon banners (the STIGs' text is the
DoD's); and the Microsoft Edge and Microsoft 365 Apps baselines (separate
products).

### What each module cites
The IDs are those of Windows 11 V2R11 (`WN11`), Server 2025 V1R4
(`WN25`), Defender Antivirus V2R10 (`WNDF-AV`) and Firewall V2R2
(`WNFWA`); the script cites each Windows version's own. **Meets**: the
module sets the value the rule asks for, on the computers the module
applies to. **Differs on purpose**: the module sets a value the rule's
check calls a finding, looser or, for one rule, stricter, for the reason in
the module's section. **Not set**: the module leaves the setting, reports
it, and names the option that sets it where there is one. The console
shows the same three, per setting.

**Where the value is written matters to scanners.** EasyRMM writes its
registry settings where Group Policy would write them, Defender's and
attack surface reduction's included (How settings are written), so a
scanner that follows the STIGs' checks reads them where it looks: the
Defender STIG's checks read only the policy values under
`HKLM\Software\Policies\Microsoft\Windows Defender`. The Firewall STIG's
checks also accept the local value when no policy sets one, which is
where the NetSecurity cmdlets write.

| Module | Meets | Differs on purpose | Not set |
|---|---|---|---|
| `accounts` | WN11-AC-000005, -000015, -000020, -000035, -000040, -000045, WN11-SO-000010, -000015; WN25-AC-000010, -000030, -000040, -000080, -000090, WN25-SO-000010, -000020 | WN11-AC-000010, WN25-AC-000020: 10 failed sign-ins, not 3 | WN11-AC-000025, WN25-AC-000050 (maximum password age); WN11-AC-000030, WN25-AC-000060 (minimum password age: without expiry it only stops a user correcting a new password the same day); WN11-SO-000020, WN25-SO-000030 (renaming Administrator) |
| `firewall` | WN11-00-000135, WN25-00-000280; WNFWA-000001 to -000005, -000009, -000010, -000012, -000013, -000017, -000018, -000020, -000021, -000027, -000028 | none | WNFWA-000011, -000019, -000029 (logging allowed connections, except during a server's first step); WNFWA-000024, -000025 (local rules not merged with policy); WNFWA-000100 (inbound only from management hosts) |
| `defender` | WN11-00-000045, WN25-00-000110, WN25-CC-000300; WNDF-AV-000001, -000010; -000021 and -000022 except on a server whose real-time protection is off without `defender-server-realtime`; -000039 on Windows 10 and 11 | WN11-CC-000210: SmartScreen warns and users may go on (`smartscreen-block` gives the rule's *Block*) | WNDF-AV-000021, -000022 on a server whose real-time protection is off, unless `defender-server-realtime` is given; WNDF-AV-000073 (cloud protection level High: `cloud-block-high`); WNDF-AV-000052 (local exclusions not merged with policy, with which Microsoft says "per-rule exclusions or local ASR rule exclusions don't apply", voiding EasyRMM's own: see Attack surface reduction); the Defender STIG's other rules (scans, remediation actions, the visibility of exclusions and more) are outside the module |
| `asr` | WNDF-AV-000044, -000051 (blocked); -000047, -000049 (audited, as the rules ask); -000048 where the Configuration Manager client is installed (audited) | WNDF-AV-000048 elsewhere: blocked, where the rule's check accepts only audit; WNDF-AV-000032 to -000038, -000043, -000045, -000046, -000050: audited, not blocked (`asr-block` blocks them one by one) | WNDF-AV-000048 on Server 2016 and 2019, where Microsoft does not support the rule |
| `smb` | WN11-00-000160, -000165, -000170, WN11-SO-000110; WN25-00-000380, -000390, -000400, WN25-SO-000180 | none | none |
| `smb-signing` | WN11-SO-000100, -000120, WN11-CC-000040; WN25-SO-000160, -000170, -000190, -000200, WN25-CC-000070 | none | All of these while the module is not chosen |
| `ntlm` | WN11-SO-000180, -000195, -000205, -000215, -000220; WN25-SO-000270, -000310, -000330, -000340 | none | none |
| `wdigest` | WN11-CC-000038 | none | none |
| `lsa-protection` | No STIG rule; Microsoft's baselines | none | none |
| `name-resolution` | WN11-CC-000035, WN25-CC-000060; LLMNR from Microsoft's baselines | none | The NetBIOS node type (baselines only) |
| `powershell` | WN11-00-000155, WN25-00-000410 | none | WN11-CC-000327, WN25-CC-000530 (transcription); WN11-CC-000326, WN25-CC-000460 (script block logging, set by log collection: see Audit policy) |
| `rdp` | WN11-CC-000270, -000285, -000290; WN25-CC-000340, -000370, -000380; NLA from Microsoft's baselines | none | WN11-CC-000275, WN25-CC-000350 (drive redirection); WN11-CC-000280, WN25-CC-000360 (always prompt for a password); WN11-CC-000155 (Remote Assistance) |
| `uac` | WN11-SO-000250, -000260, -000265, -000275, WN11-CC-000315; WN25-SO-000400, -000420, -000430, -000450, WN25-CC-000430; WN11-SO-000270 and WN25-SO-000440 (UAC on) where UAC is on, or with `uac-enable`. Server Core is not applicable | none | WN11-SO-000245, WN25-SO-000380 (Admin Approval Mode for the built-in Administrator: `uac-builtin-admin`); WN11-SO-000255, WN25-SO-000410 (standard users' elevation denied: `deny-user-elevation`); WN11-CC-000037, WN25-MS-000020 (local administrators' tokens filtered over the network) |
| `autoplay` | WN11-CC-000180, -000185, -000190; WN25-CC-000210, -000220, -000230 | none | none |
| `anonymous` | WN11-SO-000140, -000145, -000150, -000160, -000165, -000167; WN25-SO-000210, -000220, -000230, -000240, -000250; WN25-MS-000060 except on domain controllers | none | none |
| `winrm` | WN11-CC-000330, -000335, -000345, -000350, -000355, -000360; WN25-CC-000470, -000480, -000490, -000500, -000510, -000520 | none | WN11-CC-000330, -000335, -000345, -000350 and WN25-CC-000470, -000480, -000500, -000510 where someone turned Basic authentication or unencrypted traffic on (`winrm-basic-off`) |
| `printing` | WN11-CC-000100, -000110; WN25-CC-000150, -000160 | none | none |
| `features` | WN11-00-000110, -000115, -000120; WN25-00-000340, -000350, -000360, -000370 | none | WN25-00-000320 (Fax Server), WN25-00-000330 (FTP server): reported, never removed |
| `tls` | No STIG rule | none | none |

The report-only modules report: `audit` WN11-SO-000030, WN11-CC-000066,
the WN11-AU rules (with WN11-AU-000500, -000505, -000510, the log sizes),
WN25-SO-000050, WN25-CC-000090, -000270, -000280, -000290 and the WN25-AU
rules; `device-guard` WN11-CC-000070, -000075, -000080, WN25-CC-000110,
WN25-MS-000140; `bitlocker` WN11-00-000030, -000031, -000032,
WN25-00-000250; `laps` WN11-SO-000280, WN25-00-000020.

### Accounts
* **Local password policy**: at least 14 characters, complexity on, 24
  passwords remembered, no reversible encryption. Existing passwords keep
  working until they are changed. No maximum age.
* **Lockout**: after **10** failed sign-ins, for 15 minutes, the count
  reset after 15 minutes. The STIGs and the Server 2025 baseline ask for 3
  attempts; Windows 11's baseline uses 10 attempts and 10 minutes. Three
  lets anyone who knows an account's name lock it out, the MSP's own
  included, with a few wrong guesses; 15 minutes is the STIGs' minimum.
  Whether the built-in Administrator can be locked out is left as Windows
  has it, and reported.
* **No lockout on exposed computers** unless the option `lockout-exposed`
  is given; the password settings still apply. Exposed means that the
  Security log, as far back as it reaches up to 7 days, shows an account
  with 10 or more failed sign-ins (event 4625) within 15 minutes, which the
  new policy would have locked, or failed sign-ins from addresses outside
  private ranges (Remote Desktop reachable from the internet). There,
  password spraying would lock the MSP's own accounts out, the ones its
  Remote Desktop sessions ([ADR-0026](0026-rdp-sessions.md)) use included.
  The result names the accounts and addresses and how far the log reached.
* **The Guest account disabled**, blank passwords usable only at the
  console.
* **Never touched**: any other account. The module never disables,
  renames, deletes or changes the password of an account, and never adds
  or removes a user right.
* **On domain controllers** the domain's policy applies: the module is
  *managed elsewhere*. On domain members it governs local accounts only.
* Breaks: creating a local account with a short password; ten wrong
  passwords lock a local account, the MSP's included, for 15 minutes.

### Firewall
* **Windows Defender Firewall on** for the domain, private and public
  profiles, with inbound connections blocked unless a rule allows them
  (the Firewall STIG's settings). EasyRMM never blocks outbound traffic:
  the EasyRMM agent, MeshAgent and the EasyPatch agent only connect out.
* **Logging on every profile**: dropped packets logged, to a log of at
  least 16,384 KB, on all three profiles, whatever their state, since
  logging changes no traffic. A larger log is left as it is. By default
  every profile writes the same file
  (`%windir%\system32\logfiles\firewall\pfirewall.log`), so profiles
  that share a file get the same size: the larger of the two this module
  uses (32,767 KB, the most Windows allows, on a server in the firewall's
  first step, below). Undo puts back each profile's size and logging as
  they were.
* **State and rules only on the profiles it changes.** A profile already
  on and blocking inbound connections (often the public one, on a laptop
  in a hotel) keeps its state and its rules exactly as they are, and no
  allow rule is added to it; only its logging is set. Rules are added
  only to the profiles the module turns on or sets to block.
* **What a changed profile allows**, by protocol and local port only,
  never by program (a program's path changes with its version): every TCP
  and UDP port something listens on outside loopback when the job runs;
  Remote Desktop's port where Remote Desktop is enabled; WinRM's listener
  ports where WinRM listens; ICMPv4 and ICMPv6 echo requests, so uptime
  monitors keep working (as on Linux, ADR-0051); RPC's endpoint mapper and
  the ports it hands out at each start, by the firewall's own `RPCEPMap`
  and `RPC` keywords; and ports and ranges the operator adds (`allow-tcp`,
  `allow-udp`). The check lists them before apply, and lists services that
  start automatically but are not running, whose ports cannot be known (as
  on Linux, *ports unknown*).
* **Ports that move.** A listening port is a snapshot, and some services
  listen on ports chosen at start or set elsewhere. The script keeps a list
  of them, found by their services: SQL Server named instances ("A named
  instance uses Dynamic ports"; the SQL Server Browser on UDP 1434), the
  FTP server's passive ports, Veeam's data movers (in version 13, port
  6162 with the range 2500 to 3300 as a fallback), failover clustering and
  Hyper-V Replica. While one is installed, no profile is set to block: the
  check names the service and the ports it can see; the operator adds the
  ports and gives `ports-checked`.
* **Local rules must count.** The module reads each profile's effective
  `AllowLocalFirewallRules` (the active store, which includes policy).
  Where Group Policy set it off, "The firewall rules defined by the local
  administrator are ignored, and only firewall rules from GPOs are
  applied", so EasyRMM's allow rules would not count: that profile is never
  set to block, and the module is *managed elsewhere*.
* **Existing rules are never changed**, enabled or disabled, and local
  rules are never stopped from merging with policy rules (the STIG asks it
  for the public profile; without policy rules, local rules are the only
  rules).
* **A server whose profile is off** (often turned off to make something
  work) is reported, not changed, unless the option `firewall-server` is
  given. With it, in **two steps**: the first turns the profile on with
  inbound connections still allowed and allowed connections logged
  (`LogAllowed`, the log at its largest, 32,767 KB), so nothing is blocked
  except by block rules already in Windows, which the check lists first,
  and starts the harvest (see Evidence over weeks), which collects every
  local port that receives an allowed connection; the second, a later
  apply once the harvest has covered 14 days without a gap (`LogAllowed`
  on throughout), allows every
  port it collected as well as the ports above, and only then blocks. It
  is refused while the harvest's coverage is shorter, and says how long
  it is and where the gaps were; the operator can add what is missing and
  give `ports-checked`. Fourteen days sees weekly jobs; a monthly one may
  not appear, which the result says. On workstations one step is enough:
  they listen on little.
* **Managed elsewhere**: a firewall policy from Group Policy, MDM or
  Defender for Endpoint; on workstations, a firewall product registered
  with Windows Security Center; on servers, a firewall product found by its
  services or by another vendor's Windows Filtering Platform providers
  (from what `netsh wfp show state` writes; W1 confirms what it lists).
* On most computers the firewall is already on and blocking; the module
  matters where someone turned it off, typically on servers.

### Microsoft Defender
* **Only where Microsoft Defender Antivirus is the active antivirus**:
  Windows reports its running mode as *Normal*. Microsoft lists Normal,
  Passive mode, EDR Block Mode and SxS Passive Mode, spelled differently on
  different pages, so the script matches them loosely; in any mode but
  Normal the module is *not applicable*.
* **Servers.** Since a server keeps Defender running beside another
  antivirus, on a server the module is also *not applicable* where a file
  system filter in the anti-virus range of altitudes (320000 to 329999,
  filters "that detect and disinfect viruses during file I/O") other than
  Defender's own is loaded, or where a service of a known antivirus
  product is installed; the check names what it found, and no option
  overrides it. **Real-time protection off is not a reason**: where
  neither is found and it is off, the module sets the rest and leaves
  real-time protection, and behaviour monitoring with it, as they are,
  and shows itself as *partly*, naming the two; the option
  `defender-server-realtime` turns both on. Without the option EasyRMM
  never turns them on on a server: an antivirus the check does not know
  may be there, and two engines on one server is what Microsoft's passive
  mode exists to avoid. Attack surface reduction then does not apply
  either (it requires real-time protection: see Attack surface
  reduction).
* Real-time protection and behaviour monitoring on (on servers, see
  above), cloud-delivered protection on, potentially unwanted applications
  blocked, SmartScreen for Explorer on, and network protection in block
  mode on Windows 10 and 11.
* **SmartScreen warns; users may go on.** Microsoft's "Warn and prevent
  bypass" (the STIG's *Block*) "Stops users from ignoring warning messages
  about malicious files downloaded from the Internet", and a file without
  a reputation gets that warning: an unsigned EasyRMM agent installer
  ([ADR-0049](0049-operators-sign-windows-agents.md)), one signed with a
  certificate SmartScreen has not seen yet, and many MSP tools. It is the
  option `smartscreen-block`, refused while this deployment's agent
  packages are unsigned, which the server knows. W2 tests an
  operator-signed installer under it.
* **The cloud protection level stays at Windows' default.** The STIG asks
  for High, which blocks unknown files more readily, and a new EasyRMM
  agent build is an unknown file. It is offered as the option
  `cloud-block-high`, with that stated.
* No exclusions are added or removed, except the per-rule attack surface
  reduction exclusions below.
* Breaks: installers bundling unwanted software; websites with a bad
  reputation; with `smartscreen-block`, downloaded programs without a
  reputation.

### Attack surface reduction
* **Requires** Microsoft Defender Antivirus active, with real-time
  protection on. For Server 2016, "Supported ASR rules in Windows Server
  2016 and Windows Server 2012 R2 require onboarding using the modern
  unified solution package"; there the module is *not supported* until a
  test shows the rules taking effect without it. Microsoft also reports "a
  known issue with the applicability of attack surface reduction on Server
  OS versions which is marked as compliant without any actual
  enforcement", so on servers W2 shows each rule acting, in audit and in
  block, rather than trusting the setting.
* **Blocked**: Microsoft's three "standard protection" rules, which
  "Microsoft recommends enabling ... in Block mode without the need for
  extensive testing": abuse of exploited vulnerable signed drivers,
  credential stealing from LSASS, and persistence through WMI event
  subscription. The last stays in audit where the Configuration Manager
  client is installed, as Microsoft advises ("The Configuration Manager
  client relies heavily on WMI"), and is not set on Server 2016 and 2019:
  Microsoft supports it from "Windows Server 1903 (SAC) or later".
* **Audit**: every other rule Microsoft's baseline for this version
  blocks, and the prevalence rule below, which the STIG asks to audit. The
  operator can block them one by one with the option `asr-block`, after
  reading their audit events, except:
  * *Block process creations originating from PSExec and WMI commands*
    (MSP tools and Configuration Manager use both), never blocked;
  * the two rules that judge files by reputation, blocked only as the next
    bullet says.
* **The reputation rules** (*Block executable files from running unless
  they meet a prevalence, age, or trusted list criterion*, and *Use
  advanced protection against ransomware*, which "also blocks files that
  don't yet have a positive reputation" but not "a valid signed file"). A
  new agent build has no reputation; signed by the operator
  ([ADR-0049](0049-operators-sign-windows-agents.md)) it passes the
  ransomware rule, though not necessarily the prevalence rule.
  * **They stay in audit until per-rule exclusions for these two rules
    alone are in place**, written as policy values (see How settings are
    written), and `asr-block` is refused for them until then. The
    exclusions name the agents' program files (the EasyRMM agent's,
    MeshAgent's and the EasyPatch agent's, and the files their updates
    run) by full path, with a wildcard only where an update's file name
    changes, never a whole folder; W2 establishes the list. No other rule
    is exempted, so the vulnerable-driver and LSASS rules still cover the
    agents.
  * **Software jobs** ([ADR-0028](0028-software-deployment.md)) run
    installers that winget and Chocolatey download to their own folders;
    those are third-party files and are never excluded, so W2 tests a
    software job under both rules.
  * **Exclusions count for processes started after them**: "Exclusions
    apply only when the application or service starts". EasyRMM restarts
    none of the agents for this. The two rules stay in audit, and
    `asr-block` is refused for them, until every agent process has
    started after the exclusions were written (the check compares their
    start times with the manifest's); until then the console shows
    *waiting for the agents to restart (next agent update or computer
    restart)*, and the operator applies again after it.
  * **Only where Windows honours per-rule exclusions**: on a version where
    W2 has not shown them taking effect, the two rules stay in audit.
  * **Refused where local merging is off** in any of the four ways
    Microsoft lists, since "per-rule exclusions or local ASR rule
    exclusions don't apply" then: Defender for Endpoint's security
    settings management and Intune (each *Disable Local Admin Merge*), the
    Defender CSP (`DisableLocalAdminMerge`), and Group Policy (*Configure
    local administrator merge behavior for lists*).
  * Undo removes the exclusions. W2 tests an agent update under them.
* *Block Webshell creation for Servers* "blocks web shell script creation
  on Windows servers running Microsoft Exchange" and is never set, though
  Server 2025's baseline blocks it. Rules are set one at a time, never
  replacing the list.

### NTLM
* LAN Manager authentication level 5 (send NTLMv2 only, refuse LM and
  NTLM), no LAN Manager hash stored, NTLMv2 session security with 128-bit
  encryption required for NTLM clients and servers, no fallback to a null
  session; on servers, incoming NTLM audited where Microsoft's server
  baseline audits it (audit only, never blocked).
* **On domain controllers** (which need the option `domain-controller`
  anyway, see Who) the level would refuse every device that still signs in
  with NTLMv1 or LM, and the domain controller's own Security log cannot
  show which those are: the member a user signs in to logs event 4624,
  whose `LmPackageName` field is "NTLM V1", "NTLM V2" or "LM", while the
  domain controller logs 4776, which names no version. So the guard uses
  Windows' **enhanced NTLM auditing** (Microsoft's KB5064479; on domain
  controllers, events 4030 to 4033 in `Microsoft-Windows-NTLM/Operational`,
  which carry the "NTLM Version"; on Windows Server 2025, and on 2022 and
  2019 from 13 October 2026). Microsoft: "By default, the events are
  enabled."
  * The first apply starts the harvest (see Evidence over weeks), which
    records each client's NTLM versions, makes the NTLM log larger, and
    stops. Log collection does not collect that log, so nothing is judged
    at once.
  * The logging must stay on for the whole window. Only where *Log
    Enhanced Domain-wide NTLM Logs* has been turned off locally, with no
    owner, does the first apply turn it on, recorded for undo; where Group
    Policy or another owner holds it off, the module is refused and the
    owner and its policy named. Undo never turns off logging that was on
    before.
  * The module goes on only when the harvest, reading the events' XML
    fields and never their translated text, has covered at least 30 days
    without a gap and found no NTLMv1 or LM sign-in; the result names each
    client that used one. Where log collection (ADR-0060) collects
    members' 4624 events, they are read too, by `LmPackageName`, and can
    refuse the module but never shorten the window.
  * On a Server 2016 domain controller, which has no enhanced auditing,
    the module is refused.
* Breaks: devices and software that speak only LM or NTLMv1 (old NAS
  boxes, copiers, line-of-business programs). Windows 11 24H2 and Server
  2025 have removed NTLMv1 already.

### LSA protection
* **LSASS runs as a protected process.** Where Windows honours the value
  `RunAsPPL` 2 ("without a UEFI variable ... only enforced on Windows 11
  build 22H2 and later"), the module writes 2, which undo can remove
  remotely. Elsewhere the value is 1, which on a computer with Secure Boot
  is kept in a UEFI variable that only Microsoft's opt-out tool, an EFI
  program booted on the computer, removes: offered only with the option
  `lsa-uefi-lock`, stated as "undo needs someone at the computer". Server
  2025 joins the first group when a test shows value 2 taking effect there.
* **Judged in audit mode, over at least 7 days of harvest.** Plug-ins
  and drivers that would not load under protection show as CodeIntegrity
  events 3065 and 3066 when LSASS loads them, if LSA's audit mode is on:
  by default on Windows 11 22H2 and later, elsewhere with `AuditLevel` 8
  under `Image File Execution Options\LSASS.exe`, which takes effect at a
  restart. Microsoft does not say when LSASS loads each plug-in, and one
  kind it names, smart card drivers, may load only when a card is used.
  So the guard needs the harvest (see Evidence over weeks; log collection
  does not collect this log) to have covered at least 7 days without a
  gap, across any number of starts: audit mode on at every start in that
  time (each run records the last start and whether audit mode was in
  effect at it), and every event from each start on. A plug-in used less
  often than that can be missed, and the result says so.
  * The first apply starts the harvest and stops. Where audit mode was on
    at the last start and the log still holds every event since it (the
    harvest's first run reads back to that start), the covered time
    begins at that start; otherwise it begins at the next
    start, and the module shows *waiting for a restart*.
  * Where audit mode is not on, the first apply also sets `AuditLevel` 8
    (recorded for undo).
  * A start at which audit mode was off, or whose events are not all
    there, is a gap: the covered time begins again at the next start.
  * A later apply judges once the covered time is at least 7 days.
* **Refused** when the harvest has found a 3065 or 3066: smart
  card drivers, password filters and other unsigned plug-ins would stop
  working. Refused too where those events cannot be logged ("Audit events
  aren't generated if Smart App Control is enabled", nor "when a kernel
  debugger is attached and enabled"), unless the option `lsa-unaudited` is
  given.
* **Takes effect at the next restart.** The check reports *waiting for a
  restart* until Windows logs that LSASS started as a protected process
  (WinInit event 12). Undo before that restart removes the value; W2
  shows, for `lsa-uefi-lock` too, that no UEFI variable is left.

### Remote Desktop
* **Only where Remote Desktop is enabled**; otherwise *not applicable*.
  The module never enables or disables Remote Desktop.
* Network Level Authentication required, the client connection
  encryption level High, secure RPC required, passwords not saved by the
  Remote Desktop client. Microsoft: "For best security, keep NLA enabled
  whenever possible."
* Refused where the security layer is set to "RDP Security Layer", with
  which NLA cannot work: reported instead.
* **EasyRMM's own RDP sessions** ([ADR-0026](0026-rdp-sessions.md)) go
  through MeshCentral's web client, which sends the credentials typed in.
  A complete session has not been run yet; W2 runs one against a device
  with NLA required before this module is recommended.
* Breaks: passwords saved in Remote Desktop clients on this computer are
  no longer used. With NLA, an account whose password has expired or must
  be changed at the next sign-in cannot start a session (Microsoft's
  workaround is to change the password first from a session of another
  account), and domain accounts cannot sign in while the computer cannot
  reach a domain controller (local administrators still can).

### User Account Control
* **Not applicable on Server Core**: "UAC requirements are not applicable
  for Server Core installations".
* Administrators asked for consent on the secure desktop (stricter
  settings left), installer detection, elevation only for UIAccess
  programs in secure locations, write failures virtualized, and Windows
  Installer never "always install with elevated privileges".
* **UAC turned off** (`EnableLUA` 0) is turned on only with the option
  `uac-enable`: it needs a restart, and everything that ran with UAC off
  then runs differently.
* **Admin Approval Mode for the built-in Administrator**
  (`FilterAdministratorToken`) only with the option `uac-builtin-admin`.
  It gives the built-in Administrator a filtered token like other local
  administrators, so admin shares, WMI, PsExec and WinRM used with that
  account stop getting full rights. Even with the option it is set only
  when 30 days of events show no network sign-in (event 4624, logon type
  3) by the built-in Administrator (the computer's own account domain SID
  followed by RID 500; the domain's on a domain controller): the events
  log collection has collected from this computer, where it reports that
  collection without a gap over the 30 days. Otherwise the first apply
  starts the harvest (see Evidence over weeks) and stops; a later apply
  judges once the harvest has covered 30 days without a gap. Any such
  sign-in refuses it, and the result names its time and source.
* **Not set**: automatically denying elevation to standard users (the
  STIGs ask for it). It stops a technician typing an administrator's
  password into a user's prompt during remote support; offered as the
  option `deny-user-elevation`.
* `LocalAccountTokenFilterPolicy` set to 1 (local administrators keep their
  full rights over the network, which some MSP tools need) is reported,
  never changed.
* The agent and its jobs run as LocalSystem and are not affected.
* Breaks: prompts on the secure desktop. Whether MeshCentral's remote
  desktop can answer a prompt there is tested in W2 before the module is
  recommended.

### Audit policy
**Log collection owns Windows audit policy.** Its *Configure logging*
(`logs.configure`, ADR-0060, proposed and not implemented) sets the
advanced audit subcategories, `SCENoApplyLegacyAuditPolicy` (subcategories
override categories), command lines in process creation events,
PowerShell script block logging and the event logs' sizes, from the
agent, leaving what an owner holds; domain controllers only when chosen
(`logs.configure.domainControllers`). Hardening sets none of these, so
the two never fight over a value or over whose undo puts it back.

* **One table.** ADR-0060's *Windows audit policy* table is the target,
  and this ADR keeps no table of its own. It adopts the audit subcategories
  of Microsoft's baselines for Windows 11 and Server 2025, including those
  the first draft of either ADR left out (Group Membership, Removable
  Storage, File Share, Detailed File Share, Sensitive Privilege Use, Other
  System Events, Authorization Policy Change, Other Policy Change, and on
  domain controllers Directory Service Access and Changes), and sets
  `SCENoApplyLegacyAuditPolicy` and a Security log of at least the STIGs'
  minimum. The table is kept once in the repository as data, beside the
  ownership reader, and read by the agent's configuring and by this
  script, so that a computer log collection has configured shows `audit`
  in place.
* The `audit` module is **report only**. It compares the effective
  audit policy (subcategories by GUID), `SCENoApplyLegacyAuditPolicy`, the
  command line setting and the log sizes with that table, and shows each
  as *in place*, *managed elsewhere* (with the owner), or missing, naming
  *Configure logging* (`logs.configure`) as the way to set it.
* **What the baselines set and log collection does not is information,
  not a gap.** A subcategory ADR-0060 marks *baseline, not set by default*
  (one that would fill the Security log too fast on a kind of computer) is
  shown as such, with the reason, and does not keep the module from being
  in place.
* The `powershell` module reports script block logging the same way.
* **EasyRMM's own changes are not alerts.** Hardening's apply and undo of
  `defender` change settings that log collection's *Protection turned off*
  detection watches (Defender events 5001, 5010, 5012); an undo that
  turns real-time protection off again on a server where
  `defender-server-realtime` turned it on is the obvious case. The job's
  result lists each change with its time, and log collection shows a match
  explained by a hardening job on that device, within its run, with its
  cause and opens no alert (ADR-0060).
* Until log collection ships, these values stay reported, not set.

### Backups, undo and interruptions
As in ADR-0051, with Windows' places and tools:

* **Where.** `%ProgramData%\EasyRMM\Hardening\`, apart from the agent's
  state (`%ProgramData%\EasyRMM\Agent`), which uninstalling the agent
  removes. It is created as a plain folder with access for LocalSystem
  and Administrators only. Removing a device
  ([ADR-0050](0050-removing-a-device.md)) leaves the hardening in place,
  and the guide says so.
* **Checked before every mode**, the harvest included, since any local
  user may create folders under `ProgramData`, and one planted there
  before the first apply, or changed since, must not be trusted. The
  script applies PR #61's rule, the one the agent applies to its own
  state folder:
  * **The chain**: every folder from `ProgramData` down to `Hardening\`
    is a plain folder (no junction or other reparse point) with a trusted
    owner (SYSTEM, Administrators or TrustedInstaller).
  * **What it holds**: `Hardening\`, the manifest, the script's copy and
    the lock file must each have a trusted owner, and the files must be
    plain files with one link, opened without following reparse points.
  * **Judged by who may write.** Where no one but SYSTEM, Administrators
    or TrustedInstaller may write, an access list that differs from the
    protected one (entries in another order, an extra Administrators
    entry, a read-only grant) is set back to it, a warning is given, and
    the run goes on. Where anyone else may write, the entry fails.
  * **Only inside `Hardening\` is anything moved.** A failing manifest,
    copy or lock file is moved aside within `Hardening\` and never read
    again, and the run refuses, saying what it found; for the manifest,
    the result gives its new path, so that an administrator can review it
    and put it back. A failing `Hardening\`, or a folder above it, is
    never moved (`%ProgramData%\EasyRMM` holds the agent's state): the
    run refuses and names it, for an administrator.
  * In check mode, setting an access list back and moving something
    aside are the only changes the script makes.
* **The copy's hash finds drift and corruption; it protects nothing.** The
  manifest, which records the copy's SHA-256 when apply or undo writes
  it, sits beside the copy, so whoever could change one could change
  both. Every result reports the copy's hash, and the server compares it
  with the SHA-256 of the script the device's last apply or undo job ran
  (ADR-0017 records it) and shows a difference. Apply, undo and check,
  which run from the signed job and never from the copy, also compare it
  with the manifest's and move aside a copy that differs. Until the next
  apply or undo writes a new copy, the harvest stops (its time is a gap)
  and undo on the computer itself is unavailable, and the check says so.
  What keeps the copy sound is that apply checks the folder before it
  writes anything there, and that afterwards only those three may write
  to it.
* **What is recorded**, per module, in a manifest with a format version:
  each registry value before (absent, or its type and data) and after,
  Defender's and attack surface reduction's policy values among them (each
  rule's mode and each per-rule exclusion EasyRMM added); for Defender,
  also the local settings apply outranked, and what `Get-MpPreference` and
  `Get-MpComputerStatus` reported before and after; each security policy
  value before; each firewall profile's settings before, as the local
  store held them, and the names of EasyRMM's rules; each feature's and
  service's state before; what the first of two steps turned on or changed
  (the SMB1 audit, enhanced NTLM logging where it had been off, the NTLM
  log's size, LSA's audit level, a server profile's logging, the
  harvest's scheduled task and which modules it serves), and when; the
  script copy's SHA-256; and what the harvest found, with each run's
  time, the computer's last start, the logging it found in effect, and
  for each log the newest event it read (record ID and time; for the
  firewall's log, the last complete line, its time and the byte offset
  at which it ends). Every later script reads every earlier manifest
  format.
* **Undo** puts each one back if it is still as apply left it; anything
  changed since (by an administrator, a policy, Windows) is left and the
  result says so. Features come back from their kept payload; EasyRMM's
  firewall rules and per-rule exclusions are removed, and the harvest's
  task once no other module still harvests. Undo also runs where the
  platform is now check only or the reader *cannot tell*, leaving every
  value in the unreadable owner's place (see Before anything changes). A
  successful undo consumes the record; the next apply takes a fresh one.
  Applying twice changes nothing the second time. ADR-0067's registry
  editor, before a write, shows whether this manifest lists the value, and
  warns that changing it leaves hardening's undo for that value.
* **Firewall settings that were not configured** in the local store
  (Windows' defaults) are put back as not configured, never written as an
  explicit *Block* or *Allow*. Microsoft documents `NotConfigured` as
  "Valid only when configuring a Group Policy Object", so W2 settles which
  call does this for the local store, and tests it.
* **Undo before a restart.** Changes that wait for a restart are undone
  before it as well as after, and a pending restart never refuses undo: a
  feature waiting to be removed is enabled again (where component-based
  servicing will not take that while the removal is pending, undo reports
  it *to be restored after the restart*: see Before anything changes),
  UAC's value is written back, `RunAsPPL` and `AuditLevel` are removed.
  W2 tests each, before and after the restart.
* **Interruptions.** Each module writes its intent before changing
  anything and marks it done after; a later check reports a module left
  half-applied, and undo reverses what was recorded.
* **Without the agent.** Apply and undo copy the script to
  `%ProgramData%\EasyRMM\Hardening\easyrmm-hardening.ps1`, so that undo can
  be run on the computer (`powershell -ExecutionPolicy Bypass -File
  "%ProgramData%\EasyRMM\Hardening\easyrmm-hardening.ps1" undo all`, as an
  administrator) from MeshCentral's terminal, a console, or after the
  agent is gone. The harvest's task runs the same copy. The copy is
  checked like the rest of the folder before it runs.

### Lock-out guards
* **Remote Desktop and WinRM stay reachable.** The firewall changes only
  the profiles that need it, allows every listening port, RDP, WinRM, RPC
  and echo before it blocks anything, does not block while a service whose
  ports move is installed or while local rules would be ignored, and
  turns a server's profile on only with an option and in two steps; NLA
  waits for the RDP test; WinRM is never stopped and its listeners never
  removed.
* **The agents are never cut off.** The EasyRMM agent, MeshAgent and the
  EasyPatch agent connect out, and EasyRMM never blocks outbound traffic;
  their services are never stopped or changed; Defender's High cloud
  protection level and SmartScreen's *Block* are only set when the
  operator chooses them, the latter never while the agent packages are
  unsigned; the reputation-based attack surface reduction rules are only
  blocked once per-rule exclusions for the agents' files are in place and
  every agent process has started after them by itself.
* **The MSP's accounts are never disabled**, renamed or denied a sign-in
  right; lockout (10 attempts, 15 minutes) is the one way an account can
  be blocked, it ends by itself, and it is not set on computers exposed to
  spraying without an option. The built-in Administrator keeps its full
  rights over the network unless the operator chooses otherwise and 30
  days of events, collected or harvested, show it unused there.
* **The computer's restarts are reported, never performed.** Modules
  whose change waits for one (`lsa-protection`, `tls`, `smb` where it
  removes the feature,
  `powershell` and `features` where they do, `uac` with `uac-enable`)
  report *waiting for a restart*, and the device shows *restart needed*
  until a check sees the change in effect. The operator restarts when it
  suits. Applying a feature's removal is refused while a restart is
  pending; undo never is, and works before the restart.
* **Each module checks itself**: after writing, it reads every value back;
  if one is not as intended, the module is put back and reported failed,
  and the others go on.
* **One change at a time** on a device (see The job), and **domain
  controllers** need an explicit choice (see Who).
* If access is lost anyway, MeshCentral's terminal (connecting out) still
  reaches the computer, and **Undo** works through the agent or on the
  computer itself.

### Platforms
* **Apply and undo** on the versions this script has been tested on,
  listed in the guide by build: Windows 11 Pro, Enterprise and Education
  in a version Microsoft still services for that edition (24H2 Enterprise
  until 2027-10-13, 25H2, 26H2); Windows 11 26H1, the release for new
  devices with new processors ("not designed to be offered or installed on
  existing devices"; serviced to March 2029 for Enterprise, March 2028 for
  Home and Pro), once a 26H1 computer has been tested; Windows Server 2025,
  2022 and 2019, Desktop Experience and Server Core; Windows Server 2016
  until its extended support ends (13 January 2027 on its lifecycle page;
  Microsoft's FAQ gives a different date in one place). A newer build is
  *not supported on this version* until tested, as on Linux.
* **ARM64** waits for the agent's ARM64 build to have run on a real
  Windows ARM64 computer, which IMPLEMENTATION_STATUS.md lists as not yet
  verified, as well as for the `windows-11-arm` runner's results.
* **Check only** (apply refused; undo of an earlier apply still runs,
  see Before anything changes): Windows 10 22H2 (support ended 14 October
  2025; paid
  Extended Security Updates run to October 2028, see Open questions),
  Windows 11 versions out of service for their edition (23H2 Enterprise
  since 2026-11-11, 24H2 Home and Pro since 2026-10-14), Home editions
  (outside the baselines and STIGs), Azure Virtual Desktop's multi-session
  Windows until tested, Server 2016 after 13 January 2027, and computers
  whose settings an owner holds that EasyRMM cannot read yet (Group Policy
  with its record turned off or with registry preference items, MDM, a
  Configuration Manager client, DSC correcting drift, Azure machine
  configuration), each until its reader is proven (see Managed elsewhere).
* **Domain controllers** with the option `domain-controller`.
* Older Windows does not run the agent.

### Who
* **Check** needs `script.run` (Technicians and above); **apply and undo**
  need `device.harden` (Site Administrators and above), as in ADR-0051. No
  new permission.
* **Domain controllers**: apply and undo also need the option
  `domain-controller`, chosen in the dialog after a warning that some
  changes affect every computer that signs in to the domain (NTLM).
* As for other jobs, every device needs the permission, an EasyRMM agent
  and a supported platform, or nothing runs. Viewing results needs
  `device.view`.
* **A run's raw output and a job's argument values** need
  `job.view_sensitive` (Technicians and above,
  [ADR-0063](0063-who-sees-job-output-and-arguments.md)); a device's
  findings, and a job's mode, modules and options, do not.

### The rest
* **Audit**: `device.hardening`, with the mode, modules, options and job;
  for the daily check, one row per organization per daily batch (see The
  job), with the system as its actor, and the system's cancellations of
  checks an undo replaced.
* **API**: `POST /api/v1/jobs/hardening` and `GET
  /api/v1/devices/{id}/hardening`, as in ADR-0051; `canHarden` and
  `canCheckHardening` cover Windows devices.
* **Options** the server accepts for Windows: `allow-tcp` and `allow-udp`
  (ports and ranges), `ports-checked`, `firewall-server`,
  `domain-controller`, `defender-server-realtime`, `smartscreen-block`,
  `cloud-block-high`, `asr-block` (rule GUIDs from a fixed list),
  `lsa-uefi-lock`, `lsa-unaudited`, `lockout-exposed`, `uac-enable`,
  `uac-builtin-admin`, `deny-user-elevation`, `winrm-basic-off`,
  `spooler-off`.
* **The script's hash is published** in each release's notes and in the
  guide, beside the copy and hash each job keeps. An EDR or a managed
  detection service may take a script that runs as LocalSystem and changes
  LSA, Defender and the firewall for an attack and isolate the computer;
  the guide tells MSPs to allow the script by its hash before the first
  apply.

## Testing
* **Static checks**: PSScriptAnalyzer on the script, and Windows
  PowerShell 5.1 parsing it, in CI; the STIG ID test above; a test that
  fails when a module, mode and Windows role has no case; the size limits;
  the related-controls tables regenerated and compared.
* **CI's Windows runners**, from the first module on. For this public
  repository GitHub provides `windows-2025` and `windows-2022` (x64) and
  `windows-11-arm` (Windows 11 Enterprise on ARM64), each with 4 CPUs and
  16 GB. The hardening tests are `OnWindows` Go tests like the software
  scripts', in a matrix over those three labels; the existing *Agent tests
  on Windows* job keeps its tests and its `windows-latest`. The script runs
  as LocalSystem, as the agent's service would run it, through a scheduled
  task. For each module: check, apply, check, apply again (no change),
  undo, check, with every recorded value as before. ADR-0064's Windows
  test job (the MSP plan's step 6, before W1), ADR-0067's and ADR-0068's
  run the agent's own tests the same way, as LocalSystem through a
  scheduled task, each in a job of its own over `windows-latest` and
  `windows-11-arm`.
* **What runners cannot show**: restarts; domains and Group Policy from a
  domain; traffic from outside; MDM; and whatever the runner images change
  themselves. `Configure-WindowsDefender.ps1` "Disables Windows Defender"
  (real-time protection off, `C:\` and `D:\` excluded),
  `Configure-BaseImage.ps1` sets UAC's `ConsentPromptBehaviorAdmin` to 0,
  and `Configure-System.ps1` stops and disables Windows Update. So on
  runners `defender` and `asr` run in check mode only, and must report
  what the image turned off; their apply and undo, UAC's prompts and the
  removal of features are tested on machines with Defender active and
  Windows' services as shipped.
* **Windows machines under KVM**, extending `internal/vmtest` (ADR-0051's
  harness, now on `main`, which drives Linux guests over a virtio-serial
  port) to Windows guests:
  * Microsoft's evaluation media (Windows Server 2016 to 2025, 180 days;
    Windows 11 Enterprise, 90 days, ISO only), installed unattended;
    devices Windows has drivers for out of the box (an AHCI disk, an e1000e
    network card, a 16550 serial port), so no virtio drivers; Windows 11
    with OVMF's Secure Boot and a software TPM (`swtpm`), as it requires.
  * **Never cached where a pull request can restore it.** GitHub lets a
    pull request's run "restore caches created in the base branch,
    including base branches of forked repositories", so a cached Windows
    image would reach anyone who opens a pull request, and the evaluation
    media's terms have not been read. The images are built in each run, by
    jobs that run on pushes to `main` and on a schedule, never for pull
    requests; or the guests run on a self-hosted runner the owner provides
    (see Open questions). Building in each run also keeps them out of the
    cache's 10 GB per repository (the default) and away from the end of
    the evaluation periods.
  * Driven over the serial port through a small runner service built from
    this repository and baked into the image (Windows has no serial shell
    of its own), so that a firewall cannot cut the harness off.
  * Whether this works is decided in W1, and the ADR is amended if not:
    GitHub says nested virtualization is "not officially supported" (KVM on
    its Linux runners is documented, and H1 relies on it); Windows guests
    on 4 CPUs are slow, and building their images in each run slower;
    whether the evaluation media can be downloaded without a form, and
    whether their terms allow automated testing, has not been checked;
    Windows 11's evaluation asks for a Microsoft account;
    virtualization-based security inside a nested guest probably cannot
    run. The fallback is a self-hosted runner the owner provides, or the
    same scenarios run by hand on the owner's machines and recorded.
  * **Other ADRs wait for these machines.** ADR-0064, ADR-0065, ADR-0067
    and ADR-0068 plan Windows tests on them: Windows with and without
    PowerShell 7, `AllSigned` from Group Policy and Constrained Language
    Mode (ADR-0064); QEMU's NVMe and AHCI disks under Windows' own drivers
    (ADR-0065); Group Policy setting a value back, a domain account's
    hive and App Control (ADR-0067); a domain account's SID, event
    forwarding between two machines, Sysmon's events and Group Policy
    setting a log's size (ADR-0068). The MSP plan builds feature 12's pair
    of domain controllers in the same harness. So W1's decision, or its
    fallback, decides how those are verified too.
* **Scenarios, one or more per guard**, as in ADR-0051:
  * Persistence, first of all (see How settings are written): on Server
    2016, Server 2025 and Windows 11 domain members, every administrative
    template value EasyRMM writes, Defender's and attack surface
    reduction's included, still in place after an unrelated Group Policy
    object with registry settings is edited, one is linked and one is
    unlinked or removed, each followed by `gpupdate /force` and counted
    only when the registry extension's events 4016 and 5016 are logged
    for that refresh; and on a workgroup computer after an unrelated
    change to the local Group Policy object (LGPO.exe, in the test only).
  * Restarts: values persist, LSA protection active after one, features
    removed; undo before the restart (a feature waiting for removal, UAC,
    `RunAsPPL` with and without `lsa-uefi-lock`); a pending restart
    refusing a feature's removal but not its undo; *undo needed* after the
    restart, and apply refused until that undo has run; an undo recorded
    by an earlier script's manifest format, run by the current one.
  * Undo on a computer gone check only, on an untested version (labelled
    so), and under each *cannot tell* reason: values still as EasyRMM left
    them restored, values in that reason's places left and reported, and
    for DSC, a Configuration Manager baseline and Azure machine
    configuration, restored with the owner named.
  * The Hardening folder: planted before the first apply by a standard
    user, owned by that user, with a junction in its path (each refused,
    nothing moved, `%ProgramData%\EasyRMM` untouched); a hard-linked
    manifest, script copy or lock file, one with a grant letting users
    write, and a copy changed after apply wrote it (each moved aside
    within `Hardening\`, the run refused, a set-aside manifest's new path
    in the result); an extra Administrators entry or a read-only grant
    (set back, a warning, the run goes on); in every mode, the harvest
    included, a check making no other change. A copy whose hash differs
    from the last apply's script, shown by the server; the harvest and
    undo on the computer stopping until the next apply writes a copy.
  * The harvest: logging turned off locally (no owner) between runs, and a
    log set to keep its events that fills (each a gap); NTLM's logging
    turned off by a Group Policy object (refused, the policy named); the
    firewall's log rotated past the last line read, and a last line no
    longer ending at its recorded offset (each a gap); a partly written
    last line (not read until complete); the Logon subcategory's success
    audit off with no owner (a gap, *Configure logging* named); a domain
    controller with more than 4,096 NTLMv2 clients (no limit reached);
    the distinct-value limit reached (refused); two modes at once (the
    second waits for the lock file, or the harvest skips its run); a run
    killed while holding it (the next one opens it); the task ending at
    its end date, at that date moved forward by gaps up to 90 days
    (*harvest ended: apply again*), and when the EasyRMM agent is
    uninstalled.
  * The daily check: created at each device's own time, not created while
    an apply or undo is queued or running, one outstanding per device at
    most, a missed day not caught up; an undo cancelling a queued or
    delivered check (by the system, *replaced by an undo*, the user
    without `job.manage`) and waiting for a running one; one audit row per
    organization per batch; runs gone after 7 days; a Configuration
    Manager client installed after apply (*an owner EasyRMM cannot read
    appeared*, undo offered).
  * Firewall: a port forwarded from outside reaching a listening service
    before and after; a public profile already blocking, left without a
    rule and with only its logging set; WMI from a second guest after
    blocking (RPC); echo from outside; a SQL Server Express named instance
    (ports move: refused); a Group Policy object turning local rules off
    (refused); a server with its firewall off, in two steps, with a log
    small enough to wrap between harvests (a gap: the window starts
    again); every profile's log size and logging put back by undo.
  * Defender and attack surface reduction: a guest with Defender active;
    the values written as policy, read back by `Get-MpPreference`; a local
    `Set-MpPreference` value outranked and reported; a Group Policy object
    setting Defender after apply (*managed elsewhere* at the next check);
    a server with real-time protection off, with and without
    `defender-server-realtime`; an unsigned agent, and one signed with a
    certificate made for the test, installed and updated under
    SmartScreen's *Block* and under the reputation rules with the per-rule
    exclusions, the rules waiting in audit until the agents have restarted
    by themselves; a software job under them; Tamper Protection on, its
    settings reported.
  * SMB1: a client on the host forcing SMB1 against a guest with SMB1 on
    (event 3000, harvested: refused).
  * NTLM: a Server 2019 or 2022 domain controller with enhanced NTLM
    auditing and a Windows 10 or Server 2019 member set to send NTLMv1
    (harvested: refused); the domain-wide logging turned off locally
    beforehand, with no owner (turned on, and off again by undo), left on
    (untouched by undo), and turned off by a Group Policy object
    (refused, the policy named); a Server 2016 domain controller
    (refused).
  * LSA: an unsigned password filter built in the repository (event 3066:
    refused); audit mode off at the last start (the `AuditLevel` step,
    covered time beginning at the next start); a harvest shorter than 7
    days (waits); 7 days across several starts (judged); a start with
    audit mode off between them (a gap).
  * A printer shared from a domain controller (the spooler left).
  * Remote Desktop: the RDP Security Layer (refused); NLA through
    MeshCentral's web client.
  * UAC: the built-in Administrator signing in over the network from a
    second guest (`uac-builtin-admin` refused, from log collection's
    events where it collects them, and otherwise from the harvest);
    the computer's built-in Administrator told apart from another account
    whose SID ends in 500; Server Core (not
    applicable); a prompt on the secure desktop answered through
    MeshCentral.
  * Lockout: ten failed sign-ins to one account within 15 minutes
    (refused without `lockout-exposed`). QEMU's user networking gives
    only private addresses, so failed sign-ins from a public address are
    tested with a recorded Security log, a stand-in that its result names.
  * Owners: a domain of a Server 2025 domain controller, a member server
    and a Windows 11 member on QEMU's socket networking, with Group Policy
    objects setting some of the same values, audit policy among them
    (policy ownership, shared with log collection's tests; Group Policy's
    refresh does not fight apply; the domain controller option), one with
    registry preference items, one turning the resultant set of policy's
    logging off; a DSC configuration in `ApplyAndAutoCorrect`; an OSConfig
    baseline on Server 2025, its module installed in the guest for the
    test; a value set back twice by a scheduled task (owner unknown).
  * A German-language image (SIDs, GUIDs and XML fields, not names);
    Server Core; Server 2016 and 2019, which have no runner.
  * Not possible in these machines, so on real ones only (below): MDM,
    Defender for Endpoint, a Configuration Manager client (it needs a
    site; any test with only its traces is a stand-in, and its result says
    so), Azure machine configuration, a third-party antivirus or firewall
    on a server.
* **Before it is called complete** it is run on real computers: a real
  domain with a domain controller and member servers; a Windows 11
  enrolled in Intune, and one enrolled after apply (the daily check
  reports *EasyRMM's value outranks*); computers with a third-party
  antivirus and firewall, servers among them; and the script under a
  common EDR, to see whether it is taken for an attack (see Open
  questions).

## Slices
The [MSP plan's order](../feature-plan-msp.md#order), decided in review,
places W1, W2 and W3 at its steps 7, 8 and 9: after F0 (ADR-0063) and
remote PowerShell's slice 1, and before notifications.

* **W1, check.** The script's skeleton (platform, role, language mode, the
  Hardening folder's check as in PR #61, the manifest and its lock file,
  the JSON result); the ownership reader in `internal/winpolicy`
  with its three results (Group Policy with its audit policy, preferences,
  its record turned off, MDM from the `Config` node, Defender for
  Endpoint, Configuration Manager, DSC, Azure machine configuration,
  OSConfig, Tamper Protection, other antivirus and firewalls) and
  ADR-0060's audit table as data beside it, for log
  collection to reuse, and startable as ADR-0067 starts it (see Policy
  ownership); `check` for every module; on the server, the
  Windows platform, module names, options and result fields, and the
  related-controls tables with the tool that generates them; the static
  checks and the runner matrix in check mode; the KVM decision, proved
  with one Server image and the domain scenario, or recorded with why not
  (ADR-0064, ADR-0065, ADR-0067 and ADR-0068 wait for it too);
  the MDM reader on a real Intune-enrolled Windows 11.
* **W2, apply and undo**, module by module, each with its runner tests and,
  where it needs a restart, a domain, Defender active or outside traffic,
  its machine test (or recorded hand test) before the next. First the
  persistence test (see Testing), which decides whether administrative
  template values are written at all; then low-risk modules (`autoplay`,
  `wdigest`, `anonymous`, `winrm`, `features`, `powershell`, `accounts`,
  `printing`), then `defender`, `asr`,
  `name-resolution`, `smb`, `ntlm`, `uac`, `firewall`, `rdp`,
  `smb-signing`, `lsa-protection`, `tls`; the report-only modules have no
  apply. With them: the undo copy of the script; the harvest, with the
  first two-step module; the daily check and its amendments to ADR-0017,
  with `defender` (extending what F2 built, if F2 came first: see The
  job); one change at a time on the server; each change and its time in
  the result, for log collection.
* **W3, the console.** Linux hardening's H3 (a device's **Hardening** tab,
  the fleet column and filter, apply and undo from **Jobs**) with Windows'
  modules: their risks and options, the owner of each setting managed
  elsewhere or outranked by EasyRMM's value, the reason for each *check
  only*, whether each setting meets its rule, *restart needed*, the
  two-step modules' state and their harvest's coverage, and the *Related
  controls* panel; mixed
  selections sent as one job per platform.

## Consequences
* An operator can check a fleet of Windows computers in one job, see per
  module what is in place, who else owns what, which rules each setting
  meets and which controls it relates to, apply what is missing, and undo
  it module by module.
* Choosing safety over strictness leaves Windows looser than the STIGs,
  and the console says where: lockout after 10 attempts, and none on
  exposed computers without an option; no password expiry; SmartScreen
  that warns; the default cloud protection level; most attack surface
  reduction rules in audit; standard users still offered elevation; the
  built-in Administrator unfiltered over the network; SMB signing and TLS
  1.0 removal left to the operator; no deny-sign-in rights; the spooler
  off only on domain controllers; a server's firewall and Defender's
  real-time protection and behaviour monitoring left off without an
  option. The check is not an
  audit against a benchmark.
* Defender's and attack surface reduction's settings are written as
  policy: scanners following the Defender STIG find them, but technicians
  can no longer switch them in Windows Security, and they outrank an MDM
  that arrives later until the daily check reports it and someone undoes
  them. Whether any administrative template value outlives Group Policy's
  processing is unknown until W2's first test.
* Several modules take two applies, most of them days or weeks apart
  (SMB1, a server's firewall, NTLM on domain controllers, the built-in
  Administrator's filtering, LSA protection, and the reputation rules,
  which wait for the agents to restart by themselves after their
  exclusions): slower, but each change is judged on what the computer
  did, and only from evidence gathered while its logging was on. The
  harvest that makes this possible is one more scheduled task on the
  computer while it runs, which an EDR may flag; it ends by itself.
* Computers whose settings come from Group Policy, Intune or OSConfig are
  mostly reported, not changed: an MSP that manages a domain by Group
  Policy keeps doing so, and EasyRMM shows where its policy differs.
  Where the ownership reader *cannot tell* (Configuration Manager, Azure
  machine configuration, DSC correcting drift, Group Policy preferences or
  its record turned off, MDM until W1, Defender for Endpoint for its
  settings), the computer or those settings get check only, in hardening
  and log collection alike; undo of an earlier apply still runs, and
  leaves what such an owner may hold.
* EasyRMM says nothing about CIS or CMMC. MSPs who are asked for "CIS
  Level 1" get Microsoft's values with DISA's rule IDs, unless the owner
  decides to buy CIS's membership and certification; those asked about
  CMMC see SP 800-171 Rev. 2's numbers as related requirements, not an
  assessment.
* Script block logging and process command lines (set by log collection)
  record secrets that scripts and command lines contain, in logs that
  administrators can read; log collection redacts what it collects, not
  what stays on the computer.
* Where Group Policy allows only signed scripts or App Control constrains
  PowerShell, nothing runs, as for every PowerShell job today. An EDR may
  stop the script unless the MSP allows it by its hash.
* W1 and W2 carry more than hardening: ADR-0067's registry writes and
  ADR-0068's log settings use the ownership reader, and registry changes
  and `eventlog_manage` the device lock; F2 extends W2's job amendments;
  log collection's *Configure logging* waits for the reader; and the
  Windows paths of ADR-0064, ADR-0065, ADR-0067 and ADR-0068 that the
  runners cannot show stay unverified until the Windows machines under
  KVM, or real computers, show them.
* The script follows Windows releases, Microsoft's baselines and DISA's
  STIG releases; each new build is tested before apply is allowed on it.

## Open questions for the owner
Until the owner answers these, this ADR's proposed defaults apply; most of
them only matter at W2 (apply).

* **CIS.** Buy the CIS SecureSuite Product Vendor Membership (from $6,000
  a year at the lowest revenue band, "Subject to change") and have the
  feature certified every year before it is sold, distributed or marketed,
  so that EasyRMM can name CIS recommendations? This ADR assumes no.
* **Windows 10 and Server 2016 with Extended Security Updates**: check
  only, as proposed, or apply and undo where the computer still receives
  security updates?
* **The lockout threshold**: 10 attempts, as proposed, or the STIGs' and
  Server 2025 baseline's 3 on servers?
* **Attack surface reduction**: block only Microsoft's three standard
  rules, as proposed, or more by default?
* **SMB signing and NTLM**: `smb-signing` off by default and `ntlm` on, as
  proposed?
* **Signing EasyRMM's PowerShell scripts** for computers whose Group
  Policy allows only signed scripts: it depends on code signing, which is
  on hold; is it wanted when that resumes?
* **ASD's guide and the Essential Eight**: cyber.gov.au cannot be fetched
  from here. Will the owner download *Hardening Microsoft Windows 11
  workstations* and the Essential Eight's pages by hand, so that their
  licence can be read and the modules related to them for Australian
  customers?
* **An Intune tenant** for W1's MDM reader and the real-computer tests
  (and, if licensed, Defender for Endpoint, to settle its security
  settings management)?
* **The test domain**: besides the Server 2025 domain controller, a
  Server 2016 to 2022 domain controller and a member that still sends
  NTLMv1, for the NTLM guard; in the KVM machines or on the owner's?
* **A self-hosted runner** for the Windows guests, since their images may
  not be cached where pull requests can restore them and building them on
  GitHub's runners in each run may prove too slow? The same guests now
  carry the Windows machine tests of ADR-0064, ADR-0065, ADR-0067 and
  ADR-0068 (see Testing).
* **LGPO.exe on a hosted runner**: its terms allow use "on your devices
  to develop and test your programs". Does a GitHub-hosted runner count
  as one of "your devices"? Until that is answered, the persistence
  test's workgroup case runs on a self-hosted runner or by hand (see How
  settings are written).
* **Which EDR or managed detection service** to run the script under
  before it is called complete: the one MSPs using EasyRMM most often run?
* **Check only for computers with Configuration Manager, DSC or Azure
  machine configuration** until their readers exist: acceptable, or should
  those readers come first?
* **The evaluation media's terms** (https://aka.ms/useterms): do they
  allow test machines built from Microsoft's evaluation media, by script,
  on CI or on the owner's own server? W1's machine tests used them on the
  owner's Proxmox server; the terms have not been read against that use.
* **Order**: the MSP plan's order, decided in review, puts W1 to W3 at
  its steps 7 to 9, after the updater's edge channel (step 4), F0
  (step 5) and remote PowerShell's slice 1 (step 6); sooner, straight
  after Linux hardening?

## References
CIS:
* Terms of use for non-member CIS products: https://www.cisecurity.org/terms-of-use-for-non-member-cis-products
* Product Vendor Membership, its fees and CIS tools in products: https://www.cisecurity.org/cis-securesuite/pricing-and-categories/product-vendor/
* Remediation certification: https://www.cisecurity.org/cis-securesuite/pricing-and-categories/product-vendor/cis-benchmarks-remediation-certification/
* Logos and trademark use: https://www.cisecurity.org/cis-logos-and-trademark-use-policy
* Benchmarks FAQ: https://www.cisecurity.org/cis-benchmarks/cis-benchmarks-faq
* Windows benchmarks: https://www.cisecurity.org/benchmark/microsoft_windows_desktop, https://www.cisecurity.org/benchmark/microsoft_windows_server
* CIS Controls v8.1: https://www.cisecurity.org/insights/white-papers/cis-critical-security-controls-v8-1

Wazuh:
* Windows policies: https://github.com/wazuh/wazuh/tree/main/ruleset/sca/windows
* Licence in 4.14.10 and on main: https://github.com/wazuh/wazuh/blob/v4.14.10/LICENSE, https://github.com/wazuh/wazuh/blob/main/LICENSE
* 4.14.10: https://github.com/wazuh/wazuh/releases/tag/v4.14.10
* Compliance: https://documentation.wazuh.com/current/compliance/index.html
* Available policies: https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/available-sca-policies.html

DISA and copyright:
* STIGs (each zip holds the overview and XCCDF): https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_11_V2R11_STIG.zip, https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_10_V3R6_STIG.zip, https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_Server_2025_V1R4_STIG.zip, https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_Server_2022_V2R11_STIG.zip, https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_Server_2019_V3R9_STIG.zip, https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_Server_2016_V2R10_STIG.zip, https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Defender_Antivirus_V2R10_STIG.zip, https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_Defender_Firewall_V2R2_STIG.zip
* CCI list: https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CCI_List.zip
* 17 U.S.C. 105: https://www.copyright.gov/title17/92chap1.html

Microsoft baselines and tools:
* Security Compliance Toolkit (the LGPO download carries the standalone use terms): https://www.microsoft.com/en-us/download/details.aspx?id=55319
* The toolkit: https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10
* Baseline versions: https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/get-support-for-security-baselines
* Windows 11 26H2 baseline: https://techcommunity.microsoft.com/blog/microsoft-security-baselines/windows-11-version-26h2-security-baseline/4560382
* Server 2025 v2602: https://techcommunity.microsoft.com/blog/microsoft-security-baselines/security-baseline-for-windows-server-2025-version-2602/4496468
* Tool use terms: https://techcommunity.microsoft.com/t5/microsoft-security-baselines/new-amp-updated-security-tools/ba-p/1631613
* Baselines, CIS and NIST: https://learn.microsoft.com/en-us/intune/device-security/security-baselines/overview
* OSConfig: https://learn.microsoft.com/en-us/windows-server/security/osconfig/osconfig-how-to-configure-security-baselines, https://learn.microsoft.com/en-us/windows-server/security/osconfig/osconfig-overview, https://techcommunity.microsoft.com/blog/itopstalkblog/using-osconfig-to-manage-windows-server-2025-security-baselines/4415824

Owners of settings:
* RSoP registry settings: https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/rsop-registrypolicysetting
* RSoP security settings: https://learn.microsoft.com/en-us/previous-versions/aa375070(v=vs.85)
* Turning RSoP logging off: https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-grouppolicy
* gpresult: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/gpresult
* MDM Bridge WMI provider and the Policy CSP's `Config` and `Result` nodes: https://learn.microsoft.com/en-us/windows/client-management/using-powershell-scripting-with-the-wmi-bridge-provider, https://learn.microsoft.com/en-us/windows/win32/dmwmibridgeprov/mdm-policy-config01-defender02, https://learn.microsoft.com/en-us/windows/win32/dmwmibridgeprov/mdm-policy-result01-defender02, https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-configuration-service-provider
* Group Policy's registry processing (MS-GPREG 3.2.5.1.2, and the Windows Server 2003 description of the policy trees): https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpreg/57226664-ce00-4487-994e-a6b3820f3e49, https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc758189(v=ws.10)
* Group Policy Operational events 4016 and 5016: https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/applying-group-policy-troubleshooting-guidance
* Defender's order of precedence and where each tool writes: https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-settings
* Defender for Endpoint security settings management: https://learn.microsoft.com/en-us/intune/intune-service/protect/mde-security-integration, https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-security-config-mgt
* Configuration Manager baselines: https://learn.microsoft.com/en-us/intune/configmgr/compliance/deploy-use/deploy-configuration-baselines
* DSC's Local Configuration Manager: https://learn.microsoft.com/en-us/powershell/dsc/managing-nodes/metaconfig?view=dsc-1.1
* Azure machine configuration: https://learn.microsoft.com/en-us/azure/governance/machine-configuration/concepts/remediation-options, https://learn.microsoft.com/en-us/azure/azure-arc/servers/agent-overview
* Security Center on servers: https://learn.microsoft.com/en-us/troubleshoot/outlook/security/outlook-trust-center-shows-antivirus-status-as-unavailable
* Tamper Protection: https://learn.microsoft.com/en-us/defender-endpoint/tamper-protection-overview, https://learn.microsoft.com/en-us/defender-endpoint/tamper-protection-windows-configure

Windows behaviour:
* SMB signing: https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing
* SMBv1 and its audit: https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/smbv1-not-installed-by-default-in-windows, https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3
* SMB1's client no longer installed in Windows 11 Home (April 2022, shipped February 2023): https://techcommunity.microsoft.com/blog/filecab/smb1-now-disabled-by-default-for-windows-11-home-insider/3289473
* LSA protection: https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection
* Credential Guard: https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/
* Removed features (PowerShell 2.0): https://learn.microsoft.com/en-us/windows/whats-new/removed-features
* Deprecated features (NTLMv1): https://learn.microsoft.com/en-us/windows/whats-new/deprecated-features
* Enhanced NTLM auditing: https://support.microsoft.com/en-us/help/5064479
* Events 4624 and 4776: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624, https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4776
* TLS 1.0 and 1.1: https://learn.microsoft.com/en-us/windows/win32/secauthn/tls-10-11-deprecation-in-windows, https://learn.microsoft.com/en-us/windows/win32/secauthn/protocols-in-tls-ssl--schannel-ssp-, https://learn.microsoft.com/en-us/windows-server/get-started/removed-deprecated-features-windows-server
* Print Spooler on domain controllers: https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/identity-infrastructure
* Windows LAPS: https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview
* BitLocker: https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/
* Pending restarts: https://learn.microsoft.com/en-us/intune/configmgr/core/clients/manage/manage-clients
* Execution policies: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-5.1
* Language modes: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_language_modes?view=powershell-5.1
* App Control and scripts: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/script-enforcement
* Security policy refresh: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/security-policy-settings
* Defender beside other antivirus, and its running modes: https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-compatibility, https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-windows
* Minifilter altitudes: https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/load-order-groups-and-altitudes-for-minifilter-drivers
* SmartScreen: https://learn.microsoft.com/en-us/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen/available-settings, https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-smartscreen
* ASR rules, their requirements, their precedence, per-rule exclusions and when exclusions take effect: https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-overview, https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference, https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-configure
* Firewall cmdlets: https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule, https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile
* The firewall's log (its default file, its limit and what happens there): https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/configure-logging
* Windows Filtering Platform's state: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-wfp
* SQL Server's ports: https://learn.microsoft.com/en-us/sql/sql-server/install/configure-the-windows-firewall-to-allow-sql-server-access
* Veeam's ports: https://helpcenter.veeam.com/docs/vbr/userguide/used_ports.html?ver=13
* NLA: https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/remotepc/remote-desktop-allow-access, https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/error-password-change-expired-password, https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/windows/cannot-connect-rdp-azure-vm
* Win32_TSGeneralSetting: https://learn.microsoft.com/en-us/windows/win32/termserv/win32-tsgeneralsetting

Lifecycle:
* Windows 10: https://learn.microsoft.com/en-us/lifecycle/products/windows-10-enterprise-and-education
* Extended Security Updates: https://learn.microsoft.com/en-us/lifecycle/faq/extended-security-updates
* Windows 11: https://learn.microsoft.com/en-us/lifecycle/products/windows-11-enterprise-and-education, https://learn.microsoft.com/en-us/lifecycle/products/windows-11-home-and-pro
* Windows 11 26H1: https://support.microsoft.com/en-us/servicing/os/windows/2026/02/windows-11-version-26h1
* Windows Server: https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2016, https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2025

Frameworks:
* NIST SP 800-53 Rev. 5: https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
* Its catalogue (5.2.0): https://github.com/usnistgov/oscal-content/blob/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json
* 800-53 to ISO/IEC 27001:2022: https://csrc.nist.gov/projects/olir/informative-reference-catalog/details?referenceId=155, https://csrc.nist.gov/csrc/media/Projects/olir/documents/submissions/sp800-53r5-to-iso-27001-mapping-2022-OLIR-2023-10-12-UPDATED.xlsx
* NIST SP 800-171 Rev. 3: https://csrc.nist.gov/pubs/sp/800/171/r3/final, https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-171r3.pdf
* NIST SP 800-171 Rev. 2 and its Appendix D: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-171r2.pdf
* CMMC (32 CFR part 170): https://www.ecfr.gov/current/title-32/part-170
* DFARS class deviation 2024-O0013 (the Department's address could not be reached; quoted from the Internet Archive's copy): https://www.acq.osd.mil/dpap/policy/policyvault/USA000814-24-DPC.pdf, https://web.archive.org/web/20250106111059id_/https://www.acq.osd.mil/dpap/policy/policyvault/USA000814-24-DPC.pdf
* National Checklist Program: https://ncp.nist.gov/repository
* PCI DSS v4.0 (SAQ D): https://listings.pcisecuritystandards.org/documents/PCI-DSS-v4-0-SAQ-D-Merchant.pdf
* Australian Signals Directorate (could not be fetched): https://www.cyber.gov.au

Test infrastructure:
* GitHub-hosted runners: https://docs.github.com/en/actions/reference/runners/github-hosted-runners
* Runner images and what they change: https://github.com/actions/runner-images/tree/main/images/windows, https://github.com/actions/runner-images/blob/main/images/windows/scripts/build/Configure-WindowsDefender.ps1, https://github.com/actions/runner-images/blob/main/images/windows/scripts/build/Configure-BaseImage.ps1, https://github.com/actions/runner-images/blob/main/images/windows/scripts/build/Configure-System.ps1
* Caches and pull requests: https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching
* Nested virtualization: https://docs.github.com/en/actions/concepts/runners/github-hosted-runners
* KVM on Linux runners: https://github.blog/changelog/2024-04-02-github-actions-hardware-accelerated-android-virtualization-now-available/
* Evaluation media: https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise, https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2025, https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2016
* Windows 11 in a virtual machine: https://learn.microsoft.com/en-us/windows/whats-new/windows-11-requirements

EasyRMM:
* The agent's state-folder check, whose rule the Hardening folder's check follows (PR #61): https://github.com/paulmataruso/EasyRMM/pull/61
