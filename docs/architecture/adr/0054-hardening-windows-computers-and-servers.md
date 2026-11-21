# ADR-0054: Hardening Windows computers and servers

* Status: Proposed (2026-11-21). Not implemented.
* Builds on: [ADR-0051](0051-hardening-linux-computers.md) (the `hardening`
  job, its modes, results, permission and console),
  [ADR-0017](0017-scripts-and-jobs.md) (scripts and jobs),
  [ADR-0028](0028-software-deployment.md) (a fixed script compiled into the
  server, its input as arguments) and [ADR-0020](0020-windows-agent.md)
  (the Windows agent).
* Shares with log collection's ADR (ADR-0060, proposed): who sets Windows
  audit policy, and how both read what Group Policy owns.

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
  integrate" them (from $6,000 a year below $250,000 of revenue to $80,000
  above $500 million), and "CIS Benchmarks Certification must be awarded
  ... in advance of any sale, distribution, or marketing", every year, per
  tool and type of certification. CIS-CAT Pro may not be built into a
  product. CIS's marks in advertising are for members only.
* **Wazuh's security configuration assessment.** Wazuh 4.14.10 (released
  2026-11-09) checks Windows with eight policies (Windows 10 and 11
  Enterprise, Server 2012 to 2025), each "Based on" a CIS Benchmark older
  than CIS's current one (Windows 11 Enterprise 3.0.0, Server 2022 2.0.0,
  Server 2025 1.0.0). The policies are under the GPL version 2 (Wazuh's
  engine is AGPL-3.0), and reproduce CIS's recommendation numbers, titles,
  rationale and remediation text word for word. **What Wazuh calls
  frameworks are labels on those CIS checks**: in 4.14.10 the checks carry
  `cis`, `cis_csc_v7` and `cis_csc_v8` (the CIS Controls), `pci_dss_v4.0`
  and `v3.2.1`, `soc_2`, `iso_27001-2013`, `cmmc_v2.0`, `hipaa` and
  `nist_sp_800-53`. Wazuh's development branch moves to ISO 27001:2022
  numbering and adds NIS2, NIST SP 800-171, FedRAMP, GDPR and MITRE ATT&CK.
  The labels are coarse: on that branch the Windows 11 policy's 482 checks
  share 57 distinct sets, and "Enforce password history" is labelled
  AC-2, IA-2, IA-5, AC-11, AC-7 and AU-6. Wazuh's own documentation calls
  its mappings "indicative" and says they "do not by themselves certify
  compliance". EasyRMM can use none of this: the content is GPL and CIS's,
  and [ADR-0037](0037-one-licence.md) allows only permissive dependencies.
* **DISA STIGs.** Current releases: Windows 11 V2R11, Windows 10 V3R6,
  Server 2025 V1R4, Server 2022 V2R11, Server 2019 V3R9, Server 2016 V2R10,
  and the Microsoft Defender Antivirus (V2R8) and Windows Defender Firewall
  (V2R2) STIGs. They are free to download, written by DISA, a United
  States government agency, and "Copyright protection under this title is
  not available for any work of the United States Government" (17 U.S.C.
  105). Every rule has a stable ID (`WN25-SO-000310`) and names Control
  Correlation Identifiers (CCIs), which DISA's CCI list maps to NIST SP
  800-53 Rev. 5. Member server and domain controller rules are marked in
  the ID (`WN25-MS-…`, `WN25-DC-…`). They are strict and written for the
  US Department of Defense: three failed sign-ins lock an account,
  passwords expire, certificates must come from the department's own PKI.
* **Microsoft's security baselines**, in the Security Compliance Toolkit:
  Windows 11 26H2 (v2, October 2026), 25H2 and 24H2, Windows Server 2025
  (v2602, February 2026) and 2022, Windows 10 22H2, and older ones. Each is
  Group Policy backups, reports, a spreadsheet of settings and a script
  that applies them with LGPO.exe, for five profiles: domain-joined and
  standalone workstations, member servers, standalone servers and domain
  controllers. Microsoft says other organizations' recommendations
  "closely mirror Microsoft's recommendations" but are not the same, and,
  of its Intune baselines, that they are not CIS or NIST compliant,
  "strictly speaking". The packages carry no licence file; the toolkit's
  tools come with "standalone use terms", inside the LGPO download, which
  we have not read. On Windows Server 2025, OSConfig applies the same
  baseline and corrects drift every four hours.
* **Frameworks are not benchmarks.** NIST SP 800-53 Rev. 5 (release 5.2.0,
  August 2025), NIST SP 800-171 Rev. 3 (May 2024), ISO/IEC 27001:2022
  Annex A, the CIS Controls (v8.1) and the Essential Eight say what an
  organization must achieve, not which registry value to set. SP 800-53's
  CM-6 names STIGs among the "common secure configurations" an
  organization chooses; SP 800-171's 03.04.02 does the same. NIST's
  National Checklist Program tells federal civilian agencies to look for a
  checklist from a "Governmental Authority" first (DISA's STIGs are
  there), a "Software Vendor" next and a "Third Party" (CIS among them)
  last.

### What the computers are like
* **Windows' defaults moved a lot.** SMBv1 has not been installed by
  default since Windows 10 1709; Windows 11 24H2 Enterprise, Pro and
  Education require SMB signing both ways, Server 2025 outbound; NTLMv1 is
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
  CSP. Group Policy can also set PowerShell's execution policy, which then
  overrides `-ExecutionPolicy Bypass` "in all scopes", and App Control or
  AppLocker can put PowerShell in Constrained Language Mode. A change made
  underneath any of these is reverted, fights the owner, or does not run.
* **MSPs' customers depend on what benchmarks turn off**: multifunction
  printers scanning to SMB shares, NAS boxes opened as guest, line-of-
  business software that speaks NTLM or TLS 1.0, technicians typing an
  administrator's password into a user's UAC prompt during remote support,
  local administrator accounts used over the network. EasyRMM's own agent
  is unsigned unless the operator signs it
  ([ADR-0049](0049-operators-sign-windows-agents.md)), and Defender
  features that block files "that don't yet have a positive reputation"
  could block its updates.

## Decision

### Basis: Microsoft's values, DISA's rule IDs, no CIS
* **Values come from Microsoft's security baseline** for the Windows
  version and profile the computer has (workstation or server, joined to a
  domain or not, domain controller), except where this ADR loosens one for
  safety, which the module says. Microsoft is the vendor, publishes a
  baseline for each release (Server 2025's is from February 2026, Windows
  11 26H2's from October 2026), writes for ordinary organizations rather
  than one department, and covers the domain controller and standalone
  profiles an MSP meets. A setting's value is a fact, not text: nothing
  from the packages is copied.
* **Each setting is cited by the DISA STIG rule that covers it**, by ID and
  STIG release (`Windows Server 2025 STIG V1R4, WN25-SO-000310`), in the
  script's comments and in the console, for the Windows version the
  computer runs. Settings no STIG covers (LSA protection, LLMNR, NLA) name
  Microsoft's baseline instead. The IDs are public, stable and tied to
  NIST SP 800-53 through the CCIs, which gives the framework reporting
  below. EasyRMM uses the IDs and its own words, never the STIGs' text: no
  distribution statement could be found in the files (the Windows 11
  overview sends those without a common access card to
  `public.cyber.mil`).
* **No CIS numbers, titles or text, and no claim about CIS**, unless the
  owner buys the Product Vendor Membership and has the feature certified
  before it is sold, distributed or marketed (see Open questions). Nothing
  from Wazuh either.
* **No claim of compliance with anything.** The check reports what is in
  place on the computer. The console never says "compliant", "CIS Level
  1" or "STIG compliant", and EasyRMM's documentation says why.
* **Keeping current.** A test fails when a STIG ID the script cites is
  not in the STIG release it names; the IDs come from DISA's files, kept in
  the repository as test data (a list of IDs per release, a United States
  government work). New STIG releases and baselines are read when they
  come out, and the script's values and citations follow them.

### Frameworks: related controls, never compliance
For each module the console shows the controls its settings relate to,
built only from published mappings, at the level of a base control (AC-7,
not AC-7 a):

* **NIST SP 800-53 Rev. 5**: the controls the CCIs of the cited STIG rules
  name in DISA's CCI list (version 2025-01-23, whose references are to
  "NIST SP 800-53 Revision 5"), with their titles from NIST's own catalogue
  (release 5.2.0), a United States government work.
* **NIST SP 800-171 Rev. 3**: the requirements whose "Source Control" in
  NIST's publication is one of those controls (03.04.02 Configuration
  Settings lists CM-06, for example). SP 800-171 Rev. 3 is "derived from
  the controls in NIST Special Publication (SP) 800-53".
* **ISO/IEC 27001:2022 Annex A**: the Annex A controls NIST's crosswalk
  ("800-53-Rev5-to-ISO 27001-2022", version 1.0.0, posted 2023-11-13 in
  NIST's OLIR catalogue) gives for those controls, as numbers only: the
  crosswalk has no titles, and ISO's text is copyrighted and could not be
  read. NIST's own caveat goes with it: organizations "should not assume
  security requirement and control equivalency based solely on the
  mapping tables".
* **Not mapped**: the CIS Controls (CC BY-NC-ND 4.0 under the same
  non-member terms, which forbid claiming consistency with them); the
  Essential Eight (the Australian Signals Directorate's site could not be
  read while this was written: revisit, see Open questions); PCI DSS,
  HIPAA, SOC 2, GDPR, NIS2, CMMC and FedRAMP (no published mapping from
  settings that EasyRMM may use; PCI DSS's standard is behind a licence
  agreement). PCI DSS v4.0 requirement 2.2.1 asks for configuration
  standards "consistent with industry-accepted system hardening standards
  or vendor hardening recommendations"; an MSP can point its standard at
  Microsoft's baseline and the STIG IDs EasyRMM shows, but EasyRMM does not
  map requirements.
* **Wording.** The panel is headed *Related controls*, and says: "Which
  controls these settings relate to, from DISA's and NIST's published
  mappings. It is not an assessment and not a statement of compliance."
  The tables are generated from DISA's and NIST's files by a tool in the
  repository and checked in CI, not written by hand.

Generated from the STIG IDs in the module table below (Windows 11 and
Server 2025), as W3 will show them:

| Module | NIST SP 800-53 Rev. 5 | ISO/IEC 27001:2022 Annex A (NIST's crosswalk) |
|---|---|---|
| `accounts` | AC-7, CM-6, IA-5, IA-8 | A.5.16, A.5.17, A.8.5, A.8.9 |
| `firewall` | AC-4, AU-5, AU-12, CM-6, CM-7, SC-7 | A.5.14, A.8.9, A.8.15, A.8.16, A.8.19, A.8.20, A.8.22, A.8.23 |
| `defender` | CM-6, CM-7, SC-18, SI-3 | A.8.7, A.8.9, A.8.19 |
| `asr` | SC-18 | none |
| `smb` | CM-7, IA-5 | A.5.16, A.5.17, A.8.19 |
| `smb-signing` | CM-6, SC-8 | A.5.10, A.5.14, A.5.33, A.8.9, A.8.20, A.8.26 |
| `ntlm` | CM-6, IA-5 | A.5.16, A.5.17, A.8.9 |
| `wdigest`, `powershell`, `autoplay`, `printing`, `features` | CM-7 | A.8.19 |
| `name-resolution` | SC-5 | none |
| `rdp` | AC-17, IA-11, SC-11 | A.5.14, A.6.7 |
| `uac` | CM-11, IA-11, SC-3, SC-11 | A.8.19 |
| `anonymous` | AC-6, CM-6, SC-4 | A.5.15, A.8.2, A.8.9, A.8.18 |
| `winrm` | IA-11, MA-4, SC-11 | none |
| `audit` | AC-6, AU-3, AU-4, AU-12, CM-5 | A.5.15, A.5.28, A.8.2, A.8.4, A.8.6, A.8.9, A.8.15, A.8.18, A.8.19, A.8.31, A.8.32 |
| `device-guard` | CM-6 | A.8.9 |
| `bitlocker` | IA-8, SC-28 | A.5.10, A.5.16, A.5.33 |
| `laps` | IA-5 | A.5.16, A.5.17 |
| `lsa-protection`, `tls` | none (no STIG rule) | none |

The table shows how coarse these mappings are (the audit module reaches
A.8.32 through CM-5), which is why the console shows them as related, and
why EasyRMM does not add mappings of its own.

**Linux, as a follow-up.** ADR-0051's script already cites the Red Hat
Enterprise Linux 9 STIG by rule ID, so the same panel can be built for
Linux modules from those IDs' CCIs. That is a follow-up to ADR-0051 for
whoever amends it, not part of this ADR, which does not change ADR-0051;
the same amendment should drop ADR-0051's mention of naming CIS
recommendations, for the licence reasons above.

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
  modules from the PowerShell Gallery, no `Add-Type` (it compiles C# at run
  time and is refused in Constrained Language Mode). Language-neutral
  throughout: accounts and groups by SID (Administrators `S-1-5-32-544`,
  the Guest account by its RID, 501), audit subcategories by GUID, never by
  their translated names.
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
  and `restart` (a change waits for a restart). The format stays
  `EASYRMM-HARDENING-RESULT-V1`: the script and the server ship together.
* **Only tighter**, as on Linux: a value stricter than EasyRMM's is left
  (UAC that asks for credentials stays; a lockout threshold of 3 stays 3).

### Before anything changes
The script first checks, and stops with every module *not supported* and
the reason if:

* PowerShell runs in **Constrained Language Mode** (App Control for
  Business or AppLocker script rules), in any mode: the script cannot read
  or set what it needs, and must not try to get around the computer's own
  control.
* For apply and undo, the platform is check only or not supported (see
  Platforms).

If Group Policy sets PowerShell's execution policy to `AllSigned`, the
script does not start at all: Group Policy "overrides the execution
policies set in PowerShell in all scopes". The job fails with PowerShell's
message, which the server recognises and shows as *Group Policy allows only
signed scripts*. This is true of every PowerShell job EasyRMM runs today;
signing EasyRMM's scripts depends on code signing, which is on hold (see
Open questions).

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

**The owners, and how each is found:**

* **Group Policy, from the domain or the local Group Policy object.**
  Read from the computer's **resultant set of policy** in WMI
  (`root\rsop\computer`): registry-based policy (the
  `RSOP_RegistryPolicySetting` class: key, value name, value, and the
  winning policy, precedence 1) and the security settings Windows records
  when Group Policy applies security policy; `gpresult /scope computer /x`
  as a cross-check, and the source of the policy's name. **This is the same
  reading, under the same name, *policy ownership*, as log collection's
  "Group Policy wins" (ADR-0060)**, with the same labels: *set by Group
  Policy* with the policy's name. The code exists twice (in the agent's
  collector and in this script), so both are tested against the same
  domain machines and the same Group Policy objects (see Testing), and a
  change to one is made to the other. Whether Windows records the
  resultant set of policy on a computer in a workgroup, where only local
  Group Policy applies, is settled in W1; if it does not, the local Group
  Policy object's `Registry.pol` is read instead.
* **MDM** (Intune and others through the Policy CSP). Microsoft does not
  document where Windows keeps what an MDM set; the candidate is the
  PolicyManager store that Microsoft's MDM diagnostics tool dumps. W1
  settles it on a real Intune-enrolled Windows 11. **Until then, a
  computer enrolled in MDM gets check only.** Group Policy wins over MDM
  unless the MDM set `MDMWinsOverGP`, and the script reads that too.
* **OSConfig** (Windows Server 2025): a security baseline applied through
  OSConfig is corrected every four hours by default. Its settings are
  *set by OSConfig*.
* **Microsoft Defender's own guards**: Tamper Protection blocks changes to
  real-time protection, behaviour monitoring, cloud protection and more
  ("changes made through a management tool, including Group Policy, might
  appear to succeed, but tamper protection blocks the changes"), and
  settings made with `Set-MpPreference` "have the lowest precedence. Any
  policy-based method overwrites them". Settings Tamper Protection locks
  are *protected by Tamper Protection* when they differ; Defender settings
  from any policy are *set by Group Policy* or *set by MDM*. EasyRMM never
  turns Tamper Protection off.
* **Another antivirus or firewall.** Where Microsoft Defender Antivirus is
  passive or off because another product is the antivirus, `defender` and
  `asr` are *not applicable*, naming the product where Windows reports it.
  A firewall product registered with Windows Security Center makes
  `firewall` *managed elsewhere*.
* **Remote Desktop's own record**: the Terminal Services WMI provider
  reports, for NLA, the security layer and the encryption level, whether
  Group Policy sets each.
* **EasyRMM's log collection** for audit policy: see Audit policy below.

Unlike log collection, which also leaves alone a value "something else
already set differently (a script, an image)", hardening's apply changes
such a value: that is what the operator asked for, and the value before is
recorded for undo. Only values an owner keeps setting are left.

### How settings are written
* **Registry values** (administrative template policies and Windows' own
  settings) with PowerShell's registry provider, under `HKLM`, at the
  path Group Policy would write, after recording the value before (absent,
  or its type and data). They do not appear in the Local Group Policy
  Editor as configured, since they are not in the local Group Policy
  object; the console says EasyRMM set them.
* **Security policy** (password and lockout policy, the Guest account,
  anonymous SID and name translation): read with `secedit /export`,
  written with `secedit /configure` and a template holding only the
  module's settings, read back after. Tests prove the values survive Group
  Policy's 16-hourly re-application on a domain member where no policy
  sets them.
* **Microsoft Defender**: `Set-MpPreference` for single settings;
  attack surface reduction rules one at a time with `Add-MpPreference` and
  `Remove-MpPreference`, since `Set-MpPreference` replaces the whole list.
* **Windows Defender Firewall**: the NetSecurity cmdlets; EasyRMM's rules
  in a rule group of their own.
* **Windows features**: `Disable-WindowsOptionalFeature` on Windows 10
  and 11 and `Uninstall-WindowsFeature` on servers, never with `-Remove`,
  so the payload stays and undo can add a feature back without
  installation media.
* **Services**: start type and state, recorded first.
* **Remote Desktop**: the Terminal Services WMI provider
  (`Win32_TSGeneralSetting`).
* **Not used**: LGPO.exe (its terms have not been read, and it would be a
  second program to ship), Microsoft's `Baseline-LocalInstall.ps1` (it
  applies a whole baseline, including the settings this ADR leaves out),
  PowerShell DSC, and the OSConfig module from the PowerShell Gallery.

### The modules
*Recommended* ones are preselected; the others must be chosen one by one,
with what they can break stated beside them. The STIG IDs are those of
Windows 11 V2R11 and Server 2025 V1R4, and of the Defender Antivirus
(`WNDF-AV`) and Firewall (`WNFWA`) STIGs; the script cites each Windows
version's own.

| Module | What it does | Recommended |
|---|---|---|
| `accounts` | See **Accounts** below | Yes |
| `firewall` | See **Firewall** below | Yes |
| `defender` | See **Microsoft Defender** below | Yes |
| `asr` | See **Attack surface reduction** below | Yes |
| `smb` | SMBv1 off: the server's SMB1 protocol, the client's SMB1 driver, and the optional feature removed where installed (a restart); passwords never sent unencrypted to third-party SMB servers. Refused while a client is connected to this computer over SMB1. Breaks: scanners, NAS boxes and old systems that speak only SMB1. STIG WN11-00-000160, -000165, -000170, WN11-SO-000110; WN25-00-000380, -000390, -000400, WN25-SO-000180 | Yes |
| `smb-signing` | SMB signing required by the client and the server; guest access to SMB shares off. Already the default on Windows 11 24H2 Enterprise, Pro and Education, and outbound on Server 2025. Breaks: multifunction printers that scan to a share and NAS boxes that cannot sign, shares opened as guest (common in small offices); large copies are slower. STIG WN11-SO-000100, -000120, WN11-CC-000040; WN25-SO-000160, -000170, -000190, -000200, WN25-CC-000070 | No |
| `ntlm` | See **NTLM** below | Yes, except on domain controllers |
| `wdigest` | WDigest does not keep passwords in memory (`UseLogonCredential` 0, which is also Windows' behaviour when the value is absent). Breaks nothing current. STIG WN11-CC-000038 | Yes |
| `lsa-protection` | See **LSA protection** below | Yes on Windows 11 22H2 and later; no elsewhere |
| `name-resolution` | LLMNR off; NetBIOS ignores name release requests except from WINS servers. NetBIOS over TCP/IP stays on and its node type is left (Microsoft's baseline sets P-node, which stops NetBIOS names resolving by broadcast where there is no WINS server). Breaks: on networks without DNS for local devices, names only LLMNR found (`\\NAS`). STIG WN11-CC-000035, WN25-CC-000060; LLMNR from the baseline | Yes on computers in a domain; no in workgroups |
| `powershell` | Windows PowerShell 2.0 removed where it is still installed (Windows 10, Server 2016 to 2022, Windows 11 before August 2025's update). Script block logging is reported, and set by log collection (see Audit policy). Not transcription, which writes every script's text, secrets included, to files. Breaks: tools that start `powershell -Version 2`. STIG WN11-00-000155, WN25-00-000410 | Yes |
| `rdp` | See **Remote Desktop** below | Yes, once W2 proves EasyRMM's RDP sessions work with NLA |
| `uac` | See **User Account Control** below | Yes, once W2 proves remote support still answers the prompt |
| `autoplay` | AutoPlay off for all drives and for devices that are not volumes, no AutoRun commands. Breaks: CDs and USB drives no longer start anything by themselves. STIG WN11-CC-000180, -000185, -000190; WN25-CC-000210, -000220, -000230 | Yes |
| `anonymous` | No anonymous enumeration of accounts or shares, no anonymous SID and name translation, anonymous users not in Everyone, anonymous access to named pipes and shares restricted, remote calls to the account database only for administrators (as the STIGs ask). Mostly Windows' defaults. Breaks: very old systems and devices that list shares without signing in. STIG WN11-SO-000140, -000145, -000150, -000160, -000165, -000167; WN25-SO-000210, -000220, -000230, -000240, -000250, WN25-MS-000060 | Yes |
| `winrm` | WinRM's client and service: no Basic authentication, no unencrypted traffic, no Digest (client), no stored RunAs credentials (service). These are Windows' defaults; where Basic or unencrypted traffic is on (someone turned it on, often for Ansible or a monitoring tool) it is left and reported, unless the option `winrm-basic-off` is given. WinRM is never stopped and its listeners never removed. STIG WN11-CC-000330, -000335, -000345, -000350, -000355, -000360; WN25-CC-000470, -000480, -000490, -000500, -000510, -000520 | Yes |
| `printing` | Only administrators install print drivers (the baseline's setting), drivers are never downloaded over HTTP, no printing over HTTP; on domain controllers the Print Spooler stopped and disabled (Microsoft: "domain controllers and Active Directory admin systems need to have the Print spooler service disabled"). On other servers, only with the option `spooler-off`, and refused where the server shares a printer, has the Print Server role or is a Remote Desktop session host. Never on workstations. Breaks: users adding a printer whose driver is not installed yet. STIG WN11-CC-000100, -000110; WN25-CC-000150, -000160 | Yes |
| `features` | Removes, where installed, the Telnet and TFTP clients, Simple TCP/IP Services and the Peer Name Resolution Protocol (payload kept). An FTP server or Fax server is reported, never removed: it may be there on purpose (the STIG allows FTP where "required by the organization"). Breaks: someone using the Telnet client to test ports. STIG WN11-00-000110, -000115, -000120; WN25-00-000320 to -000370 | Yes |
| `tls` | Schannel: SSL 2.0 and 3.0 and TLS 1.0 and 1.1 off for clients and servers (a restart). Microsoft's own pages disagree on whether TLS 1.0 and 1.1 are already off on Server 2025 and Windows 11 24H2; the check reads what is in effect. Breaks: older SQL Server clients and drivers, older .NET programs, devices and line-of-business software that speak only TLS 1.0 | No |
| `audit` | Report only: see **Audit policy** below | (report) |
| `device-guard` | Report only: whether virtualization-based security, memory integrity (HVCI) and Credential Guard are running. Turning them on needs hardware and firmware support and a restart, cannot be undone remotely when locked in UEFI, and Credential Guard is not recommended on domain controllers. STIG WN11-CC-000070, -000075, -000080; WN25-CC-000110, WN25-MS-000140 | (report) |
| `bitlocker` | Report only: whether the system volume is protected, how, and whether a recovery password exists. Turning BitLocker on before its recovery key is kept somewhere can lose data; escrowing keys is a feature of its own. STIG WN11-00-000030, -000031, -000032; WN25-00-000250 | (report) |
| `laps` | Report only: whether Windows LAPS manages the local administrator's password. Setting it up needs a directory (Active Directory or Entra ID) and a policy. Windows LAPS came with April 2023's updates to Windows 10 and 11 and Server 2019 and 2022, and is in Server 2025; Microsoft does not list Server 2016. STIG WN11-SO-000280, WN25-00-000020 (the local administrator's password age) | (report) |

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
* **The Guest account disabled**, blank passwords usable only at the
  console.
* **Never touched**: any other account. The module never disables,
  renames, deletes or changes the password of an account, and never adds
  or removes a user right.
* **On domain controllers** the domain's policy applies: the module is
  *managed elsewhere*. On domain members it governs local accounts only.
* Breaks: creating a local account with a short password; ten wrong
  passwords lock a local account, the MSP's included, for 15 minutes.
* STIG WN11-AC-000005, -000010, -000015, -000020, -000035, -000040,
  -000045, WN11-SO-000010, -000015; WN25-AC-000010, -000020, -000030,
  -000040, -000080, -000090, WN25-SO-000010, -000020.

### Firewall
* **Windows Defender Firewall on** for the domain, private and public
  profiles, with inbound connections blocked unless a rule allows them, and
  dropped packets logged (the Firewall STIG's log settings). EasyRMM never
  blocks outbound traffic: the EasyRMM agent, MeshAgent and the EasyPatch
  agent only connect out.
* **Before a profile is turned on or set to block**, EasyRMM's rule group
  gets allow rules, for every profile, for every TCP and UDP port something
  listens on outside loopback when the job runs (with the program, where
  Windows reports it), Remote Desktop's port where Remote Desktop is
  enabled, WinRM's listener ports where WinRM listens, and ports and
  ranges the operator adds (`allow-tcp`, `allow-udp`). The check lists them
  before apply, and lists services that start automatically but are not
  running, whose ports cannot be known (as on Linux, *ports unknown*).
* **Existing rules are never changed**, enabled or disabled, and local
  rules are never stopped from merging with policy rules (the STIG asks it
  for the public profile; without policy rules, local rules are the only
  rules).
* **Managed elsewhere**: a firewall policy from Group Policy or MDM; a
  firewall product registered with Windows Security Center.
* On most computers the firewall is already on and blocking; the module
  matters where someone turned it off, typically on servers.
* STIG WN11-00-000135, WN25-00-000280; WNFWA-000001 to -000004, -000012,
  -000020, and the logging rules WNFWA-000009, -000010, -000017, -000018,
  -000027, -000028.

### Microsoft Defender
* **Only where Microsoft Defender Antivirus is the active antivirus**;
  passive or off, the module is *not applicable*.
* Real-time protection and behaviour monitoring on, cloud-delivered
  protection on, potentially unwanted applications blocked, SmartScreen
  for Explorer on, and network protection in block mode on Windows 10 and
  11.
* **The cloud protection level stays at Windows' default.** The STIG asks
  for High, which blocks unknown files more readily, and an unsigned
  EasyRMM agent update is an unknown file. It is offered as the option
  `cloud-block-high`, with that stated.
* No exclusions are added or removed.
* Breaks: installers bundling unwanted software; websites with a bad
  reputation.
* STIG WN11-00-000045, WN11-CC-000210; WN25-00-000110, WN25-CC-000300;
  WNDF-AV-000001, -000010, -000021, -000022, -000039.

### Attack surface reduction
* **Requires** Microsoft Defender Antivirus active, with real-time
  protection on. For Server 2016, Microsoft's support table requires
  onboarding with Defender for Endpoint's "modern unified solution"; there
  the module is *not supported* until a test shows the rules taking effect
  without it.
* **Blocked**: Microsoft's three "standard protection" rules, which
  "Microsoft recommends enabling ... in Block mode without the need for
  extensive testing": abuse of exploited vulnerable signed drivers,
  credential stealing from LSASS, and persistence through WMI event
  subscription. The last stays in audit where the Configuration Manager
  client is installed, as Microsoft advises ("The Configuration Manager
  client relies heavily on WMI").
* **Audit**: every other rule Microsoft's baseline for this version blocks.
  The operator can block them one by one with the option `asr-block`,
  after reading their audit events, except:
  * *Block process creations originating from PSExec and WMI commands*
    (MSP tools and Configuration Manager use both), never blocked;
  * the two rules that judge files by reputation (*Block executable files
    from running unless they meet a prevalence, age, or trusted list
    criterion* and *Use advanced protection against ransomware*, which
    "blocks files *that don't yet have a positive reputation*"), refused
    while any of EasyRMM's agents on the computer (the EasyRMM agent,
    MeshAgent, the EasyPatch agent) lacks an Authenticode signature
    Windows trusts.
* *Block Webshell creation for Servers* is for Exchange servers and is
  never set. Rules are set one at a time, never replacing the list.
* STIG WNDF-AV-000032 to -000038 and -000043 to -000051.

### NTLM
* LAN Manager authentication level 5 (send NTLMv2 only, refuse LM and
  NTLM), no LAN Manager hash stored, NTLMv2 session security with 128-bit
  encryption required for NTLM clients and servers, no fallback to a null
  session; on servers, incoming NTLM audited where Microsoft's server
  baseline audits it (audit only, never blocked).
* **On domain controllers** (which need the option `domain-controller`
  anyway, see Who), refused while the Security log shows a sign-in with
  NTLM V1 or LM (event 4624, "Package Name (NTLM only)") in the last 30
  days: the domain controller would refuse those devices.
* Breaks: devices and software that speak only LM or NTLMv1 (old NAS
  boxes, copiers, line-of-business programs). Windows 11 24H2 and Server
  2025 have removed NTLMv1 already.
* STIG WN11-SO-000180, -000195, -000205, -000215, -000220; WN25-SO-000270,
  -000310, -000330, -000340.

### LSA protection
* **LSASS runs as a protected process.** Where Windows honours the value
  `RunAsPPL` 2 ("without a UEFI variable ... only enforced on Windows 11
  build 22H2 and later"), the module writes 2, which undo can remove
  remotely. Elsewhere the value is 1, which on a computer with Secure Boot
  is kept in a UEFI variable that only Microsoft's opt-out tool, an EFI
  program booted on the computer, removes: offered only with the option
  `lsa-uefi-lock`, stated as "undo needs someone at the computer". Server 2025 joins the first
  group when a test shows value 2 taking effect there.
* **Refused** when Windows' CodeIntegrity log shows, in the last 30 days,
  that an LSA plug-in or driver would not load (events 3065 and 3066, which
  Windows 11 22H2 and later log by default in audit mode): smart card
  drivers, password filters and other unsigned plug-ins stop working.
  Refused too where those events cannot be logged (Smart App Control on,
  or audit mode off), unless the option `lsa-unaudited` is given.
* **Takes effect at the next restart.** The check reports *waiting for a
  restart* until Windows logs that LSASS started as a protected process
  (WinInit event 12).
* No STIG rule; Microsoft's baselines set it.

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
* STIG WN11-CC-000270, -000285, -000290; WN25-CC-000340, -000370, -000380.
  NLA has no STIG rule.

### User Account Control
* UAC on (if it was off: a restart), administrators asked for consent on
  the secure desktop (stricter settings left), Admin Approval Mode for the
  built-in Administrator, installer detection, elevation only for UIAccess
  programs in secure locations, write failures virtualized, and Windows
  Installer never "always install with elevated privileges".
* **Not set**: automatically denying elevation to standard users (the
  STIGs ask for it). It stops a technician typing an administrator's
  password into a user's prompt during remote support; offered as the
  option `deny-user-elevation`.
* `LocalAccountTokenFilterPolicy` set to 1 (local administrators keep their
  full rights over the network, which some MSP tools need) is reported,
  never changed.
* The agent and its jobs run as LocalSystem and are not affected.
* Breaks: the built-in Administrator now gets prompts. Whether
  MeshCentral's remote desktop can answer a prompt on the secure desktop
  is tested in W2 before the module is recommended.
* STIG WN11-SO-000245, -000250, -000260, -000265, -000270, -000275,
  WN11-CC-000315; WN25-SO-000380, -000400, -000420, -000430, -000440,
  -000450, WN25-CC-000430.

### Audit policy
**Log collection owns Windows audit policy.** Its *Configure logging*
(ADR-0060, proposed) sets the advanced audit subcategories, command lines
in process creation events, PowerShell script block logging and the
minimum sizes of the logs, from the agent, on by default, leaving what
Group Policy sets. Hardening does not set any of these, so the two never
fight over a value or over whose undo puts it back:

* The `audit` module is **report only**. Its check compares the effective
  audit policy (subcategories by GUID, whether subcategories override
  categories), the command line setting and the log sizes with Microsoft's
  baseline and the STIGs' minimums, and names *Configure logging* as the
  way to set them (or Group Policy, where Group Policy owns them).
* The `powershell` module reports script block logging the same way.
* Until log collection ships, these stay reported, not set.
* STIG WN11-SO-000030, WN11-CC-000066, WN11-CC-000326, WN11-AU-000005 to
  -000589, WN11-AU-000500, -000505, -000510; WN25-SO-000050,
  WN25-CC-000090, -000460, -000270, -000280, -000290, and WN25-AU's
  subcategory rules.

### Backups, undo and interruptions
As in ADR-0051, with Windows' places and tools:

* **Where.** `%ProgramData%\EasyRMM\Hardening\`, apart from the agent's
  state (`%ProgramData%\EasyRMM\Agent`), which uninstalling the agent
  removes. It is created as the agent creates its own folder (a plain
  folder, not a link, with access for LocalSystem and Administrators only).
  Removing a device ([ADR-0050](0050-removing-a-device.md)) leaves the
  hardening in place, and the guide says so.
* **What is recorded**, per module, in a manifest with a format version:
  each registry value before (absent, or its type and data) and after;
  each security policy value before; Defender's settings and each attack
  surface reduction rule's action before; each firewall profile's state
  before and the names of EasyRMM's rules; each feature's and service's
  state before.
* **Undo** puts each one back if it is still as apply left it; anything
  changed since (by an administrator, a policy, Windows) is left and the
  result says so. Features come back from their kept payload; EasyRMM's
  firewall rules are removed. A successful undo consumes the record; the
  next apply takes a fresh one. Applying twice changes nothing the second
  time.
* **Interruptions.** Each module writes its intent before changing
  anything and marks it done after; a later check reports a module left
  half-applied, and undo reverses what was recorded.
* **Without the agent.** Apply and undo copy the script to
  `%ProgramData%\EasyRMM\Hardening\easyrmm-hardening.ps1`, so that undo can
  be run on the computer (`powershell -ExecutionPolicy Bypass -File
  "%ProgramData%\EasyRMM\Hardening\easyrmm-hardening.ps1" undo all`, as an
  administrator) from MeshCentral's terminal, a console, or after the
  agent is gone.

### Lock-out guards
* **Remote Desktop and WinRM stay reachable.** The firewall allows their
  ports, and every listening port, before it blocks anything; NLA waits for
  the RDP test; WinRM is never stopped and its listeners never removed.
* **The agents are never cut off.** The EasyRMM agent, MeshAgent and the
  EasyPatch agent connect out, and EasyRMM never blocks outbound traffic;
  their services are never stopped or changed; Defender's High cloud
  protection level is only set when the operator chooses it, and the
  reputation-based attack surface reduction rules are never blocked while
  an agent is unsigned.
* **The MSP's accounts are never disabled**, renamed or denied a sign-in
  right; lockout (10 attempts, 15 minutes) is the one way an account can
  be blocked, and it ends by itself.
* **Restarts are reported, never performed.** Modules whose change waits
  for one (`lsa-protection`, `tls`, `smb` where it removes the feature,
  `uac` where UAC was off) report *waiting for a restart*, and the device
  shows *restart needed* until a check sees the change in effect. The
  operator restarts when it suits.
* **Each module checks itself**: after writing, it reads every value back;
  if one is not as intended, the module is put back and reported failed,
  and the others go on.
* **Domain controllers** need an explicit choice (see Who).
* If access is lost anyway, MeshCentral's terminal (connecting out) still
  reaches the computer, and **Undo** works through the agent or on the
  computer itself.

### Platforms
* **Apply and undo** on the versions this script has been tested on,
  listed in the guide by build: Windows 11 Pro, Enterprise and Education
  in a version Microsoft still services for that edition (24H2 Enterprise
  until 2027-10-13, 25H2, 26H2), on x64 and ARM64; Windows Server 2025,
  2022 and 2019, Desktop Experience and Server Core; Windows Server 2016
  until its extended support ends (13 January 2027 on its lifecycle page;
  Microsoft's FAQ gives a different date in one place). A newer build is
  *not supported on this version* until tested, as on Linux.
* **Check only**: Windows 10 22H2 (support ended 14 October 2025; paid
  Extended Security Updates run to October 2028, see Open questions),
  Windows 11 versions out of service for their edition (23H2 Enterprise
  since 2026-11-11, 24H2 Home and Pro since 2026-10-14), Home editions
  (outside the baselines and STIGs), computers enrolled in MDM until W1
  settles MDM detection, Azure Virtual Desktop's multi-session Windows
  until tested, and Server 2016 after 13 January 2027.
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

### The rest
* **Audit**: `device.hardening`, with the mode, modules, options and job.
* **API**: `POST /api/v1/jobs/hardening` and `GET
  /api/v1/devices/{id}/hardening`, as in ADR-0051; `canHarden` and
  `canCheckHardening` cover Windows devices.
* **Options** the server accepts for Windows: `allow-tcp` and `allow-udp`
  (ports and ranges), `domain-controller`, `cloud-block-high`, `asr-block`
  (rule GUIDs from a fixed list), `lsa-uefi-lock`, `lsa-unaudited`,
  `deny-user-elevation`, `winrm-basic-off`, `spooler-off`.

## Testing
* **Static checks**: PSScriptAnalyzer on the script, and Windows
  PowerShell 5.1 parsing it, in CI; the STIG ID test above; a test that
  fails when a module, mode and Windows role has no case; the size limits.
* **CI's Windows runners**, the main test, from the first module on. For
  this public repository GitHub provides `windows-2025` and `windows-2022`
  (x64) and `windows-11-arm` (Windows 11 Enterprise on ARM64), each with 4
  CPUs and 16 GB. The script runs as LocalSystem, as the agent's service
  would run it, through a scheduled task. For each module: check, apply,
  check, apply again (no change), undo, check, with every recorded value as
  before. The existing *Agent tests on Windows* job keeps its tests; the
  hardening tests are `OnWindows` Go tests like the software scripts', in
  a matrix over the three images. What runners cannot show: restarts,
  domains and Group Policy from a domain, traffic from outside, MDM.
* **Windows machines under KVM**, extending `internal/vmtest` (the
  harness built for ADR-0051's tests on CI's Linux runners, on the Linux
  hardening branch) to Windows guests, for what runners cannot show:
  * Microsoft's evaluation media (Windows Server 2016 to 2025, 180 days;
    Windows 11 Enterprise, 90 days, ISO only), installed unattended once
    into a cached disk image; devices Windows has drivers for out of the
    box (an AHCI disk, an e1000e network card, a 16550 serial port), so no
    virtio drivers; Windows 11 with OVMF's Secure Boot and a software TPM
    (`swtpm`), as it requires.
  * Driven over the serial port through a small runner service built from
    this repository and baked into the image (Windows has no serial shell
    of its own), so that a firewall cannot cut the harness off.
  * Scenarios: restarts (values persist, LSA protection active after one,
    features removed); a domain of a Server 2025 domain controller, a
    member server and a Windows 11 member on QEMU's socket networking, with
    Group Policy objects setting some of the same values (policy
    ownership, shared with log collection's tests; Group Policy's refresh
    does not fight apply; the domain controller option; the NTLMv1 guard);
    a port forwarded from outside reaching a listening service before and
    after `firewall`; a German-language image (SIDs and GUIDs, not names);
    Server Core; Server 2016 and 2019, which have no runner.
  * Whether this works is decided in W1, and the ADR is amended if not:
    GitHub says nested virtualization is "not officially supported" (KVM on
    its Linux runners is documented, and H1 relies on it); Windows guests
    on 4 CPUs are slow; whether the evaluation media can be downloaded
    without a form, and whether their terms allow automated testing, has
    not been checked; Windows 11's evaluation asks for a Microsoft account;
    virtualization-based security inside a nested guest probably cannot
    run. The fallback is a
    self-hosted runner the owner provides, or the same scenarios run by
    hand on the owner's machines and recorded.
* **Before it is called complete** it is run on real computers: a real
  domain with a domain controller and member servers, a Windows 11 enrolled
  in Intune, and computers with a third-party antivirus.

## Slices
* **W1, check.** The script's skeleton (platform, role, language mode,
  policy ownership, MDM, OSConfig, Tamper Protection and antivirus
  detection, the manifest, the JSON result) and `check` for every module;
  on the server, the Windows platform, module names, options and result
  fields, and the related-controls tables with the tool that generates
  them; the static checks and the runner matrix in check mode; the KVM
  decision, proved with one Server image and the domain scenario, or
  recorded with why not.
* **W2, apply and undo**, module by module, each with its runner tests
  and, where it needs a restart, a domain or outside traffic, its machine
  test (or recorded hand test) before the next: report-only and low-risk
  modules first (`autoplay`, `wdigest`, `anonymous`, `winrm`, `features`,
  `powershell`, `accounts`, `printing`), then `defender`, `asr`,
  `name-resolution`, `smb`, `ntlm`, `uac`, `firewall`, `rdp`,
  `smb-signing`, `lsa-protection`, `tls`. The undo copy of the script.
* **W3, the console.** Linux hardening's H3 (a device's **Hardening** tab,
  the fleet column and filter, apply and undo from **Jobs**) with Windows'
  modules: their risks and options, the owner of each setting managed
  elsewhere, *restart needed*, and the *Related controls* panel; mixed
  selections sent as one job per platform.

## Consequences
* An operator can check a fleet of Windows computers in one job, see per
  module what is in place, who else owns what, and which controls it
  relates to, apply what is missing, and undo it module by module.
* Choosing safety over strictness leaves Windows looser than the STIGs:
  lockout after 10 attempts, no password expiry, the default cloud
  protection level, most attack surface reduction rules in audit,
  standard users still offered elevation, SMB signing and TLS 1.0 removal
  left to the operator, no deny-sign-in rights, the spooler off only on
  domain controllers. The check is not an audit against a benchmark.
* Computers whose settings come from Group Policy, Intune or OSConfig are
  mostly reported, not changed: an MSP that manages a domain by Group
  Policy keeps doing so, and EasyRMM shows where its policy differs.
* EasyRMM says nothing about CIS. MSPs who are asked for "CIS Level 1" get
  Microsoft's values with DISA's rule IDs, unless the owner decides to buy
  CIS's membership and certification.
* Script block logging and process command lines (set by log collection)
  record secrets that scripts and command lines contain, in logs that
  administrators can read; log collection redacts what it collects, not
  what stays on the computer.
* Where Group Policy allows only signed scripts or App Control constrains
  PowerShell, nothing runs, as for every PowerShell job today.
* The script follows Windows releases, Microsoft's baselines and DISA's
  STIG releases; each new build is tested before apply is allowed on it.

## Open questions for the owner
* **CIS.** Buy the CIS SecureSuite Product Vendor Membership (from $6,000
  a year at the lowest revenue band) and have the feature certified every
  year before it is sold, distributed or marketed, so that EasyRMM can name
  CIS recommendations? This ADR assumes no.
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
* **The Essential Eight**: should EasyRMM relate modules to it for
  Australian customers? Its pages could not be read while this was
  written.
* **Order**: this plan puts the work after the updater's edge channel;
  sooner, straight after Linux hardening?

## References
CIS:
* Terms of use for non-member CIS products: https://www.cisecurity.org/terms-of-use-for-non-member-cis-products
* Product Vendor Membership: https://www.cisecurity.org/cis-securesuite/pricing-and-categories/product-vendor/
* Remediation certification: https://www.cisecurity.org/cis-securesuite/pricing-and-categories/product-vendor/cis-benchmarks-remediation-certification/
* Logos and trademark use: https://www.cisecurity.org/cis-logos-and-trademark-use-policy
* Benchmarks FAQ: https://www.cisecurity.org/cis-benchmarks/cis-benchmarks-faq
* Windows benchmarks: https://www.cisecurity.org/benchmark/microsoft_windows_desktop, https://www.cisecurity.org/benchmark/microsoft_windows_server
* CIS Controls v8.1: https://www.cisecurity.org/insights/white-papers/cis-critical-security-controls-v8-1

Wazuh:
* Windows policies: https://github.com/wazuh/wazuh/tree/main/ruleset/sca/windows
* Licence: https://github.com/wazuh/wazuh/blob/main/LICENSE
* 4.14.10: https://github.com/wazuh/wazuh/releases/tag/v4.14.10
* Compliance: https://documentation.wazuh.com/current/compliance/index.html
* Available policies: https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/available-sca-policies.html

DISA and copyright:
* STIGs (each zip holds the overview and XCCDF): https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_11_V2R11_STIG.zip, https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_10_V3R6_STIG.zip, https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_Server_2025_V1R4_STIG.zip, https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_Server_2022_V2R11_STIG.zip, https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_Server_2019_V3R9_STIG.zip, https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_Server_2016_V2R10_STIG.zip, https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Defender_Antivirus_V2R8_STIG.zip, https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_Defender_Firewall_V2R2_STIG.zip
* CCI list: https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CCI_List.zip
* 17 U.S.C. 105: https://www.copyright.gov/title17/92chap1.html

Microsoft baselines and tools:
* Security Compliance Toolkit: https://www.microsoft.com/en-us/download/details.aspx?id=55319
* The toolkit: https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10
* Baseline versions: https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/get-support-for-security-baselines
* Windows 11 26H2 baseline: https://techcommunity.microsoft.com/blog/microsoft-security-baselines/windows-11-version-26h2-security-baseline/4560382
* Server 2025 v2602: https://techcommunity.microsoft.com/blog/microsoft-security-baselines/security-baseline-for-windows-server-2025-version-2602/4496468
* Tool use terms: https://techcommunity.microsoft.com/t5/microsoft-security-baselines/new-amp-updated-security-tools/ba-p/1631613
* Baselines, CIS and NIST: https://learn.microsoft.com/en-us/intune/device-security/security-baselines/overview
* OSConfig: https://learn.microsoft.com/en-us/windows-server/security/osconfig/osconfig-how-to-configure-security-baselines, https://learn.microsoft.com/en-us/windows-server/security/osconfig/osconfig-overview, https://techcommunity.microsoft.com/blog/itopstalkblog/using-osconfig-to-manage-windows-server-2025-security-baselines/4415824

Windows behaviour:
* SMB signing: https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing
* SMBv1: https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/smbv1-not-installed-by-default-in-windows
* LSA protection: https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection
* Credential Guard: https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/
* Removed features (PowerShell 2.0): https://learn.microsoft.com/en-us/windows/whats-new/removed-features
* Deprecated features (NTLMv1): https://learn.microsoft.com/en-us/windows/whats-new/deprecated-features
* TLS 1.0 and 1.1: https://learn.microsoft.com/en-us/windows/win32/secauthn/tls-10-11-deprecation-in-windows, https://learn.microsoft.com/en-us/windows/win32/secauthn/protocols-in-tls-ssl--schannel-ssp-, https://learn.microsoft.com/en-us/windows-server/get-started/removed-deprecated-features-windows-server
* Print Spooler on domain controllers: https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/identity-infrastructure
* Windows LAPS: https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview
* BitLocker: https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/
* Event 4624: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624
* Execution policies: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-5.1
* Language modes: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_language_modes?view=powershell-5.1
* App Control and scripts: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/script-enforcement
* Security policy refresh: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/security-policy-settings
* RSoP registry settings: https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/rsop-registrypolicysetting
* RSoP security settings: https://learn.microsoft.com/en-us/previous-versions/aa375070(v=vs.85)
* gpresult: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/gpresult
* ASR rules: https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-overview, https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference, https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-configure
* Tamper Protection: https://learn.microsoft.com/en-us/defender-endpoint/tamper-protection-overview, https://learn.microsoft.com/en-us/defender-endpoint/tamper-protection-windows-configure
* NLA: https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/remotepc/remote-desktop-allow-access
* Win32_TSGeneralSetting: https://learn.microsoft.com/en-us/windows/win32/termserv/win32-tsgeneralsetting
* MDM diagnostics: https://learn.microsoft.com/en-us/windows/client-management/mdm-collect-logs

Lifecycle:
* Windows 10: https://learn.microsoft.com/en-us/lifecycle/products/windows-10-enterprise-and-education
* Extended Security Updates: https://learn.microsoft.com/en-us/lifecycle/faq/extended-security-updates
* Windows 11: https://learn.microsoft.com/en-us/lifecycle/products/windows-11-enterprise-and-education, https://learn.microsoft.com/en-us/lifecycle/products/windows-11-home-and-pro
* Windows Server: https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2016, https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2025

Frameworks:
* NIST SP 800-53 Rev. 5: https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
* Its catalogue (5.2.0): https://github.com/usnistgov/oscal-content/blob/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json
* 800-53 to ISO/IEC 27001:2022: https://csrc.nist.gov/projects/olir/informative-reference-catalog/details?referenceId=155, https://csrc.nist.gov/csrc/media/Projects/olir/documents/submissions/sp800-53r5-to-iso-27001-mapping-2022-OLIR-2023-10-12-UPDATED.xlsx
* NIST SP 800-171 Rev. 3: https://csrc.nist.gov/pubs/sp/800/171/r3/final, https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-171r3.pdf
* National Checklist Program: https://ncp.nist.gov/repository
* PCI DSS v4.0 (SAQ D): https://listings.pcisecuritystandards.org/documents/PCI-DSS-v4-0-SAQ-D-Merchant.pdf

Test infrastructure:
* GitHub-hosted runners: https://docs.github.com/en/actions/reference/runners/github-hosted-runners
* Runner images: https://github.com/actions/runner-images/tree/main/images/windows
* Nested virtualization: https://docs.github.com/en/actions/concepts/runners/github-hosted-runners
* KVM on Linux runners: https://github.blog/changelog/2024-04-02-github-actions-hardware-accelerated-android-virtualization-now-available/
* Evaluation media: https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise, https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2025, https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2016
* Windows 11 in a virtual machine: https://learn.microsoft.com/en-us/windows/whats-new/windows-11-requirements
