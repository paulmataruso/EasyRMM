# Sources of the related-controls data

The files in this directory are extracted from DISA's and NIST's published
files by `extract` (in `../extract`), and `related.json` is generated from
them and `../cites.json` by `controls.Generate` (ADR-0054, *Frameworks:
related controls, never compliance*). Nothing here is written by hand.

They hold identifiers only: STIG rule version IDs (`WN11-SO-000010`), DISA
rule IDs (`SV-253449r958908_rule`), CCI numbers, SP 800-53 control and
enhancement IDs, SP 800-171 requirement numbers and ISO/IEC 27001:2022
Annex A numbers, plus the SP 800-53 Rev. 5 control titles from NIST's
catalog. No STIG rule titles, discussions, check or fix text, and no ISO
text, are kept. `equivalents.csv` names what each match was made by: a
registry value, an audit subcategory, a Group Policy security setting, a
Windows feature or a file, as the checks name them, or a few words of
EasyRMM's own for rules matched by reading.

## The files

| File | Source | Version and date | SHA-256 of the downloaded file | Extracted |
|---|---|---|---|---|
| `stig-win11-v2r11.csv` | <https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_11_V2R11_STIG.zip> | Windows 11 STIG V2R11, benchmark date 2026-09-30 | `5a1337e899f113a2482debd3ef240a867fdd205423cbf134e8961de249260d54` | STIG, below |
| `stig-win10-v3r6.csv` | <https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_10_V3R6_STIG.zip> | Windows 10 STIG V3R6, 2026-01-05 | `bee65d971714589e58963be80fbe3e8ca04493e040fc94cf87336a06f9e882f5` | STIG |
| `stig-ws2025-v1r4.csv` | <https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_Server_2025_V1R4_STIG.zip> | Windows Server 2025 STIG V1R4, 2026-09-30 | `0b83a3d42789577e5850d1bc60474af2e4c28b28b155f21f7b6a486ee0c1d84e` | STIG |
| `stig-ws2022-v2r11.csv` | <https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_Server_2022_V2R11_STIG.zip> | Windows Server 2022 STIG V2R11, 2026-09-30 | `808e83970c4f27590f31435856be9810e02d8f72d3c0a67c0a195cae46dbf48e` | STIG |
| `stig-ws2019-v3r9.csv` | <https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_Server_2019_V3R9_STIG.zip> | Windows Server 2019 STIG V3R9, 2026-07-01 | `b8b1ab26fcf08ddfe99cc1e5faece4638770c7236ae69b860336ca9e217c5812` | STIG |
| `stig-ws2016-v2r10.csv` | <https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_Server_2016_V2R10_STIG.zip> | Windows Server 2016 STIG V2R10, 2025-01-15 | `46fd732925b9c4073b72d5c6536d1bf8b93a6307133ab604e4be28377e767139` | STIG |
| `stig-defender-av-v2r10.csv` | <https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Defender_Antivirus_V2R10_STIG.zip> | Microsoft Defender Antivirus STIG V2R10, 2026-09-30 | `f35242dbbbc098ba78972ca069274d8441e50eba52e3c1b7699e21cc6c0aa328` | STIG |
| `stig-defender-firewall-v2r2.csv` | <https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_Defender_Firewall_V2R2_STIG.zip> | Windows Defender Firewall with Advanced Security STIG V2R2, 2023-11-09 | `4fd9e65948717c06e00605b11e12958eedde409ac50040958e7c13e7146d25b3` | STIG |
| `cci.csv` | <https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CCI_List.zip> | CCI list version 2025-01-23, published 2025-01-23 | `077cbb6d2ae5f8fdbaaf416d87a34a8621767cdba490f3283feb0c5c35892700` | CCI list |
| `sp800-53r5-controls.csv` | <https://raw.githubusercontent.com/usnistgov/oscal-content/f0de6d8d8c059d374f15e0ae07508d82e370fc1d/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json> | SP 800-53 Rev. 5 catalog 5.2.0 (OSCAL), last modified 2026-10-22; `usnistgov/oscal-content` release v1.6.0, commit `f0de6d8d8c059d374f15e0ae07508d82e370fc1d` | `64ca6b4161de51ab6af098a7d101d326f14c95e1abf721396cd8a049e8115eeb` | SP 800-53 titles |
| `sp800-171r2-appendix-d.csv` | <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-171r2.pdf> | SP 800-171 Rev. 2, February 2020 (includes updates as of January 28, 2021) | `298bdbfcf6a4890a564b225c893230a0b32b2e69e3b98dd898aaeb1d544c5e12` | Appendix D |
| `sp800-171r3-source-controls.csv` | <https://raw.githubusercontent.com/usnistgov/oscal-content/f0de6d8d8c059d374f15e0ae07508d82e370fc1d/nist.gov/SP800-171/rev3/json/NIST_SP800-171_rev3_catalog.json> | SP 800-171 Rev. 3 catalog (OSCAL) version 1.1.0, last modified 2026-10-22; same commit | `fd68bad4c1fee98dd1b2511884b585fb1f14265d4c5693d0492a25dd66e73dde` | SP 800-171 Rev. 3 |
| `iso27001-2022-from-sp800-53r5.csv` | <https://csrc.nist.gov/csrc/media/Projects/olir/documents/submissions/sp800-53r5-to-iso-27001-mapping-2022-OLIR-2023-10-12-UPDATED.xlsx> | OLIR "800-53-Rev5-to-ISO 27001-2022" version 1.0.0, posted 2023-11-13 | `e631de234a1fac057991773f015c221226940540f5602e1b70a3768eaff5cbd9` | Crosswalk |
| `equivalents.csv` | the six Windows STIGs above | | | Equivalents |
| `sources.csv` | all of the above | | | the list above, for `related.json`'s sources |

`../extract/sources.go` records the same URLs and SHA-256 values; the
extraction refuses a file whose SHA-256 differs from the recorded one, and
a STIG, CCI list or catalog whose own version differs from the recorded
version. The SHA-256 of the OLIR spreadsheet is the one NIST's catalog
gives for it (`hash` in
<https://csrc.nist.gov/extensions/nudp/services/json/olir/informative-reference-catalog/details/155>).
DISA and the PDF publish no checksum: theirs are the SHA-256 of the files
as downloaded on 2026-11-22.

## How each was extracted

**STIG.** The zip's one `*-xccdf.xml` member: for each `Rule`, its
`version` (the rule's version ID), its `id` (the rule ID) and its `ident`
values whose system is `http://cyber.mil/cci`, in the file's order. The
release (`V2R11`) is the benchmark's `version` and the release number in
its `release-info`, whose benchmark date is the date above.

**CCI list.** `U_CCI_List.xml` in the zip: for each CCI that a rule of the
eight STIG releases names, the `index` of its references titled "NIST SP
800-53 Revision 5" (`sp80053r5`) and "NIST SP 800-53 Revision 4"
(`sp80053r4`), as the list writes them (`AC-7 a`, `AC-6 (9)`), separated by
semicolons. The list's version is its `metadata/version`.

**SP 800-53 titles.** Each base control of the catalog's groups that is not
withdrawn: its `label` without a class (`AC-7`; the classed labels are
zero-padded) and its `title`.

**Appendix D.** NIST publishes no machine-readable Appendix D: the
publication's page (<https://csrc.nist.gov/pubs/sp/800/171/r2/upd1/final>)
offers a spreadsheet of the requirements and a CSF mapping, neither with the
SP 800-53 Rev. 4 controls. So the PDF is read with poppler's `pdftotext
-layout` (version 26.01.0 was used), from "TABLE D-1:" to "APPENDIX E",
skipping page headers and footers and footnotes. Each row holds the
requirements in it and the SP 800-53 Rev. 4 controls and enhancements it
lists, as the tables write them (`AC-6(1)`). A table's basic requirements
share one row, as the tables merge their cells; a derived requirement
starts a row when a control stands on its first line, and otherwise shares
the row above it (3.5.7 to 3.5.10 share IA-5(1); 3.10.3 to 3.10.5 share
PE-3; 3.14.4 and 3.14.5 share SI-3). The result, 87 rows holding the 110
requirements, was checked by eye against the rendered tables (Tables D-1
to D-14, pages 62 to 83), and its split into basic and derived
requirements against NIST's spreadsheet `sp800-171r2-security-reqs.xlsx`. The PDF's cover notes that SP 800-171
Rev. 2 was withdrawn (date updated May 14, 2024), superseded by Rev. 3; it
is used because CMMC Level 2 and DFARS 252.204-7012 use it. NIST's caveat:
"The mapping tables are included for informational purposes and do not
impart additional security requirements beyond those requirements defined
in Chapter Three."

**SP 800-171 Rev. 3.** Each requirement of the catalog that is not
withdrawn: its `sort-id` (`03.04.02`) and the titles of the back-matter
resources its `reference` links point to whose link is to an SP 800-53
control in NIST's CPRT (`AC-02(03)`), which are the requirement's source
controls. The 97 requirements and their source controls are the same
as NIST's CPRT export of SP 800-171 Rev. 3
(<https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/SP_800_171_3_0_0/export/json?element=all>)
and as the PDF's "Source Control(s)" lines.

**Crosswalk.** Every sheet of the spreadsheet whose header row has "Focal
Document Element" and "Reference Document Element": for each SP 800-53
Rev. 5 control or enhancement as the sheet writes it (`AC-07`), the Annex A
numbers (`A.8.5`) given for it, in the sheet's order; the clause numbers
(`5.2`, `7.5.1`) and all descriptions are left out. NIST's caveat:
"Organizations should not assume security requirement and control
equivalency based solely on the mapping tables herein since there is always
some degree of subjectivity in the mapping analysis because the mappings
are not always one-to-one and may not be completely equivalent."

**Equivalents.** For every Windows 11 rule in `../cites.json`, the rule of
Windows 10 V3R6, and for every Server 2025 rule, the rules of Server 2022
V2R11, 2019 V3R9 and 2016 V2R10, that check the same thing. `WN25-MS` and
`WN25-DC` rules match whatever the older release calls the rule (`WN22-MS`,
`WN16-MS`). The check text is read in memory and never written. A rule's
key is the first of these its check names:

1. the registry values (hive, path and value name; case and spaces ignored);
2. the audit subcategories with Success or Failure, as AuditPol or Group
   Policy writes them (`Audit Registry` is Registry);
3. the account policies, security options or user rights, by name;
4. the Windows features, by name;
5. the event log files and `Eventvwr.exe`.

A rule matches the rule of the other release with the same key. Where that
release has two (Windows 10, Server 2022 and Server 2019 check Sensitive
Privilege Use once through AuditPol and once through Group Policy), the one
checked the same way is taken; Server 2016 checks it once, so
`WN16-AU-000350` and `-000360` are each the equivalent of two Server 2025
rules. Without a key, a check that is word for word the same
(product names and rule IDs aside) matches (`same check text`). The
eighteen pairs left were matched by reading both checks, and are listed
with what they check in `readMatches` in `../extract/equivalents.go`
(`read: …`). Values are not compared: a release sometimes asks a different
value of the same setting (the age of the Administrator account's password,
the size of the Security event log). An empty `equivalent` means the
release has no such rule: Server 2022, 2019 and 2016 have no rule for
auditing Account Lockout successes (`WN25-AU-000150`), and Server 2016 none
for Handle Manipulation and Registry auditing (`WN25-AU-000583`, `-000585`,
`-000586`).

## Regenerating

`related.json` alone, after changing `../cites.json`:

```sh
go run ./server/internal/jobs/hardening/controls/cmd/gencontrols
```

`TestRelatedIsGenerated` fails until it is run.

Everything, from the downloaded files (needs poppler's `pdftotext`):

```sh
src=/var/tmp/w1-controls/src
mkdir -p "$src"
for z in U_MS_Windows_11_V2R11_STIG U_MS_Windows_10_V3R6_STIG \
  U_MS_Windows_Server_2025_V1R4_STIG U_MS_Windows_Server_2022_V2R11_STIG \
  U_MS_Windows_Server_2019_V3R9_STIG U_MS_Windows_Server_2016_V2R10_STIG \
  U_MS_Defender_Antivirus_V2R10_STIG U_MS_Windows_Defender_Firewall_V2R2_STIG \
  U_CCI_List; do
  curl -fsSL -o "$src/$z.zip" "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/$z.zip"
done
oscal=https://raw.githubusercontent.com/usnistgov/oscal-content/f0de6d8d8c059d374f15e0ae07508d82e370fc1d/nist.gov
curl -fsSL -o "$src/NIST_SP-800-53_rev5_catalog.json" "$oscal/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
curl -fsSL -o "$src/NIST_SP800-171_rev3_catalog.json" "$oscal/SP800-171/rev3/json/NIST_SP800-171_rev3_catalog.json"
curl -fsSL -o "$src/NIST.SP.800-171r2.pdf" https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-171r2.pdf
curl -fsSL -o "$src/sp800-53r5-to-iso-27001-mapping-2022-OLIR-2023-10-12-UPDATED.xlsx" \
  https://csrc.nist.gov/csrc/media/Projects/olir/documents/submissions/sp800-53r5-to-iso-27001-mapping-2022-OLIR-2023-10-12-UPDATED.xlsx
go run ./server/internal/jobs/hardening/controls/cmd/gencontrols -extract "$src"
```

A new release of any of them is taken by changing its entry (URL, file,
SHA-256, version) in `../extract/sources.go`, and for a STIG the release key
in `../cites.json` and the IDs the modules cite; then running the above,
reading the differences in `equivalents.csv` and `related.json`, updating
this file, and running the tests (`TestCitedRulesExist` fails for a cited
ID the new release does not have).
