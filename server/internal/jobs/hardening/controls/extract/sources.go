package extract

// disaZip is where DISA serves its STIG and CCI list zips.
const disaZip = "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/"

// oscalContent is NIST's OSCAL content at the commit of its v1.6.0 release,
// whose SP 800-53 Rev. 5 catalog is release 5.2.0.
const oscalContent = "https://raw.githubusercontent.com/usnistgov/oscal-content/f0de6d8d8c059d374f15e0ae07508d82e370fc1d/nist.gov/"

// Pinned are the files data/ was extracted from, with the SHA-256 each had
// when it was downloaded (see data/SOURCES.md). A new release is taken by
// changing its entry here and running the extraction again.
var Pinned = []Source{
	stig("win11-v2r11", "U_MS_Windows_11_V2R11_STIG.zip", "5a1337e899f113a2482debd3ef240a867fdd205423cbf134e8961de249260d54", "Microsoft Windows 11", "V2R11"),
	stig("win10-v3r6", "U_MS_Windows_10_V3R6_STIG.zip", "bee65d971714589e58963be80fbe3e8ca04493e040fc94cf87336a06f9e882f5", "Microsoft Windows 10", "V3R6"),
	stig("ws2025-v1r4", "U_MS_Windows_Server_2025_V1R4_STIG.zip", "0b83a3d42789577e5850d1bc60474af2e4c28b28b155f21f7b6a486ee0c1d84e", "Microsoft Windows Server 2025", "V1R4"),
	stig("ws2022-v2r11", "U_MS_Windows_Server_2022_V2R11_STIG.zip", "808e83970c4f27590f31435856be9810e02d8f72d3c0a67c0a195cae46dbf48e", "Microsoft Windows Server 2022", "V2R11"),
	stig("ws2019-v3r9", "U_MS_Windows_Server_2019_V3R9_STIG.zip", "b8b1ab26fcf08ddfe99cc1e5faece4638770c7236ae69b860336ca9e217c5812", "Microsoft Windows Server 2019", "V3R9"),
	stig("ws2016-v2r10", "U_MS_Windows_Server_2016_V2R10_STIG.zip", "46fd732925b9c4073b72d5c6536d1bf8b93a6307133ab604e4be28377e767139", "Microsoft Windows Server 2016", "V2R10"),
	stig("defender-av-v2r10", "U_MS_Defender_Antivirus_V2R10_STIG.zip", "f35242dbbbc098ba78972ca069274d8441e50eba52e3c1b7699e21cc6c0aa328", "Microsoft Defender Antivirus", "V2R10"),
	stig("defender-firewall-v2r2", "U_MS_Windows_Defender_Firewall_V2R2_STIG.zip", "4fd9e65948717c06e00605b11e12958eedde409ac50040958e7c13e7146d25b3", "Microsoft Windows Defender Firewall with Advanced Security", "V2R2"),
	{
		Key: "cci-list", Kind: KindCCI, File: "U_CCI_List.zip", URL: disaZip + "U_CCI_List.zip",
		SHA256:  "077cbb6d2ae5f8fdbaaf416d87a34a8621767cdba490f3283feb0c5c35892700",
		Name:    "DISA Control Correlation Identifier (CCI) list",
		Version: "2025-01-23",
	},
	{
		Key: "sp800-53r5", Kind: KindCatalog, File: "NIST_SP-800-53_rev5_catalog.json",
		URL:     oscalContent + "SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json",
		SHA256:  "64ca6b4161de51ab6af098a7d101d326f14c95e1abf721396cd8a049e8115eeb",
		Name:    "NIST SP 800-53 Rev. 5 catalog (OSCAL)",
		Version: "5.2.0",
	},
	{
		Key: "sp800-171r2", Kind: KindAppendixD, File: "NIST.SP.800-171r2.pdf",
		URL:     "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-171r2.pdf",
		SHA256:  "298bdbfcf6a4890a564b225c893230a0b32b2e69e3b98dd898aaeb1d544c5e12",
		Name:    "NIST SP 800-171 Rev. 2, Appendix D (mapping to SP 800-53 Rev. 4)",
		Version: "Rev. 2",
		Date:    "2020-02",
		Note:    "The mapping tables are included for informational purposes and do not impart additional security requirements beyond those requirements defined in Chapter Three.",
	},
	{
		Key: "sp800-171r3", Kind: KindRev3, File: "NIST_SP800-171_rev3_catalog.json",
		URL:     oscalContent + "SP800-171/rev3/json/NIST_SP800-171_rev3_catalog.json",
		SHA256:  "fd68bad4c1fee98dd1b2511884b585fb1f14265d4c5693d0492a25dd66e73dde",
		Name:    "NIST SP 800-171 Rev. 3 catalog (OSCAL), source controls",
		Version: "1.1.0",
	},
	{
		Key: "olir-sp800-53r5-iso27001-2022", Kind: KindCrosswalk, File: "sp800-53r5-to-iso-27001-mapping-2022-OLIR-2023-10-12-UPDATED.xlsx",
		URL:     "https://csrc.nist.gov/csrc/media/Projects/olir/documents/submissions/sp800-53r5-to-iso-27001-mapping-2022-OLIR-2023-10-12-UPDATED.xlsx",
		SHA256:  "e631de234a1fac057991773f015c221226940540f5602e1b70a3768eaff5cbd9",
		Name:    "NIST OLIR crosswalk 800-53-Rev5-to-ISO 27001-2022 (Annex A numbers)",
		Version: "1.0.0",
		Date:    "2023-11-13",
		Note:    "Organizations should not assume security requirement and control equivalency based solely on the mapping tables herein since there is always some degree of subjectivity in the mapping analysis because the mappings are not always one-to-one and may not be completely equivalent.",
	},
}

func stig(key, file, sum, product, version string) Source {
	return Source{
		Key: key, Kind: KindSTIG, File: file, URL: disaZip + file, SHA256: sum,
		Name: "DISA STIG: " + product, Version: version,
	}
}
