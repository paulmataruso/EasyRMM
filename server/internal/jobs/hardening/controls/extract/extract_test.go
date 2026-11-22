package extract

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/paulmataruso/easyrmm/server/internal/jobs/hardening/controls"
)

func zipOf(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, name := range slices.Sorted(func(yield func(string) bool) {
		for k := range files {
			if !yield(k) {
				return
			}
		}
	}) {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(files[name])); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// xccdf is a small STIG: version 2, release 11, two rules.
func xccdf(prefix string, rules ...[2]string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?><Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="test">` +
		`<plain-text id="release-info">Release: 11 Benchmark Date: 30 Sep 2026</plain-text><version>2</version>`)
	for i, r := range rules {
		b.WriteString(`<Group id="V-` + prefix + `"><Rule id="SV-` + prefix + string(rune('0'+i)) + `r1_rule"><version>` + r[0] + `</version>` +
			`<ident system="http://cyber.mil/legacy">V-1</ident><ident system="http://cyber.mil/cci">CCI-000044</ident>` +
			`<check system="C-1"><check-content>` + r[1] + `</check-content></check></Rule></Group>`)
	}
	b.WriteString(`</Benchmark>`)
	return b.String()
}

const regCheck = "Registry Hive: HKEY_LOCAL_MACHINE\nRegistry Path: \\SOFTWARE\\Policies\\Test\\\n\nValue Name: Enabled\n\nValue: 1"

func TestParseXCCDF(t *testing.T) {
	r, err := parseSTIGZip(zipOf(t, map[string]string{
		"x/readme.pdf":                    "not xml",
		"x/U_Test_V2R11_Manual-xccdf.xml": xccdf("1", [2]string{"WN11-CC-000010", regCheck}, [2]string{"WN11-AU-000005", "Account Logon >> Credential Validation - Failure"}),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if r.version != "V2R11" || r.date != "2026-09-30" || len(r.rules) != 2 {
		t.Fatalf("release = %+v", r)
	}
	if got := r.rules[0]; got.version != "WN11-CC-000010" || got.id != "SV-10r1_rule" || !slices.Equal(got.ccis, []string{"CCI-000044"}) || got.check != regCheck {
		t.Errorf("rule = %+v", got)
	}

	for name, x := range map[string]string{
		"not XML":         "<",
		"no release-info": `<Benchmark><version>1</version><Group><Rule id="SV-1"><version>A</version></Rule></Group></Benchmark>`,
		"bad release-info": `<Benchmark><plain-text id="release-info">Release: x</plain-text><version>1</version>` +
			`<Group><Rule id="SV-1"><version>A</version></Rule></Group></Benchmark>`,
		"bad date": `<Benchmark><plain-text id="release-info">Release: 1 Benchmark Date: 31 Feb 2026</plain-text></Benchmark>`,
		"no rules": `<Benchmark><plain-text id="release-info">Release: 1 Benchmark Date: 1 Feb 2026</plain-text></Benchmark>`,
		"rule twice": `<Benchmark><plain-text id="release-info">Release: 1 Benchmark Date: 1 Feb 2026</plain-text>` +
			`<Group><Rule id="SV-1"><version>A</version></Rule></Group><Group><Rule id="SV-2"><version>A</version></Rule></Group></Benchmark>`,
	} {
		if _, err := parseXCCDF([]byte(x)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, files := range map[string]map[string]string{
		"no XCCDF":  {"a.txt": "x"},
		"two XCCDF": {"a-xccdf.xml": "x", "b-xccdf.xml": "y"},
	} {
		if _, err := parseSTIGZip(zipOf(t, files)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := parseSTIGZip([]byte("not a zip")); err == nil {
		t.Error("not a zip: accepted")
	}
}

const cciListXML = "\xef\xbb\xbf" + `<?xml version="1.0" encoding="utf-8"?><cci_list xmlns="http://iase.disa.mil/cci">` +
	`<metadata><version>2025-01-23</version><publishdate>2025-01-23</publishdate></metadata><cci_items>` +
	`<cci_item id="CCI-000044"><references>` +
	`<reference creator="NIST" title="NIST SP 800-53" version="3" index="AC-7 a" />` +
	`<reference creator="NIST" title="NIST SP 800-53 Revision 4" version="4" index="AC-7 a" />` +
	`<reference creator="NIST" title="NIST SP 800-53 Revision 5" version="5" index="AC-7 a" />` +
	`</references></cci_item>` +
	`<cci_item id="CCI-000366"><references>` +
	`<reference creator="NIST" title="NIST SP 800-53 Revision 4" version="4" index="CM-6 b" />` +
	`<reference creator="NIST" title="NIST SP 800-53 Revision 5" version="5" index="CM-6 b" />` +
	`<reference creator="NIST" title="NIST SP 800-53 Revision 5" version="5" index="CM-6 (1)" />` +
	`</references></cci_item></cci_items></cci_list>`

func TestParseCCI(t *testing.T) {
	l, err := parseCCIZip(zipOf(t, map[string]string{"U_CCI_List.xml": cciListXML, "README.TXT": "x"}))
	if err != nil {
		t.Fatal(err)
	}
	if l.version != "2025-01-23" || l.date != "2025-01-23" {
		t.Errorf("version %q date %q", l.version, l.date)
	}
	if got := l.refs["CCI-000366"]; !slices.Equal(got.rev5, []string{"CM-6 b", "CM-6 (1)"}) || !slices.Equal(got.rev4, []string{"CM-6 b"}) {
		t.Errorf("CCI-000366 = %+v", got)
	}
	for name, x := range map[string]string{
		"not XML":    "<",
		"no items":   `<cci_list><metadata><version>1</version></metadata></cci_list>`,
		"no version": `<cci_list><cci_items><cci_item id="CCI-1"/></cci_items></cci_list>`,
		"separator in index": `<cci_list><metadata><version>1</version></metadata><cci_items><cci_item id="CCI-1"><references>` +
			`<reference title="NIST SP 800-53 Revision 5" index="AC-1;AC-2" /></references></cci_item></cci_items></cci_list>`,
	} {
		if _, err := parseCCI([]byte(x)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := parseCCIZip(zipOf(t, map[string]string{"x": "y"})); err == nil {
		t.Error("zip without the list: accepted")
	}
}

const catalogJSON = `{"catalog": {"metadata": {"version": "5.2.0", "last-modified": "2026-10-22T11:30:00.00000-00:00"},
 "groups": [{"controls": [
  {"id": "ac-7", "title": "Unsuccessful Logon Attempts", "props": [{"name": "label", "value": "AC-07", "class": "zero-padded"}, {"name": "label", "value": "AC-7"}]},
  {"id": "ac-13", "title": "Supervision and Review", "props": [{"name": "label", "value": "AC-13"}, {"name": "status", "value": "withdrawn"}]},
  {"id": "cm-6", "title": "Configuration Settings", "props": [{"name": "label", "value": "CM-6"}]}
 ]}]}}`

func TestParseCatalog(t *testing.T) {
	got, info, err := parseCatalog([]byte(catalogJSON))
	if err != nil {
		t.Fatal(err)
	}
	want := []baseControl{{"AC-7", "Unsuccessful Logon Attempts"}, {"CM-6", "Configuration Settings"}}
	if !slices.Equal(got, want) || info != (catalogInfo{"5.2.0", "2026-10-22"}) {
		t.Errorf("parseCatalog = %v, %+v", got, info)
	}
	for name, x := range map[string]string{
		"not JSON":    "{",
		"no version":  `{"catalog": {"metadata": {}}}`,
		"no controls": `{"catalog": {"metadata": {"version": "1", "last-modified": "2026-01-01"}}}`,
		"no label":    `{"catalog": {"metadata": {"version": "1", "last-modified": "2026-01-01"}, "groups": [{"controls": [{"id": "a", "title": "A"}]}]}}`,
	} {
		if _, _, err := parseCatalog([]byte(x)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

const rev3JSON = `{"catalog": {"metadata": {"version": "1.1.0", "last-modified": "2026-10-22T11:30:00Z"},
 "groups": [{"controls": [
  {"id": "SP_800_171_03.01.01", "props": [{"name": "sort-id", "value": "03.01.01"}],
   "links": [{"href": "#u1", "rel": "reference"}, {"href": "#u2", "rel": "reference"}, {"href": "#u3", "rel": "reference"}]},
  {"id": "SP_800_171_03.01.13", "props": [{"name": "sort-id", "value": "03.01.13"}, {"name": "status", "value": "withdrawn"}],
   "links": [{"href": "03.13.08", "rel": "addressed_by"}]}
 ]}],
 "back-matter": {"resources": [
  {"uuid": "u1", "title": "AC-02", "rlinks": [{"href": "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=AC-02"}]},
  {"uuid": "u2", "title": "AC-02(03)", "rlinks": [{"href": "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=AC-02(03)"}]},
  {"uuid": "u3", "title": "SP 800-46", "rlinks": [{"href": "https://doi.org/10.6028/NIST.SP.800-46r2"}]}
 ]}}}`

func TestParseRev3(t *testing.T) {
	got, info, err := parseRev3([]byte(rev3JSON))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].id != "03.01.01" || !slices.Equal(got[0].controls, []string{"AC-02", "AC-02(03)"}) || info.version != "1.1.0" {
		t.Errorf("parseRev3 = %+v, %+v", got, info)
	}
	for name, x := range map[string]string{
		"not JSON":           "{",
		"no requirements":    `{"catalog": {"metadata": {"version": "1", "last-modified": "2026-01-01"}}}`,
		"no source controls": `{"catalog": {"metadata": {"version": "1", "last-modified": "2026-01-01"}, "groups": [{"controls": [{"id": "a", "props": [{"name": "sort-id", "value": "03.01.01"}]}]}]}}`,
	} {
		if _, _, err := parseRev3([]byte(x)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// appendixText imitates pdftotext -layout's output of Appendix D.
const appendixText = `CONTENTS
APPENDIX D MAPPING TABLES ........ 61
APPENDIX E TAILORING CRITERIA ........ 84
          APPENDIX D                                       PAGE 61
                  TABLE D-1: MAPPING ACCESS CONTROL REQUIREMENTS TO CONTROLS
                                              NIST SP 800-53              ISO/IEC 27001
                        SECURITY REQUIREMENTS     Relevant Security Controls
           3.1 ACCESS CONTROL
           Basic Security Requirements
           3.1.1    Limit system access to     AC-2      Account Management     A.9.2.1   User registration
                    authorized users.
           3.1.2    Limit system access to                                    A.9.2.2   User access
                    the types of transactions. AC-3      Access Enforcement
This publication is available free of charge from: https://doi.org/10.6028/NIST.SP.800-171r2
           Derived Security Requirements
           3.1.5    Employ least privilege.     AC-6      Least Privilege        A.9.1.2   Access
                                                AC-6(1)   Least Privilege        No direct mapping.
          31 The security controls in Tables D-1 through D-14 are taken from SP 800-53 (AC-99).
             continued footnote naming SC-99.
          APPENDIX D                                       PAGE 62
          SP 800-171, REVISION 2                 PROTECTING CONTROLLED UNCLASSIFIED INFORMATION
          ___________________________________________
                                                AC-6(5)   Least Privilege        No direct mapping.
           3.5.7    Enforce a minimum password  IA-5(1)   Authenticator          No direct mapping.
           3.5.8    Prohibit password reuse.
           3.5.9    Allow temporary passwords.
           3.13.11  Employ FIPS-validated       SC-13     Cryptographic          A.10.1.1
                    cryptography (see SC-130x and XSC-1).
APPENDIX E
           3.99.1   Not in Appendix D.          AC-1
`

func TestParseAppendixD(t *testing.T) {
	got, err := parseAppendixD(appendixText)
	if err != nil {
		t.Fatal(err)
	}
	want := []appendixDRow{
		{[]string{"3.1.1", "3.1.2"}, []string{"AC-2", "AC-3"}},
		{[]string{"3.1.5"}, []string{"AC-6", "AC-6(1)", "AC-6(5)"}},
		{[]string{"3.5.7", "3.5.8", "3.5.9"}, []string{"IA-5(1)"}},
		{[]string{"3.13.11"}, []string{"SC-13"}},
	}
	if len(got) != len(want) {
		t.Fatalf("rows = %+v", got)
	}
	for i := range want {
		if !slices.Equal(got[i].requirements, want[i].requirements) || !slices.Equal(got[i].controls, want[i].controls) {
			t.Errorf("row %d = %+v, want %+v", i, got[i], want[i])
		}
	}

	for name, text := range map[string]string{
		"no table":              "nothing",
		"no appendix E":         "TABLE D-1: x\n",
		"no rows":               "TABLE D-1: x\nAPPENDIX E\n",
		"outside a section":     "TABLE D-1: x\n 3.1.1  Limit  AC-2\nAPPENDIX E\n",
		"control before any":    "TABLE D-1: x\nBasic Security Requirements\n      AC-2\nAPPENDIX E\n",
		"requirement twice":     "TABLE D-1: x\nDerived Security Requirements\n 3.1.1  a  AC-2\n 3.1.1  b  AC-3\nAPPENDIX E\n",
		"row without a control": "TABLE D-1: x\nDerived Security Requirements\n 3.1.1  a\nAPPENDIX E\n",
	} {
		if _, err := parseAppendixD(text); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// xlsxOf builds a workbook: a crosswalk sheet and a definitions sheet.
func xlsxOf(t *testing.T) []byte {
	t.Helper()
	const ns = `xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"`
	return zipOf(t, map[string]string{
		"xl/workbook.xml": `<workbook ` + ns + ` xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>` +
			`<sheet name="AC" sheetId="1" r:id="rId1"/><sheet name="Definitions" sheetId="2" r:id="rId2"/><sheet name="Empty" sheetId="3" r:id="rId3"/></sheets></workbook>`,
		"xl/_rels/workbook.xml.rels": `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
			`<Relationship Id="rId1" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Target="/xl/worksheets/sheet2.xml"/>` +
			`<Relationship Id="rId3" Target="worksheets/sheet3.xml"/></Relationships>`,
		"xl/sharedStrings.xml": `<sst ` + ns + `><si><t>Focal Document
Element</t></si><si><r><t>Reference Document </t></r><r><t>Element</t></r></si><si><t>AC-07</t></si><si><t>A.8.5</t></si><si><t>5.2</t></si></sst>`,
		"xl/worksheets/sheet1.xml": `<worksheet ` + ns + `><sheetData>` +
			`<row r="1"><c r="A1" t="s"><v>0</v></c><c r="D1" t="s"><v>1</v></c></row>` +
			`<row r="2"><c r="A2" t="s"><v>2</v></c><c r="D2" t="s"><v>3</v></c></row>` +
			`<row r="3"><c r="A3" t="s"><v>2</v></c><c r="D3" t="s"><v>4</v></c></row>` +
			`<row r="4"><c r="A4" t="s"><v>2</v></c><c r="D4" t="s"><v>3</v></c></row>` +
			`<row r="5"><c r="A5" t="inlineStr"><is><t>AC-07(02)</t></is></c><c r="D5" t="inlineStr"><is><t>A.8.10</t></is></c></row>` +
			`<row r="6"><c r="A6"><v>1</v></c></row>` +
			`</sheetData></worksheet>`,
		"xl/worksheets/sheet2.xml": `<worksheet ` + ns + `><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>Term</t></is></c></row></sheetData></worksheet>`,
		"xl/worksheets/sheet3.xml": `<worksheet ` + ns + `><sheetData/></worksheet>`,
	})
}

func TestParseCrosswalk(t *testing.T) {
	got, err := parseCrosswalk(xlsxOf(t))
	if err != nil {
		t.Fatal(err)
	}
	want := []crosswalkRow{{"AC-07", []string{"A.8.5"}}, {"AC-07(02)", []string{"A.8.10"}}}
	if len(got) != len(want) || got[0].control != want[0].control || !slices.Equal(got[0].annexA, want[0].annexA) ||
		got[1].control != want[1].control || !slices.Equal(got[1].annexA, want[1].annexA) {
		t.Errorf("parseCrosswalk = %+v", got)
	}
	if _, err := parseCrosswalk([]byte("not a zip")); err == nil {
		t.Error("not a zip: accepted")
	}
	noMapping := zipOf(t, map[string]string{
		"xl/workbook.xml":            `<workbook><sheets/></workbook>`,
		"xl/_rels/workbook.xml.rels": `<Relationships/>`,
	})
	if _, err := parseCrosswalk(noMapping); err == nil {
		t.Error("no mappings: accepted")
	}
	for name, files := range map[string]map[string]string{
		"bad shared strings": {"xl/sharedStrings.xml": "<", "xl/workbook.xml": "<workbook/>", "xl/_rels/workbook.xml.rels": "<Relationships/>"},
		"bad workbook":       {"xl/workbook.xml": "<"},
		"bad relationships":  {"xl/workbook.xml": "<workbook/>", "xl/_rels/workbook.xml.rels": "<"},
		"bad sheet": {"xl/workbook.xml": `<workbook xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet r:id="a"/></sheets></workbook>`,
			"xl/_rels/workbook.xml.rels": `<Relationships><Relationship Id="a" Target="s.xml"/></Relationships>`, "xl/s.xml": "<"},
		"bad cell reference": {"xl/workbook.xml": `<workbook xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet r:id="a"/></sheets></workbook>`,
			"xl/_rels/workbook.xml.rels": `<Relationships><Relationship Id="a" Target="s.xml"/></Relationships>`,
			"xl/s.xml":                   `<worksheet><sheetData><row><c r="7"><v>1</v></c></row></sheetData></worksheet>`},
		"bad shared index": {"xl/workbook.xml": `<workbook xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet r:id="a"/></sheets></workbook>`,
			"xl/_rels/workbook.xml.rels": `<Relationships><Relationship Id="a" Target="s.xml"/></Relationships>`,
			"xl/s.xml":                   `<worksheet><sheetData><row><c r="A1" t="s"><v>9</v></c></row></sheetData></worksheet>`},
	} {
		if _, err := readXLSX(zipOf(t, files)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestKeyOf(t *testing.T) {
	for check, want := range map[string]string{
		regCheck: `registry: HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Test\Enabled`,
		"Registry HiveHKEY_LOCAL_MACHINE\nRegistry PathSOFTWARE\\ Policies\\Test\\\n\nValue NameEnabled":                            `registry: HKEY_LOCAL_MACHINE\SOFTWARE\ Policies\Test\Enabled`,
		"Compare:\n\nObject Access >> Audit Registry - Failure\nPolicy Change >> MPSSVC Rule-Level Policy Change - Success":         "audit policy: Registry - Failure; MPSSVC Rule-Level Policy Change - Success",
		`... >> Audit Audit Policy Change. If "Audit Audit Policy Change" is not set to "Success", this is a finding.`:              "audit policy: Audit Policy Change - Success",
		"Navigate to ... >> Account Policies >> Account Lockout Policy.\n\nIf the \"Account lockout duration\" is less than \"15\"": "security policy: Account lockout duration",
		"Navigate to ... >> Security Options.\n\nIf the value for \"Accounts: Guest account status\" is not set":                    "security policy: Accounts: Guest account status",
		`Enter "Get-WindowsFeature | Where Name -eq Fax".`:                                                                          "Windows feature: Fax",
		"Get-WindowsOptionalFeature -Online | Where FeatureName -like *PowerShellv2*":                                               "Windows feature: PowerShellv2",
		`View the permissions on "Application.evtx".`:                                                                               "file: Application.evtx",
	} {
		if got := keyOf(check).String(); got != want {
			t.Errorf("keyOf(%q) = %q, want %q", check, got, want)
		}
	}
	if k := keyOf("Verify a process exists."); k.kind != "" {
		t.Errorf("keyOf found %+v in prose", k)
	}
	a := keyOf(`Registry Hive: HKEY_LOCAL_MACHINE` + "\nRegistry Path: \\SOFTWARE\\Policies\\Test\\\nValue Name: Enabled")
	b := keyOf("Registry Hive: HKEY_LOCAL_MACHINE\nRegistry Path: \\SOFTWARE\\ Policies\\TEST\\\nValue Name:enabled")
	if !a.equal(b) {
		t.Errorf("registry keys differing in spacing and case do not match: %v %v", a.keys, b.keys)
	}
	if (checkKey{}).equal(checkKey{}) {
		t.Error("two empty keys match")
	}
}

func TestMatchRule(t *testing.T) {
	audit := keyOf("A >> Sensitive Privilege Use - Success")
	gpo := keyOf(`If "Audit Sensitive Privilege Use" is not set to "Success"`)
	keys := map[string]checkKey{"T-1": audit, "T-2": gpo, "T-3": keyOf(regCheck), "T-4": {}, "T-5": {}}
	texts := map[string]string{"T-1": "a", "T-2": "b", "T-3": "c", "T-4": "same", "T-5": "twice"}

	if got, how, err := matchRule("S", gpo, "x", keys, texts); err != nil || got != "T-2" || how != "audit policy: Sensitive Privilege Use - Success" {
		t.Errorf("by key and method = %q %q %v", got, how, err)
	}
	if got, how, err := matchRule("S", checkKey{}, "same", keys, texts); err != nil || got != "T-4" || how != "same check text" {
		t.Errorf("by text = %q %q %v", got, how, err)
	}
	if got, _, err := matchRule("S", checkKey{}, "none", keys, texts); err != nil || got != "" {
		t.Errorf("no match = %q %v", got, err)
	}
	texts["T-6"], keys["T-6"] = "twice", checkKey{}
	if _, _, err := matchRule("S", checkKey{}, "twice", keys, texts); err == nil {
		t.Error("two rules with the same text: accepted")
	}
	keys["T-7"], texts["T-7"] = keyOf(regCheck), "c"
	if _, _, err := matchRule("S", keyOf(regCheck), "c", keys, texts); err == nil {
		t.Error("two rules with the same key, method and text: accepted")
	}
}

func testCites(t *testing.T, ids ...string) controls.Cites {
	t.Helper()
	c, err := controls.ParseCites([]byte(`{"releases": {"WN11": "win11-v2r11", "WNDF-AV": "av"},
 "modules": [{"module": "m", "meets": ["` + strings.Join(ids, `", "`) + `"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestEquivalents(t *testing.T) {
	stigs := map[string]stigRelease{
		"win11-v2r11": {rules: []stigRule{
			{version: "WN11-CC-000010", check: regCheck},
			{version: "WN11-00-000030", check: "Read me."},
			{version: "WN11-00-000040", check: "Nothing else checks this."},
		}},
		"win10-v3r6": {rules: []stigRule{
			{version: "WN10-CC-000010", check: regCheck},
			{version: "WN10-00-000030", check: "Read me differently."},
		}},
	}
	reads := []readMatch{{"WN11-00-000030", "win10-v3r6", "WN10-00-000030", "the same thing"}}
	rows, err := equivalents(testCites(t, "WN11-CC-000010", "WN11-00-000030", "WN11-00-000040", "WNDF-AV-000001"), stigs, reads)
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"WN11-00-000030", "win10-v3r6", "WN10-00-000030", "read: the same thing"},
		{"WN11-00-000040", "win10-v3r6", "", ""},
		{"WN11-CC-000010", "win10-v3r6", "WN10-CC-000010", `registry: HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Test\Enabled`},
	}
	if !slices.EqualFunc(rows, want, slices.Equal[[]string]) {
		t.Errorf("equivalents = %q, want %q", rows, want)
	}

	for name, tc := range map[string]struct {
		ids   []string
		reads []readMatch
		drop  string
	}{
		"read match not cited":    {ids: []string{"WN11-CC-000010"}, reads: reads},
		"read match also keyed":   {ids: []string{"WN11-CC-000010"}, reads: []readMatch{{"WN11-CC-000010", "win10-v3r6", "WN10-CC-000010", "x"}}},
		"read match not in it":    {ids: []string{"WN11-00-000030"}, reads: []readMatch{{"WN11-00-000030", "win10-v3r6", "WN10-00-000999", "x"}}},
		"cited rule not in it":    {ids: []string{"WN11-CC-000999"}},
		"no source release":       {ids: []string{"WN11-CC-000010"}, drop: "win11-v2r11"},
		"no target release":       {ids: []string{"WN11-CC-000010"}, drop: "win10-v3r6"},
		"ambiguous in the target": {ids: []string{"WN11-00-000030"}, drop: "ambiguous"},
	} {
		t.Run(name, func(t *testing.T) {
			s := map[string]stigRelease{"win11-v2r11": stigs["win11-v2r11"], "win10-v3r6": stigs["win10-v3r6"]}
			switch tc.drop {
			case "ambiguous":
				s["win10-v3r6"] = stigRelease{rules: []stigRule{{version: "A", check: "Read me."}, {version: "B", check: "Read  me."}}}
			case "":
			default:
				delete(s, tc.drop)
			}
			if _, err := equivalents(testCites(t, tc.ids...), s, tc.reads); err == nil {
				t.Error("accepted")
			}
		})
	}
}

// sources builds a source directory and the matching Sources list.
func sources(t *testing.T) (string, []Source) {
	t.Helper()
	dir := t.TempDir()
	files := map[string][]byte{
		"w11.zip": zipOf(t, map[string]string{"a-xccdf.xml": xccdf("1", [2]string{"WN11-CC-000010", regCheck}, [2]string{"WN11-00-000030", "Read me."})}),
		"w10.zip": func() []byte {
			x := strings.Replace(xccdf("2", [2]string{"WN10-CC-000010", regCheck}, [2]string{"WN10-00-000030", "Different."}), "<version>2</version>", "<version>3</version>", 1)
			return zipOf(t, map[string]string{"b-xccdf.xml": x})
		}(),
		"cci.zip":   zipOf(t, map[string]string{"U_CCI_List.xml": cciListXML}),
		"53.json":   []byte(catalogJSON),
		"r3.json":   []byte(strings.ReplaceAll(rev3JSON, `"AC-02"`, `"AC-07"`)),
		"r2.pdf":    []byte("%PDF-1.4 stand-in"),
		"iso.xlsx":  xlsxOf(t),
		"cites.txt": nil,
	}
	var list []Source
	for name, kind := range map[string]Kind{"w11.zip": KindSTIG, "w10.zip": KindSTIG, "cci.zip": KindCCI, "53.json": KindCatalog,
		"r3.json": KindRev3, "r2.pdf": KindAppendixD, "iso.xlsx": KindCrosswalk} {
		sum := sha256.Sum256(files[name])
		s := Source{Key: name, Kind: kind, File: name, URL: "https://example.invalid/" + name, SHA256: hex.EncodeToString(sum[:]), Name: name}
		switch name {
		case "w11.zip":
			s.Key, s.Version = "win11-v2r11", "V2R11"
		case "w10.zip":
			s.Key, s.Version = "win10-v3r6", "V3R11"
		case "r2.pdf":
			s.Version, s.Date, s.Note = "Rev. 2", "2020-02", "informational"
		}
		list = append(list, s)
	}
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	slices.SortFunc(list, func(a, b Source) int { return strings.Compare(a.File, b.File) })
	return dir, list
}

func packageDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cites := `{"releases": {"WN11": "win11-v2r11"}, "modules": [{"module": "m", "meets": ["WN11-CC-000010", "WN11-00-000030"]}]}`
	if err := os.WriteFile(filepath.Join(dir, controls.CitesFile), []byte(cites), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func fakePDF(_ context.Context, b []byte) (string, error) {
	if !bytes.HasPrefix(b, []byte("%PDF")) {
		return "", errors.New("not a PDF")
	}
	return appendixText, nil
}

func TestRun(t *testing.T) {
	src, list := sources(t)
	pkg := packageDir(t)
	reads := []readMatch{{"WN11-00-000030", "win10-v3r6", "WN10-00-000030", "read"}}
	if err := Run(context.Background(), Options{SourceDir: src, PackageDir: pkg, Sources: list, PDFText: fakePDF, reads: reads}); err != nil {
		t.Fatal(err)
	}
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(pkg, name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	if got := read("data/stig-win11-v2r11.csv"); got != "version,rule,ccis\nWN11-CC-000010,SV-10r1_rule,CCI-000044\nWN11-00-000030,SV-11r1_rule,CCI-000044\n" {
		t.Errorf("stig file = %q", got)
	}
	if got := read("data/cci.csv"); got != "cci,sp80053r5,sp80053r4\nCCI-000044,AC-7 a,AC-7 a\n" {
		t.Errorf("cci.csv = %q (only the CCIs the STIGs use)", got)
	}
	if got := read("data/equivalents.csv"); !strings.Contains(got, "WN11-00-000030,win10-v3r6,WN10-00-000030,read: read\n") {
		t.Errorf("equivalents.csv = %q", got)
	}
	if got := read("data/sources.csv"); !strings.Contains(got, "win11-v2r11,stig,w11.zip,V2R11,2026-09-30,") ||
		!strings.Contains(got, "r2.pdf,appendixD,r2.pdf,Rev. 2,2020-02,") || !strings.Contains(got, ",informational\n") {
		t.Errorf("sources.csv = %q", got)
	}
	for _, s := range []string{"check", "Read me", "Account Management", "Least Privilege"} {
		for _, f := range []string{"data/stig-win11-v2r11.csv", "data/equivalents.csv", "data/sp800-171r2-appendix-d.csv"} {
			if strings.Contains(read(f), s) {
				t.Errorf("%s holds text %q", f, s)
			}
		}
	}

	// What it wrote is what the generator reads.
	b, err := controls.Generate(os.DirFS(pkg))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"id": "AC-7"`) || !strings.Contains(string(b), `"03.01.01"`) {
		t.Errorf("generated %s", b)
	}
}

func TestRunRefuses(t *testing.T) {
	for name, change := range map[string]func(src, pkg string, o *Options){
		"changed file": func(src, _ string, _ *Options) {
			if err := os.WriteFile(filepath.Join(src, "53.json"), []byte(catalogJSON+" "), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"missing file":  func(src, _ string, _ *Options) { _ = os.Remove(filepath.Join(src, "r3.json")) },
		"other version": func(_, _ string, o *Options) { o.Sources[len(o.Sources)-1].Version = "V9R9" },
		"unknown kind":  func(_, _ string, o *Options) { o.Sources[0].Kind = "other" },
		"no cites.json": func(_, pkg string, _ *Options) { _ = os.Remove(filepath.Join(pkg, controls.CitesFile)) },
		"bad cites.json": func(_, pkg string, _ *Options) {
			_ = os.WriteFile(filepath.Join(pkg, controls.CitesFile), []byte("{"), 0o600)
		},
		"no package dir": func(_, _ string, o *Options) { o.PackageDir = filepath.Join(o.PackageDir, "missing") },
		"PDF unreadable": func(_, _ string, o *Options) {
			o.PDFText = func(context.Context, []byte) (string, error) { return "", errors.New("no") }
		},
		"PDF not a table": func(_, _ string, o *Options) {
			o.PDFText = func(context.Context, []byte) (string, error) { return "text", nil }
		},
		"a kind missing": func(_, _ string, o *Options) {
			o.Sources = slices.DeleteFunc(o.Sources, func(s Source) bool { return s.Kind == KindCrosswalk })
		},
		"CCI not listed": func(src string, _ string, o *Options) {
			b := zipOf(t, map[string]string{"U_CCI_List.xml": strings.ReplaceAll(cciListXML, "CCI-000044", "CCI-000045")})
			if err := os.WriteFile(filepath.Join(src, "cci.zip"), b, 0o600); err != nil {
				t.Fatal(err)
			}
			for i := range o.Sources {
				if o.Sources[i].File == "cci.zip" {
					sum := sha256.Sum256(b)
					o.Sources[i].SHA256 = hex.EncodeToString(sum[:])
				}
			}
		},
		"stale read match": func(_, _ string, o *Options) {
			o.reads = append(o.reads, readMatch{"WN11-00-000099", "win10-v3r6", "WN10-00-000030", "x"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			src, list := sources(t)
			pkg := packageDir(t)
			o := Options{SourceDir: src, PackageDir: pkg, Sources: list, PDFText: fakePDF,
				reads: []readMatch{{"WN11-00-000030", "win10-v3r6", "WN10-00-000030", "read"}}}
			change(src, pkg, &o)
			if err := Run(context.Background(), o); err == nil {
				t.Error("Run accepted it")
			}
		})
	}
}

func TestPinned(t *testing.T) {
	keys := map[string]bool{}
	for _, s := range Pinned {
		if len(s.SHA256) != 64 || !strings.HasPrefix(s.URL, "https://") || !strings.HasSuffix(s.URL, s.File) || s.Name == "" || s.Version == "" {
			t.Errorf("incomplete source %+v", s)
		}
		if keys[s.Key] {
			t.Errorf("key %s twice", s.Key)
		}
		keys[s.Key] = true
	}
	for release, targets := range Equivalents {
		for _, r := range append([]string{release}, targets...) {
			if !keys[r] {
				t.Errorf("Equivalents names %s, which is not pinned", r)
			}
		}
	}
	for _, m := range readMatches {
		if !slices.Contains(Equivalents[releaseOfRule(m.Rule)], m.Release) {
			t.Errorf("read match %+v is between releases Equivalents does not pair", m)
		}
	}
}

func releaseOfRule(id string) string {
	switch {
	case strings.HasPrefix(id, "WN11-"):
		return "win11-v2r11"
	case strings.HasPrefix(id, "WN25-"):
		return "ws2025-v1r4"
	}
	return ""
}

// TestPDFToText: pdftotext fails on what is not a PDF, or is not installed.
func TestPDFToText(t *testing.T) {
	if _, err := pdftotext(context.Background(), []byte("not a PDF")); err == nil {
		t.Error("pdftotext read something that is not a PDF")
	}
}
