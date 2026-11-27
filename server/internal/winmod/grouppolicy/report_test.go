package grouppolicy

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func sample(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/sample/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func find(nodes []Node, label string) *Node {
	for i := range nodes {
		if nodes[i].Label == label {
			return &nodes[i]
		}
		if n := find(nodes[i].Children, label); n != nil {
			return n
		}
	}
	return nil
}

func ext(c Config, name string) *Extension {
	for i := range c.Extensions {
		if c.Extensions[i].Name == name {
			return &c.Extensions[i]
		}
	}
	return nil
}

// TestReportParserOnWindows parses sample Get-GPOReport XML (the CI's Windows job runs every test named ...OnWindows; the
// parser is plain Go, so it also runs everywhere else). No domain is needed.
func TestReportParserOnWindows(t *testing.T) {
	r, err := ParseReport(sample(t, "gpo_report.xml"), 4000)
	if err != nil {
		t.Fatal(err)
	}
	if r.ID != "8f2c1b3a-5d4e-4a7b-9c1d-2e3f4a5b6c7d" || r.Name != "Workstation baseline" {
		t.Errorf("identity: %q %q", r.ID, r.Name)
	}
	if !r.Computer.Enabled || r.User.Enabled || r.Computer.Version != (Version{4, 4}) || r.User.Version != (Version{2, 2}) {
		t.Errorf("halves: %+v %+v", r.Computer, r.User)
	}
	reg := ext(r.Computer, "Registry")
	if reg == nil || reg.Kind != "RegistrySettings" || len(reg.Settings) != 2 {
		t.Fatalf("registry extension: %+v", reg)
	}
	p := reg.Settings[0]
	if p.Label != "Turn off Windows Defender Antivirus" || p.State != "Disabled" {
		t.Errorf("a policy keeps its name and state: %+v", p)
	}
	if n := find(reg.Settings, "Maximum Log Size (KB)"); n == nil || find(n.Children, "Value") == nil || find(n.Children, "Value").Value != "196608" {
		t.Errorf("a policy's element keeps its value: %+v", n)
	}
	if sec := ext(r.Computer, "Security"); sec == nil || find(sec.Settings, "Minimum Password Length") == nil && find(sec.Settings, "MinimumPasswordLength") == nil && find(sec.Settings, "Account") == nil {
		t.Errorf("security settings: %+v", sec)
	}
	if sc := ext(r.Computer, "Scripts"); sc == nil || find(sc.Settings, "Command") == nil {
		t.Errorf("scripts: %+v", sc)
	}
	if si := ext(r.Computer, "Software Installation"); si == nil || !si.NoAPI {
		t.Errorf("Software Installation is marked read-only for good: %+v", si)
	}
	if reg.NoAPI {
		t.Error("registry settings are not marked as having no API")
	}
	if len(r.Links) != 2 || r.Links[1].Path != "corp.example.test" || !r.Links[1].Enforced || !r.Links[0].Enabled {
		t.Errorf("links: %+v", r.Links)
	}
	// A stored preference password is a finding and its value is never kept.
	if len(r.Findings) != 1 || !strings.Contains(r.Findings[0], "cpassword") {
		t.Errorf("findings: %v", r.Findings)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "j1Uyj3Vx8TY9") {
		t.Error("the stored password's value is in the parsed report")
	}
	if !strings.Contains(string(b), "stored password hidden") {
		t.Error("the stored password's place is not marked")
	}
}

func TestReportOfAnUnsavedGPO(t *testing.T) {
	r, err := ParseReport(sample(t, "gpo_report_empty.xml"), 4000)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Computer.Extensions) != 0 || len(r.User.Extensions) != 0 || len(r.Findings) != 0 || r.Name != "New GPO" {
		t.Errorf("%+v", r)
	}
}

func TestReportRefusesWhatIsNotAReport(t *testing.T) {
	for name, in := range map[string]string{
		"not xml":  "<GPO><Name>x",
		"wrong":    `<html><body/></html>`,
		"deep":     strings.Repeat("<a>", 200) + strings.Repeat("</a>", 200),
		"empty":    "",
		"entities": `<!DOCTYPE x [<!ENTITY a "b">]><GPO>&a;</GPO>`,
	} {
		if r, err := ParseReport([]byte(in), 100); err == nil && name != "entities" {
			t.Errorf("%s: accepted: %+v", name, r)
		}
	}
}

func TestReportBudgetCutsAndSaysSo(t *testing.T) {
	r, err := ParseReport(sample(t, "gpo_report.xml"), 10)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Truncated || r.Settings > 10 || r.Total <= r.Settings {
		t.Errorf("truncated=%v settings=%d total=%d", r.Truncated, r.Settings, r.Total)
	}
}

func gz(t *testing.T, b []byte) string {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write(b)
	_ = w.Close()
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func TestDecodeReportFromTheScriptsEnvelope(t *testing.T) {
	env, _ := json.Marshal(map[string]string{"id": "8f2c1b3a-5d4e-4a7b-9c1d-2e3f4a5b6c7d", "name": "Workstation baseline", "xmlGzip": gz(t, sample(t, "gpo_report.xml"))})
	out, err := decodeReport(env)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) > 64<<10 {
		t.Errorf("stored form is %d bytes, over the result limit", len(out))
	}
	var r Report
	if err := json.Unmarshal(out, &r); err != nil || r.Name != "Workstation baseline" {
		t.Errorf("%v %+v", err, r)
	}
	for name, bad := range map[string]string{
		"not base64": `{"id":"x","name":"y","xmlGzip":"!!!"}`,
		"not gzip":   `{"id":"x","name":"y","xmlGzip":"` + base64.StdEncoding.EncodeToString([]byte("plain")) + `"}`,
		"extra":      `{"id":"x","name":"y","xmlGzip":"","other":1}`,
	} {
		if _, err := decodeReport(json.RawMessage(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A big report is cut to fit, not refused.
	var big strings.Builder
	big.WriteString(`<GPO xmlns="http://www.microsoft.com/GroupPolicy/Settings"><Name>Big</Name><Computer><Enabled>true</Enabled><ExtensionData><Extension xmlns:q1="x" xsi:type="q1:RegistrySettings" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">`)
	for i := 0; i < 3000; i++ {
		big.WriteString(`<q1:Policy><q1:Name>Policy number ` + strings.Repeat("x", 40) + `</q1:Name><q1:State>Enabled</q1:State><q1:Category>Some/Category/Path</q1:Category></q1:Policy>`)
	}
	big.WriteString(`</Extension><Name>Registry</Name></ExtensionData></Computer></GPO>`)
	env, _ = json.Marshal(map[string]string{"id": "i", "name": "Big", "xmlGzip": gz(t, []byte(big.String()))})
	out, err = decodeReport(env)
	if err != nil || len(out) > 64<<10 {
		t.Fatalf("big report: %v, %d bytes", err, len(out))
	}
	_ = json.Unmarshal(out, &r)
	if !r.Truncated {
		t.Error("a report cut to fit does not say so")
	}
}

func TestBackupFromOutput(t *testing.T) {
	line := `EASYRMM-WINMOD-RESULT-V1 {"ok":true,"version":1,"data":{"summary":"s","backup":{"backupId":"b","zip":"UEs="}},"error":null}`
	b, err := BackupFromOutput("noise\n" + line + "\n")
	if err != nil || b == nil || b.Zip != "UEs=" {
		t.Fatalf("%v %+v", err, b)
	}
	if b, err := BackupFromOutput(`EASYRMM-WINMOD-RESULT-V1 {"ok":true,"version":1,"data":{"summary":"s","backup":null},"error":null}`); err != nil || b != nil {
		t.Errorf("no backup: %v %+v", err, b)
	}
	if _, err := BackupFromOutput("nothing"); err == nil {
		t.Error("no result line was accepted")
	}
}
