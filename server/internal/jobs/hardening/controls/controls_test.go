package controls

import (
	"bytes"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
)

// regenerate is the command that rewrites related.json.
const regenerate = "go run ./server/internal/jobs/hardening/controls/cmd/gencontrols"

// TestRelatedIsGenerated is CI's "regenerated and compared": the embedded
// tables are what the generator makes from cites.json and data/ now.
func TestRelatedIsGenerated(t *testing.T) {
	got, err := Generate(os.DirFS("."))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, relatedJSON) {
		t.Fatalf("related.json is not what cites.json and data/ give; run %s", regenerate)
	}
}

func repoCites(t *testing.T) Cites {
	t.Helper()
	b, err := os.ReadFile(CitesFile)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseCites(b)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func repoSTIG(t *testing.T, release string) map[string]stigRule {
	t.Helper()
	rules, err := loadSTIG(os.DirFS("."), release)
	if err != nil {
		t.Fatal(err)
	}
	return rules
}

// TestCitedRulesExist is ADR-0054's STIG ID test: a rule ID a module cites
// that is not in the STIG release it names fails.
func TestCitedRulesExist(t *testing.T) {
	c := repoCites(t)
	for _, m := range c.Modules {
		for _, id := range m.All() {
			release, ok := c.ReleaseOf(id)
			if !ok {
				t.Errorf("%s: %s names no release", m.Module, id)
				continue
			}
			if _, ok := repoSTIG(t, release)[id]; !ok {
				t.Errorf("%s cites %s, which is not in %s", m.Module, id, STIGFile(release))
			}
		}
	}
}

// equivalentsFor names, for a release whose rules are cited, the releases
// data/equivalents.csv gives each of them a row in.
var equivalentsFor = map[string][]string{
	"win11-v2r11": {"win10-v3r6"},
	"ws2025-v1r4": {"ws2022-v2r11", "ws2019-v3r9", "ws2016-v2r10"},
}

// TestEquivalentsExist checks data/equivalents.csv the same way: every
// rule in it is in the release it names, and every Windows 11 and Server
// 2025 rule cited has a row for each older release.
func TestEquivalentsExist(t *testing.T) {
	c := repoCites(t)
	rows, err := readCSV(os.DirFS("."), "data/equivalents.csv", []string{"rule", "release", "equivalent", "matchedBy"})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[[2]string]bool{}
	for _, r := range rows {
		rule, release, eq, how := r[0], r[1], r[2], r[3]
		source, ok := c.ReleaseOf(rule)
		if !ok || !slices.Contains(equivalentsFor[source], release) {
			t.Errorf("%s: no equivalents are kept from %q to %q", rule, source, release)
			continue
		}
		if _, ok := repoSTIG(t, source)[rule]; !ok {
			t.Errorf("%s is not in %s", rule, STIGFile(source))
		}
		if eq != "" {
			if _, ok := repoSTIG(t, release)[eq]; !ok {
				t.Errorf("%s's equivalent %s is not in %s", rule, eq, STIGFile(release))
			}
		}
		if (eq == "") != (how == "") {
			t.Errorf("%s in %s: equivalent %q matched by %q", rule, release, eq, how)
		}
		key := [2]string{rule, release}
		if seen[key] {
			t.Errorf("%s in %s twice", rule, release)
		}
		seen[key] = true
	}
	for _, m := range c.Modules {
		for _, id := range m.All() {
			source, _ := c.ReleaseOf(id)
			for _, release := range equivalentsFor[source] {
				if !seen[[2]string{id, release}] {
					t.Errorf("%s cites %s, which has no row for %s in data/equivalents.csv", m.Module, id, release)
				}
			}
		}
	}
}

// TestAuditReportsEveryAURule: ADR-0054's audit module reports "the WN11-AU
// rules" and "the WN25-AU rules", every one in the release.
func TestAuditReportsEveryAURule(t *testing.T) {
	c := repoCites(t)
	i := slices.IndexFunc(c.Modules, func(m CitedModule) bool { return m.Module == "audit" })
	if i < 0 {
		t.Fatal("no audit module")
	}
	reports := c.Modules[i].Reports
	for prefix, release := range map[string]string{"WN11-AU-": "win11-v2r11", "WN25-AU-": "ws2025-v1r4"} {
		for _, id := range slices.Sorted(maps.Keys(repoSTIG(t, release))) {
			if strings.HasPrefix(id, prefix) && !slices.Contains(reports, id) {
				t.Errorf("audit does not report %s", id)
			}
		}
	}
}

func TestFor(t *testing.T) {
	r, ok := For("accounts")
	if !ok {
		t.Fatal("no accounts")
	}
	if !slices.Contains(r.SP80053R5, Control{ID: "AC-7", Title: "Unsuccessful Logon Attempts"}) {
		t.Errorf("accounts SP 800-53 = %v, want AC-7 with its title", r.SP80053R5)
	}
	if !slices.Contains(r.SP800171R2, "3.1.8") || !slices.Contains(r.SP800171R3, "03.01.08") || !slices.Contains(r.ISO27001, "A.8.5") {
		t.Errorf("accounts = %+v", r)
	}
	r.SP80053R5[0].ID = "changed"
	r.SP800171R2[0] = "changed"
	if again, _ := For("accounts"); again.SP80053R5[0].ID == "changed" || again.SP800171R2[0] == "changed" {
		t.Error("For returns the tables' own slices")
	}

	none, ok := For("tls")
	if !ok || len(none.SP80053R5)+len(none.SP800171R2)+len(none.SP800171R3)+len(none.ISO27001) != 0 {
		t.Errorf("tls = %+v, %v; want known and empty", none, ok)
	}
	if none.SP80053R5 == nil || none.ISO27001 == nil {
		t.Error("empty lists are nil, so the console would get null")
	}
	if _, ok := For("no-such-module"); ok {
		t.Error("For knows a module that does not exist")
	}
}

func TestModules(t *testing.T) {
	c := repoCites(t)
	var want []string
	for _, m := range c.Modules {
		want = append(want, m.Module)
	}
	got := Modules()
	if !slices.Equal(got, want) {
		t.Errorf("Modules() = %v, want cites.json's order %v", got, want)
	}
	for _, m := range []string{"accounts", "firewall", "defender", "asr", "smb", "smb-signing", "ntlm", "wdigest", "lsa-protection",
		"name-resolution", "powershell", "rdp", "uac", "autoplay", "anonymous", "winrm", "printing", "features", "tls",
		"audit", "device-guard", "bitlocker", "laps"} {
		if !slices.Contains(got, m) {
			t.Errorf("no %s", m)
		}
	}
}

func TestSources(t *testing.T) {
	s := Sources()
	var names []string
	for _, src := range s {
		if src.Name == "" || src.Version == "" || src.Date == "" || !strings.HasPrefix(src.URL, "https://") {
			t.Errorf("incomplete source %+v", src)
		}
		names = append(names, src.Name+" "+src.Version)
	}
	joined := strings.Join(names, "\n")
	for _, want := range []string{"Windows 11 V2R11", "Windows Server 2025 V1R4", "Defender Antivirus V2R10", "Firewall with Advanced Security V2R2",
		"CCI) list 2025-01-23", "SP 800-53 Rev. 5 catalog (OSCAL) 5.2.0", "800-171 Rev. 2", "800-171 Rev. 3", "ISO 27001-2022"} {
		if !strings.Contains(joined, want) {
			t.Errorf("sources lack %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "Windows 10") || strings.Contains(joined, "Server 2016") {
		t.Errorf("sources name a release the tables are not built from:\n%s", joined)
	}
	s[0].Name = "changed"
	if Sources()[0].Name == "changed" {
		t.Error("Sources returns the tables' own slice")
	}
}

func TestParseTable(t *testing.T) {
	for _, b := range []string{"", "{", `{"sources": [], "modules": []}`} {
		if _, err := parseTable([]byte(b)); err == nil {
			t.Errorf("parseTable(%q) accepted it", b)
		}
	}
	defer func() {
		if recover() == nil {
			t.Error("mustParse did not panic on a broken table")
		}
	}()
	mustParse([]byte("{"))
}
