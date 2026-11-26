package library_test

import (
	"encoding/json"
	"io/fs"
	"strings"
	"testing"

	"github.com/paulmataruso/easyrmm/server/internal/compliance"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/content"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/library"
	"github.com/paulmataruso/easyrmm/server/internal/jobs"
)

func embeddedLibrary(t *testing.T) []library.File {
	t.Helper()
	var out []library.File
	for _, p := range []string{"controls/windows.json", "controls/linux.json"} {
		b, err := fs.ReadFile(content.FS, p)
		if err != nil {
			t.Fatal(err)
		}
		f, err := library.Parse(b)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		out = append(out, f)
	}
	return out
}

// Every control maps to a real check: the setting it names is in the
// hardening scripts' own list, in the module it says, and every setting the
// scripts check has a control.
func TestEveryControlMapsToARealCheck(t *testing.T) {
	files := embeddedLibrary(t)
	byRef := map[string]bool{}
	for _, f := range files {
		if errs := library.Validate(f); len(errs) > 0 {
			t.Errorf("%s: %v", f.Library.Key, errs)
		}
		for _, c := range f.Controls {
			var ref compliance.HardeningRef
			if err := json.Unmarshal(c.ExecutorRef, &ref); err != nil {
				t.Fatal(err)
			}
			byRef[ref.Platform+"/"+ref.Setting] = true
		}
	}
	for _, s := range jobs.WindowsSettingCatalog() {
		if !byRef["windows/"+s.ID] {
			t.Errorf("Windows setting %s has no control (run go run ./server/cmd/genlibrary)", s.ID)
		}
	}
	for _, s := range jobs.LinuxSettingCatalog() {
		if !byRef["linux/"+s.ID] {
			t.Errorf("Linux setting %s has no control (run go run ./server/cmd/genlibrary)", s.ID)
		}
	}
	if len(byRef) != len(jobs.WindowsSettingCatalog())+len(jobs.LinuxSettingCatalog()) {
		t.Errorf("%d controls for %d settings", len(byRef), len(jobs.WindowsSettingCatalog())+len(jobs.LinuxSettingCatalog()))
	}
}

func TestGeneratedLibraryIsWhatIsCommitted(t *testing.T) {
	for name, gen := range map[string]library.File{"controls/windows.json": library.GenerateWindows(), "controls/linux.json": library.GenerateLinux()} {
		want, _ := json.MarshalIndent(gen, "", "  ")
		got, err := fs.ReadFile(content.FS, name)
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(string(got)) != string(want) {
			t.Errorf("%s is out of date: run go run ./server/cmd/genlibrary, then go run ./server/cmd/packlint -update", name)
		}
	}
}

func TestValidateRefusesWhatIsNotARealCheck(t *testing.T) {
	good := library.GenerateWindows()
	mutate := func(f func(c *compliance.Control)) []error {
		l := library.File{Library: good.Library, Controls: []compliance.Control{good.Controls[0]}}
		f(&l.Controls[0])
		return library.Validate(l)
	}
	cases := map[string]func(c *compliance.Control){
		"unknown setting": func(c *compliance.Control) {
			c.ExecutorRef = json.RawMessage(`{"platform":"windows","module":"accounts","setting":"accounts-nope"}`)
		},
		"wrong module": func(c *compliance.Control) {
			c.ExecutorRef = json.RawMessage(`{"platform":"windows","module":"firewall","setting":"accounts-history"}`)
		},
		"linux setting under windows": func(c *compliance.Control) {
			c.ExecutorRef = json.RawMessage(`{"platform":"windows","module":"ssh","setting":"ssh-x11-forwarding"}`)
		},
		"unknown platform": func(c *compliance.Control) {
			c.ExecutorRef = json.RawMessage(`{"platform":"macos","module":"a","setting":"a-b"}`)
		},
		"bad id":                func(c *compliance.Control) { c.ID = "Win.Bad" },
		"derived from content":  func(c *compliance.Control) { c.Provenance.DerivedFromContent = true },
		"no author":             func(c *compliance.Control) { c.Provenance.Author = "" },
		"licence class unknown": func(c *compliance.Control) { c.LicenceClass = "MIT" },
		"more restrictive than library": func(c *compliance.Control) {
			c.LicenceClass, c.Provenance.LicenceClass = compliance.ClassRestricted, compliance.ClassRestricted
		},
		"fix without warning":    func(c *compliance.Control) { c.WarningID = "" },
		"fix without apply ref":  func(c *compliance.Control) { c.ApplyRef = json.RawMessage("null") },
		"report only with a fix": func(c *compliance.Control) { c.RiskTier = compliance.TierReport },
		"bad severity":           func(c *compliance.Control) { c.Severity = "urgent" },
		"version zero":           func(c *compliance.Control) { c.Version = 0 },
	}
	for name, f := range cases {
		if errs := mutate(f); len(errs) == 0 {
			t.Errorf("%s: no error", name)
		}
	}
	if errs := mutate(func(*compliance.Control) {}); len(errs) != 0 {
		t.Errorf("the unchanged control: %v", errs)
	}
}

func TestBuildRefusesRepeatedIDs(t *testing.T) {
	f := library.GenerateLinux()
	if _, err := library.Build(f, f); err == nil {
		t.Error("two files with the same control were accepted")
	}
	idx, err := library.Build(embeddedLibrary(t)...)
	if err != nil || len(idx) != len(jobs.WindowsSettingCatalog())+len(jobs.LinuxSettingCatalog()) {
		t.Errorf("%d controls, %v", len(idx), err)
	}
}

// Tiers follow the scripts' own tiers for Windows, and only report-only
// controls have no fix.
func TestTiersAndFixes(t *testing.T) {
	win := library.GenerateWindows()
	tiers := map[string]int{}
	for _, c := range win.Controls {
		tiers[c.RiskTier]++
		if (c.RiskTier == compliance.TierReport) == c.ApplySupported {
			t.Errorf("%s: tier %s with apply %v", c.ID, c.RiskTier, c.ApplySupported)
		}
	}
	if tiers["T0"] == 0 || tiers["T1"] == 0 || tiers["T2"] == 0 || tiers["T3"] == 0 {
		t.Errorf("windows tiers %v", tiers)
	}
	for _, c := range win.Controls {
		if c.ID == "win.rdp.nla" && c.RiskTier != compliance.TierDangerous {
			t.Errorf("rdp nla is tier %s, want T3 (it can cut access)", c.RiskTier)
		}
		if c.ID == "win.firewall.public-enabled" && c.RiskTier != compliance.TierDangerous {
			t.Errorf("a firewall profile is tier %s, want T3", c.RiskTier)
		}
	}
}
