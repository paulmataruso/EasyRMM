package controls

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

// fixture is a small set of inputs whose tables can be worked out by hand.
func fixture() fstest.MapFS {
	return fstest.MapFS{
		"cites.json": {Data: []byte(`{
  "releases": {"WN11": "win11-test", "WNDF-AV": "av-test"},
  "modules": [
    {"module": "one", "meets": ["WN11-AC-000005"], "differs": ["WNDF-AV-000001"], "notSet": ["WN11-SO-000010"]},
    {"module": "report", "reports": ["WN11-SO-000010"]},
    {"module": "empty", "meets": [], "differs": [], "notSet": []}
  ]
}`)},
		"data/stig-win11-test.csv": {Data: []byte("version,rule,ccis\n" +
			"WN11-AC-000005,SV-1r1_rule,CCI-000044\n" +
			"WN11-SO-000010,SV-2r1_rule,CCI-000366;CCI-000804\n")},
		"data/stig-av-test.csv": {Data: []byte("version,rule,ccis\n" +
			"WNDF-AV-000001,SV-3r1_rule,CCI-001240\n")},
		"data/cci.csv": {Data: []byte("cci,sp80053r5,sp80053r4\n" +
			"CCI-000044,AC-7 a,AC-7 a\n" +
			"CCI-000366,CM-6 b,CM-6 b\n" +
			"CCI-000804,IA-8,IA-8\n" +
			"CCI-001240,SI-3 (2),SI-3 (2)\n")},
		"data/sp800-53r5-controls.csv": {Data: []byte("control,title\n" +
			"AC-7,Unsuccessful Logon Attempts\nCM-6,Configuration Settings\nIA-8,Identification and Authentication (Non-organizational Users)\nSI-3,Malicious Code Protection\n")},
		"data/sp800-171r2-appendix-d.csv": {Data: []byte("requirements,controls\n" +
			"3.1.8,AC-7\n3.4.1;3.4.2,CM-2;CM-6\n3.14.4;3.14.5,SI-3\n3.5.3,IA-2(1)\n")},
		"data/sp800-171r3-source-controls.csv": {Data: []byte("requirement,controls\n" +
			"03.01.08,AC-07\n03.04.02,CM-06\n03.14.02,SI-03;SI-03(02)\n")},
		"data/iso27001-2022-from-sp800-53r5.csv": {Data: []byte("control,annexA\n" +
			"AC-07,A.8.5\nCM-06,A.8.9\nSI-03,A.8.7\nSI-03(02),A.8.99\nIA-08,A.5.16\nIA-08,A.5.10\n")},
		"data/sources.csv": {Data: []byte("key,kind,name,version,date,url,sha256,note\n" +
			"win11-test,stig,DISA STIG: test,V1R1,2026-01-01,https://example.invalid/a,00,\n" +
			"win10-test,stig,DISA STIG: older,V1R1,2026-01-01,https://example.invalid/b,00,\n" +
			"cci-list,cci,CCI list,2025-01-23,2025-01-23,https://example.invalid/c,00,a caveat\n")},
	}
}

func generated(t *testing.T, fsys fstest.MapFS) table {
	t.Helper()
	b, err := Generate(fsys)
	if err != nil {
		t.Fatal(err)
	}
	var tb table
	if err := json.Unmarshal(b, &tb); err != nil {
		t.Fatal(err)
	}
	return tb
}

func TestGenerateFollowsTheADRsRules(t *testing.T) {
	tb := generated(t, fixture())
	if len(tb.Modules) != 3 {
		t.Fatalf("modules = %+v", tb.Modules)
	}
	one := tb.Modules[0]
	// Meets and differs count; not set (WN11-SO-000010) does not.
	wantR5 := []Control{{"AC-7", "Unsuccessful Logon Attempts"}, {"SI-3", "Malicious Code Protection"}}
	if !slices.Equal(one.SP80053R5, wantR5) {
		t.Errorf("SP 800-53 = %v, want %v", one.SP80053R5, wantR5)
	}
	// SI-3 (2) names the enhancement, which no Rev. 2 row lists.
	if want := []string{"3.1.8"}; !slices.Equal(one.SP800171R2, want) {
		t.Errorf("Rev. 2 = %v, want %v", one.SP800171R2, want)
	}
	if want := []string{"03.01.08", "03.14.02"}; !slices.Equal(one.SP800171R3, want) {
		t.Errorf("Rev. 3 = %v, want %v", one.SP800171R3, want)
	}
	// Base controls only: SI-3(2)'s A.8.99 is not taken.
	if want := []string{"A.8.5", "A.8.7"}; !slices.Equal(one.ISO27001, want) {
		t.Errorf("ISO = %v, want %v", one.ISO27001, want)
	}

	report := tb.Modules[1]
	if want := []Control{{"CM-6", "Configuration Settings"}, {"IA-8", "Identification and Authentication (Non-organizational Users)"}}; !slices.Equal(report.SP80053R5, want) {
		t.Errorf("report SP 800-53 = %v", report.SP80053R5)
	}
	// A shared row gives all its requirements.
	if want := []string{"3.4.1", "3.4.2"}; !slices.Equal(report.SP800171R2, want) {
		t.Errorf("report Rev. 2 = %v, want %v", report.SP800171R2, want)
	}
	if want := []string{"A.5.10", "A.5.16", "A.8.9"}; !slices.Equal(report.ISO27001, want) {
		t.Errorf("report ISO = %v, want %v", report.ISO27001, want)
	}

	empty := tb.Modules[2]
	if empty.SP80053R5 == nil || empty.SP800171R2 == nil || empty.SP800171R3 == nil || empty.ISO27001 == nil {
		t.Errorf("empty module has null lists: %+v", empty)
	}

	// Older releases that only give equivalents are not the tables' sources.
	if len(tb.Sources) != 2 || tb.Sources[0].Name != "DISA STIG: test" || tb.Sources[1].Note != "a caveat" {
		t.Errorf("sources = %+v", tb.Sources)
	}
}

func TestGenerateIsDeterministic(t *testing.T) {
	a, err := Generate(fixture())
	if err != nil {
		t.Fatal(err)
	}
	for range 5 {
		b, err := Generate(fixture())
		if err != nil {
			t.Fatal(err)
		}
		if string(a) != string(b) {
			t.Fatal("Generate gave different bytes for the same files")
		}
	}
	if !strings.HasSuffix(string(a), "}\n") {
		t.Error("no final newline")
	}
}

func TestGenerateRefuses(t *testing.T) {
	for name, change := range map[string]func(fstest.MapFS){
		"no cites.json":  func(f fstest.MapFS) { delete(f, "cites.json") },
		"cites not JSON": func(f fstest.MapFS) { set(f, "cites.json", "{") },
		"unknown field": func(f fstest.MapFS) {
			set(f, "cites.json", `{"releases": {"WN11": "x"}, "modules": [{"module": "a"}], "extra": 1}`)
		},
		"no modules":     func(f fstest.MapFS) { set(f, "cites.json", `{"releases": {"WN11": "x"}, "modules": []}`) },
		"unnamed module": func(f fstest.MapFS) { set(f, "cites.json", `{"releases": {"WN11": "x"}, "modules": [{"module": ""}]}`) },
		"module twice": func(f fstest.MapFS) {
			set(f, "cites.json", `{"releases": {"WN11": "x"}, "modules": [{"module": "a"}, {"module": "a"}]}`)
		},
		"reports and sets": func(f fstest.MapFS) {
			replace(f, "cites.json", `"reports": [`, `"meets": ["WN11-AC-000005"], "reports": [`)
		},
		"rule twice": func(f fstest.MapFS) {
			replace(f, "cites.json", `"meets": ["WN11-AC-000005"]`, `"meets": ["WN11-AC-000005", "WN11-AC-000005"]`)
		},
		"no release":          func(f fstest.MapFS) { replace(f, "cites.json", `"WN11-AC-000005"]`, `"WN10-AC-000005"]`) },
		"rule not in release": func(f fstest.MapFS) { replace(f, "cites.json", `"WN11-AC-000005"]`, `"WN11-AC-000999"]`) },
		"no STIG file":        func(f fstest.MapFS) { delete(f, "data/stig-av-test.csv") },
		"STIG rule twice":     func(f fstest.MapFS) { appendTo(f, "data/stig-av-test.csv", "WNDF-AV-000001,SV-3r1_rule,CCI-001240\n") },
		"STIG rule unnamed":   func(f fstest.MapFS) { appendTo(f, "data/stig-av-test.csv", "WNDF-AV-000002,,CCI-001240\n") },
		"empty data file":     func(f fstest.MapFS) { set(f, "data/cci.csv", "") },
		"wrong header":        func(f fstest.MapFS) { set(f, "data/cci.csv", "cci,rev5,rev4\n") },
		"bad header CSV":      func(f fstest.MapFS) { set(f, "data/cci.csv", "\"cci\n") },
		"bad row":             func(f fstest.MapFS) { appendTo(f, "data/cci.csv", "CCI-1,AC-1\n") },
		"CCI not listed":      func(f fstest.MapFS) { replace(f, "data/cci.csv", "CCI-000044,", "CCI-000045,") },
		"bad Rev. 5 ref":      func(f fstest.MapFS) { replace(f, "data/cci.csv", "AC-7 a,AC-7 a", "x,AC-7 a") },
		"bad Rev. 4 ref":      func(f fstest.MapFS) { replace(f, "data/cci.csv", "AC-7 a,AC-7 a", "AC-7 a,x") },
		"no title":            func(f fstest.MapFS) { replace(f, "data/sp800-53r5-controls.csv", "AC-7,", "AC-8,") },
		"title of an enhancement": func(f fstest.MapFS) {
			appendTo(f, "data/sp800-53r5-controls.csv", "AC-7(1),Enhancement\n")
		},
		"bad appendix D control": func(f fstest.MapFS) { appendTo(f, "data/sp800-171r2-appendix-d.csv", "3.1.1,x\n") },
		"bad Rev. 3 control":     func(f fstest.MapFS) { appendTo(f, "data/sp800-171r3-source-controls.csv", "03.01.01,x\n") },
		"bad ISO control":        func(f fstest.MapFS) { appendTo(f, "data/iso27001-2022-from-sp800-53r5.csv", "x,A.5.1\n") },
		"no titles file":         func(f fstest.MapFS) { delete(f, "data/sp800-53r5-controls.csv") },
		"no appendix D":          func(f fstest.MapFS) { delete(f, "data/sp800-171r2-appendix-d.csv") },
		"no Rev. 3":              func(f fstest.MapFS) { delete(f, "data/sp800-171r3-source-controls.csv") },
		"no crosswalk":           func(f fstest.MapFS) { delete(f, "data/iso27001-2022-from-sp800-53r5.csv") },
		"no sources":             func(f fstest.MapFS) { delete(f, "data/sources.csv") },
	} {
		t.Run(name, func(t *testing.T) {
			f := fixture()
			change(f)
			if _, err := Generate(f); err == nil {
				t.Error("Generate accepted it")
			}
		})
	}
}

func set(f fstest.MapFS, name, data string) { f[name] = &fstest.MapFile{Data: []byte(data)} }

func appendTo(f fstest.MapFS, name, data string) { set(f, name, string(f[name].Data)+data) }

func replace(f fstest.MapFS, name, old, new string) {
	s := string(f[name].Data)
	if !strings.Contains(s, old) {
		panic(name + " has no " + old)
	}
	set(f, name, strings.Replace(s, old, new, 1))
}

func TestElement(t *testing.T) {
	for ref, want := range map[string][2]string{
		"AC-7 a":       {"AC-7", "AC-7"},
		"AC-6 (9)":     {"AC-6", "AC-6(9)"},
		"IA-5 (1) (a)": {"IA-5", "IA-5(1)"},
		"CP-9 (a)":     {"CP-9", "CP-9"},
		"CP-4 (4)4":    {"CP-4", "CP-4(4)"},
		"AC-02(03)":    {"AC-2", "AC-2(3)"},
		"AC-07":        {"AC-7", "AC-7"},
		" AC-17(2) ":   {"AC-17", "AC-17(2)"},
		"SI-4(4)":      {"SI-4", "SI-4(4)"},
	} {
		base, el, ok := element(ref)
		if !ok || base != want[0] || el != want[1] {
			t.Errorf("element(%q) = %q, %q, %v; want %v", ref, base, el, ok, want)
		}
	}
	for _, ref := range []string{"", "A.8.5", "ac-7", "AC7"} {
		if _, _, ok := element(ref); ok {
			t.Errorf("element(%q) accepted it", ref)
		}
	}
}

func TestCompareNatural(t *testing.T) {
	in := []string{"AC-17", "AC-2", "3.1.10", "3.1.8", "A.8.10", "A.5.16", "A.8.9", "03.01.08", "AC-02", "SC-7", "3.14.1"}
	got := sortedSet(append(in, "AC-2"))
	want := []string{"03.01.08", "3.1.8", "3.1.10", "3.14.1", "A.5.16", "A.8.9", "A.8.10", "AC-02", "AC-2", "AC-17", "SC-7"}
	if !slices.Equal(got, want) {
		t.Errorf("sortedSet = %v, want %v", got, want)
	}
	if compareNatural("AC-2", "AC-2") != 0 || compareNatural("AC", "AC-2") >= 0 {
		t.Error("compareNatural on equal and prefix strings")
	}
}

func TestCitedModule(t *testing.T) {
	m := CitedModule{Meets: []string{"a"}, Differs: []string{"b"}, NotSet: []string{"c"}}
	if got := m.Counted(); !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("Counted = %v", got)
	}
	if got := m.All(); !slices.Equal(got, []string{"a", "b", "c"}) {
		t.Errorf("All = %v", got)
	}
	r := CitedModule{Reports: []string{"d"}}
	if got := r.Counted(); !slices.Equal(got, []string{"d"}) {
		t.Errorf("report Counted = %v", got)
	}
	c := Cites{Releases: map[string]string{"WNDF": "short", "WNDF-AV": "long"}}
	if got, ok := c.ReleaseOf("WNDF-AV-000001"); !ok || got != "long" {
		t.Errorf("ReleaseOf takes %q, want the longest prefix", got)
	}
	if _, ok := c.ReleaseOf("WN11-AC-000005"); ok {
		t.Error("ReleaseOf found a release for an unknown prefix")
	}
}
