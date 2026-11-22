package powershell

import (
	"slices"
	"strings"
	"testing"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

func TestInstallFolder(t *testing.T) {
	for name, want := range map[string]struct{ preview, ok bool }{
		"7":         {false, true},
		"8":         {false, true},
		"6":         {false, true},
		"7-preview": {true, true},
		"7-Preview": {true, true},
		"Modules":   {},
		"7.4":       {},
		"7-rc":      {},
		"1234":      {},
		"":          {},
	} {
		preview, ok := installFolder(name)
		if preview != want.preview || ok != want.ok {
			t.Errorf("%q: %v %v", name, preview, ok)
		}
	}
}

func TestStorePackage(t *testing.T) {
	for name, want := range map[string]struct {
		version, arch string
		preview, ok   bool
	}{
		"Microsoft.PowerShell_7.6.10.0_x64__8wekyb3d8bbwe":       {"7.6.10.0", agentproto.ArchX64, false, true},
		"Microsoft.PowerShell_7.6.10.0_arm64__8wekyb3d8bbwe":     {"7.6.10.0", agentproto.ArchARM64, false, true},
		"microsoft.powershell_7.4.13.0_X86__8wekyb3d8bbwe":       {"7.4.13.0", agentproto.ArchX86, false, true},
		"Microsoft.PowerShellPreview_7.7.0.5_x64__8wekyb3d8bbwe": {"7.7.0.5", agentproto.ArchX64, true, true},
		// What winget installs for 7.6 (an LTS release) by default.
		"Microsoft.PowerShell-LTS_7.6.10.0_x64__8wekyb3d8bbwe":    {"7.6.10.0", agentproto.ArchX64, false, true},
		"Microsoft.PowerShell-LTS_7.6.10.0_arm64__8wekyb3d8bbwe":  {"7.6.10.0", agentproto.ArchARM64, false, true},
		"Microsoft.PowerShell-Extra_7.6.10.0_x64__8wekyb3d8bbwe":  {},
		"Microsoft.PowerShell_7.6.10.0_riscv__8wekyb3d8bbwe":      {"7.6.10.0", "", false, true},
		"Microsoft.PowerShell_7.6.10.0_neutral_~_8wekyb3d8bbwe":   {},
		"Microsoft.PowerShell_7.6.10.0_x64__0000000000000":        {},
		"Contoso.PowerShell_7.6.10.0_x64__8wekyb3d8bbwe":          {},
		"Microsoft.PowerShell.Extra_7.6.10.0_x64__8wekyb3d8bbwe":  {},
		"Microsoft.PowerShell_7.6.10.0_x64__8wekyb3d8bbwe\\..\\x": {},
	} {
		v, arch, preview, ok := storePackage(name)
		if v != want.version || arch != want.arch || preview != want.preview || ok != want.ok {
			t.Errorf("%q: %q %q %v %v", name, v, arch, preview, ok)
		}
	}
}

func TestVersions(t *testing.T) {
	if v := productVersion("7.6.10 SHA: 0123456789abcdef"); v != "7.6.10" {
		t.Errorf("product version %q", v)
	}
	if v := productVersion("  "); v != "" {
		t.Errorf("an empty product version %q", v)
	}
	for _, bad := range []string{"", "seven", "7..1", "7.-1", "-preview.1", "7.x"} {
		if _, ok := parseVersion(bad); ok {
			t.Errorf("%q parsed", bad)
		}
	}
	// Each is older than the next.
	ordered := []string{"6.2.7", "7.4.13", "7.6.0-preview.4", "7.6.0-rc.1", "7.6", "7.6.0.1", "7.6.9", "7.6.10", "7.10.0"}
	for i := range ordered {
		for j := range ordered {
			a, _ := parseVersion(ordered[i])
			b, ok := parseVersion(ordered[j])
			if !ok {
				t.Fatalf("%q did not parse", ordered[j])
			}
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if got := a.compare(b); got != want {
				t.Errorf("%s against %s: %d, want %d", ordered[i], ordered[j], got, want)
			}
		}
	}
	a, _ := parseVersion("7.6")
	b, _ := parseVersion("7.6.0")
	if a.compare(b) != 0 {
		t.Error("a missing number is not 0")
	}
	if v, err := withEngine("5.1.26100.1", [4]uint16{10, 0, 26100, 7019}); err != nil || v != "5.1.26100.7019" {
		t.Errorf("Windows PowerShell's version %q %v", v, err)
	}
	for _, bad := range []string{"", "5", "5.1-x", "five"} {
		if v, err := withEngine(bad, [4]uint16{10, 0, 1, 2}); err == nil {
			t.Errorf("%q gave %q", bad, v)
		}
	}
}

func TestAssess(t *testing.T) {
	core := func(version, arch string) agentproto.PowerShellInstall {
		return agentproto.PowerShellInstall{Edition: agentproto.EditionCore, Version: version, Arch: arch, Path: `C:\Program Files\PowerShell\7\pwsh.exe`}
	}
	for _, c := range []struct {
		name   string
		in     agentproto.PowerShellInstall
		native string
		reason string
	}{
		{"x64 on x64", core("7.6.10", "x64"), "x64", ""},
		{"ARM64 on ARM64", core("7.6.10", "arm64"), "arm64", ""},
		{"x64 on ARM64, emulated", core("7.4.13", "x64"), "arm64", ""},
		{"version 8", core("8.0.0", "x64"), "x64", ""},
		{"ARM64 on x64", core("7.6.10", "arm64"), "x64", "Built for arm64, which this computer does not run natively: never used for scripts."},
		{"no architecture", core("7.6.10", ""), "x64", "Built for an unknown architecture, which this computer does not run natively: never used for scripts."},
		{"x86", core("7.6.10", "x86"), "x64", reasonX86},
		{"x86 on x86 Windows", core("7.6.10", "x86"), "x86", reasonX86},
		{"version 6", core("6.2.7", "x64"), "x64", "PowerShell 6 is out of support: never used for scripts."},
		{"a prerelease label", core("7.7.0-rc.1", "x64"), "x64", reasonPreview},
		{"no version", core("", "x64"), "x64", reasonVersion},
		{"a Store install", agentproto.PowerShellInstall{Edition: agentproto.EditionCore, Version: "7.6.10", Arch: "x64", Store: true}, "x64", reasonStore},
		{"a preview folder", agentproto.PowerShellInstall{Edition: agentproto.EditionCore, Version: "7.6.10", Arch: "x64", Preview: true}, "x64", reasonPreview},
	} {
		in := c.in
		in.Usable, in.Reason = !c.in.Usable, "left over"
		assess(&in, c.native)
		if in.Usable != (c.reason == "") || in.Reason != c.reason {
			t.Errorf("%s: usable %v, reason %q", c.name, in.Usable, in.Reason)
		}
	}
	pre := agentproto.PowerShellInstall{Edition: agentproto.EditionCore, Version: "7.7.0-preview.5", Arch: "x64"}
	if assess(&pre, "x64"); !pre.Preview {
		t.Error("a prerelease label does not make a preview")
	}
}

// TestOrder: the computer's own architecture before a newer emulated
// build, then the newest version; never a preview, a Store install, x86 or
// version 6; then what blocks a run, then the rest.
func TestOrder(t *testing.T) {
	list := func() []agentproto.PowerShellInstall {
		return []agentproto.PowerShellInstall{
			{Edition: agentproto.EditionCore, Version: "7.7.0-preview.5", Arch: "x64", Path: `C:\Program Files\PowerShell\7-preview\pwsh.exe`, Preview: true},
			{Edition: agentproto.EditionCore, Version: "7.6.10", Arch: "x86", Path: `C:\Program Files (x86)\PowerShell\7\pwsh.exe`},
			{Edition: agentproto.EditionCore, Version: "7.7.0", Arch: "x64", Path: `C:\Program Files\WindowsApps\Microsoft.PowerShell_7.7.0.0_x64__8wekyb3d8bbwe\pwsh.exe`, Store: true},
			{Edition: agentproto.EditionCore, Version: "7.4.13", Arch: "x64", Path: `C:\Program Files\PowerShell\7\pwsh.exe`},
			{Edition: agentproto.EditionCore, Version: "6.2.7", Arch: "x64", Path: `C:\Program Files\PowerShell\6\pwsh.exe`},
			{Edition: agentproto.EditionCore, Version: "7.6.10", Arch: "arm64", Path: `C:\Program Files\PowerShell\8\pwsh.exe`},
			{Edition: agentproto.EditionCore, Version: "8.0.1", Arch: "x64", Path: `C:\Program Files\PowerShell\9\pwsh.exe`},
			{Edition: agentproto.EditionCore, Path: `C:\Program Files\PowerShell\10\pwsh.exe`, Blocked: true, Reason: "Could not be checked: a lock."},
			{Edition: agentproto.EditionDesktop, Version: "5.1.26100.1", Arch: "x64", Path: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, Usable: true},
		}
	}
	// Each install by its folder, x86 for Program Files (x86)'s.
	paths := func(l []agentproto.PowerShellInstall) string {
		var out []string
		for _, p := range l {
			dir := p.Path[:strings.LastIndex(p.Path, `\`)]
			name := dir[strings.LastIndex(dir, `\`)+1:]
			if strings.Contains(dir, "(x86)") {
				name = "x86"
			}
			out = append(out, name)
		}
		return strings.Join(out, " ")
	}
	for native, want := range map[string]string{
		// Windows PowerShell, the usable ones in the order a run tries them,
		// the blocked one, then the rest by path.
		"x64":   `v1.0 9 7 10 x86 6 7-preview 8 Microsoft.PowerShell_7.7.0.0_x64__8wekyb3d8bbwe`,
		"arm64": `v1.0 8 9 7 10 x86 6 7-preview Microsoft.PowerShell_7.7.0.0_x64__8wekyb3d8bbwe`,
	} {
		l := list()
		for i := range l {
			if l[i].Edition == agentproto.EditionCore && l[i].Reason == "" {
				assess(&l[i], native)
			}
		}
		order(l, native)
		if got := paths(l); got != want {
			t.Errorf("on %s:\n got %s\nwant %s", native, got, want)
		}
	}
}

func TestConfigModulePath(t *testing.T) {
	for in, want := range map[string]string{
		`{"PSModulePath": " C:\\Modules ", "ExecutionPolicy": "RemoteSigned"}`: `C:\Modules`,
		`{"ExecutionPolicy": "RemoteSigned"}`:                                  "",
		`{}`:                                                                   "",
	} {
		if got, err := configModulePath([]byte(in)); err != nil || got != want {
			t.Errorf("%s: %q %v", in, got, err)
		}
	}
	for _, bad := range []string{`{"PSModulePath": 5}`, `[]`, `{`, ``} {
		if _, err := configModulePath([]byte(bad)); err == nil {
			t.Errorf("%q was read", bad)
		}
	}
}

func TestExpand(t *testing.T) {
	env := map[string]string{"ProgramData": `C:\ProgramData`, "X": "x"}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	for in, want := range map[string]string{
		`%ProgramData%\Modules;%X%`:  `C:\ProgramData\Modules;x`,
		`100%`:                       `100%`,
		`a%X%b%X`:                    `axb%X`,
		`C:\Program Files\Modules`:   `C:\Program Files\Modules`,
		`%ProgramData%%ProgramData%`: `C:\ProgramDataC:\ProgramData`,
	} {
		if got, err := expand(in, lookup); err != nil || got != want {
			t.Errorf("%q: %q %v, want %q", in, got, err, want)
		}
	}
	// What Windows would leave, and then read on from as another name, is
	// refused, naming it.
	for in, name := range map[string]string{
		`%Unknown%\Modules`: "%Unknown%",
		`%Unknown%X%`:       "%Unknown%",
		`%%X%`:              "%%",
		`a%X%b%Y%`:          "%Y%",
	} {
		if got, err := expand(in, lookup); err == nil || !strings.HasPrefix(err.Error(), name+", which the agent does not expand") {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
}

func TestPerRun(t *testing.T) {
	for name, want := range map[string]bool{
		"TEMP": true, "tmp": true, "Temp": true, "EASYRMM_JOB_ID": true, "easyrmm_x": true,
		"TEMPDIR": false, "PATH": false, "ProgramData": false, "XEASYRMM_": false,
	} {
		if PerRun(name) != want {
			t.Errorf("%s: %v", name, !want)
		}
	}
}

// TestRunLookup: a run's environment as the configured module path sees
// it: what the run sets over the agent's, ignoring case, then the agent's;
// never what each run sets for itself, nor a name with "=".
func TestRunLookup(t *testing.T) {
	agent := map[string]string{"PSModulePath": `C:\Machine`, "ProgramData": `C:\ProgramData`, "TEMP": `C:\Windows\TEMP`, "=C:": `C:\`}
	lookup := runLookup(runEnv(`C:\A;C:\B`), func(k string) (string, bool) { v, ok := agent[k]; return v, ok })
	for name, want := range map[string]string{
		"PSModulePath":                `C:\A;C:\B`,
		"psmodulepath":                `C:\A;C:\B`,
		"POWERSHELL_TELEMETRY_OPTOUT": "1",
		"POWERSHELL_UPDATECHECK":      "Off",
		"ProgramData":                 `C:\ProgramData`,
	} {
		if got, ok := lookup(name); !ok || got != want {
			t.Errorf("%s: %q %v, want %q", name, got, ok, want)
		}
	}
	for _, name := range []string{"TEMP", "TMP", "EASYRMM_RUN_ID", "=C:", "", "Unset"} {
		if got, ok := lookup(name); ok {
			t.Errorf("%s: %q", name, got)
		}
	}
}

// TestSpell: Windows PowerShell's two folders, spelled unlike every value
// Windows PowerShell 5.1 compares a given PSModulePath with, ignoring case:
// as they are, then with a trailing backslash on the first, the second,
// both.
func TestSpell(t *testing.T) {
	folders := []string{`C:\Program Files\WindowsPowerShell\Modules`, `C:\Windows\system32\WindowsPowerShell\v1.0\Modules`}
	plain := folders[0] + ";" + folders[1]
	first := folders[0] + `\;` + folders[1]
	second := plain + `\`
	both := first + `\`
	for _, c := range []struct {
		taken []string
		want  string
	}{
		{nil, plain},
		{[]string{`C:\Other`}, plain},
		{[]string{strings.ToUpper(plain)}, first},
		{[]string{`C:\Account`, plain, `C:\Account;` + plain}, first},
		{[]string{plain, first}, second},
		{[]string{second, plain, strings.ToLower(first)}, both},
		{[]string{first}, plain},
	} {
		if got := spell(folders, c.taken); got != c.want {
			t.Errorf("taken %q: %q, want %q", c.taken, got, c.want)
		}
	}
	if folders[0] != `C:\Program Files\WindowsPowerShell\Modules` {
		t.Errorf("the folders changed: %q", folders)
	}
}

// TestCompared: the computer's and the system account's PSModulePath as
// Windows PowerShell 5.1 reads them, from the agent's environment: an
// expandable value expanded twice, another once, and the two joined; a
// variable the agent's environment does not set, one each run sets for
// itself, and those the agent sets for a run, PSModulePath, which is what
// is being spelled, among them, refused.
func TestCompared(t *testing.T) {
	agent := map[string]string{
		"ProgramFiles": `C:\Program Files`, "SystemRoot": `C:\Windows`, "Twice": `%SystemRoot%\Twice`,
		"PerRunTwice": `%TEMP%`, "PSModulePath": `C:\Agent`, "TEMP": `C:\Windows\TEMP`,
	}
	lookup := func(k string) (string, bool) { v, ok := agent[k]; return v, ok }
	def := &registryPath{value: `%ProgramFiles%\WindowsPowerShell\Modules;%SystemRoot%\system32\WindowsPowerShell\v1.0\Modules`, expandable: true}
	machine := `C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules`
	for _, c := range []struct {
		machine, account *registryPath
		want             []string
	}{
		{nil, nil, nil},
		{def, nil, []string{machine}},
		{nil, &registryPath{value: `%Twice%`}, []string{`%SystemRoot%\Twice`}},
		{def, &registryPath{value: `%Twice%;%ProgramFiles%`, expandable: true}, []string{machine, `C:\Windows\Twice;C:\Program Files`, `C:\Windows\Twice;C:\Program Files;` + machine}},
	} {
		got, err := compared(c.machine, c.account, lookup)
		if err != nil || !slices.Equal(got, c.want) {
			t.Errorf("%+v %+v: %q %v, want %q", c.machine, c.account, got, err, c.want)
		}
	}
	for _, c := range []struct {
		machine, account *registryPath
		want             string
	}{
		{&registryPath{value: `%TEMP%\Modules`, expandable: true}, nil, "the computer's PSModulePath names %TEMP%,"},
		{&registryPath{value: `%PerRunTwice%`, expandable: true}, nil, "the computer's PSModulePath names %TEMP%,"},
		{def, &registryPath{value: `C:\A;%psmodulepath%`}, "the system account's PSModulePath names %psmodulepath%,"},
		{nil, &registryPath{value: `%Unset%`}, "the system account's PSModulePath names %Unset%,"},
		{nil, &registryPath{value: `%POWERSHELL_UPDATECHECK%`}, "the system account's PSModulePath names %POWERSHELL_UPDATECHECK%,"},
	} {
		_, err := compared(c.machine, c.account, lookup)
		if err == nil || !strings.HasPrefix(err.Error(), "Windows PowerShell would be given a module path it may not keep as given: "+c.want) {
			t.Errorf("%+v %+v: %v, want %q", c.machine, c.account, err, c.want)
		}
	}
}

func TestNotFound(t *testing.T) {
	looked := []string{`C:\Program Files\PowerShell`, `C:\Program Files (x86)\PowerShell`}
	e := &NotFound{Looked: looked, Found: []agentproto.PowerShellInstall{{Edition: agentproto.EditionDesktop, Usable: true}}}
	if e.Error() != `PowerShell 7 is not installed on this device (looked in C:\Program Files\PowerShell and C:\Program Files (x86)\PowerShell). The script was not run.` {
		t.Error(e.Error())
	}
	e.Found = append(e.Found,
		agentproto.PowerShellInstall{Edition: agentproto.EditionCore, Path: `C:\Program Files (x86)\PowerShell\7\pwsh.exe`, Reason: reasonX86},
		agentproto.PowerShellInstall{Edition: agentproto.EditionCore, Path: `C:\Program Files\PowerShell\7\pwsh.exe`, Reason: `C:\Program Files\PowerShell\7\Modules\Foo\Foo.psm1 can be changed by BUILTIN\Users: not used, since what it runs and loads must be changeable by administrators only.`},
	)
	want := `No PowerShell 7 on this device can run scripts (looked in C:\Program Files\PowerShell and C:\Program Files (x86)\PowerShell; found ` +
		`C:\Program Files (x86)\PowerShell\7\pwsh.exe: A 32-bit (x86) build: never used for scripts, since it sees the 32-bit registry and System32; ` +
		`C:\Program Files\PowerShell\7\pwsh.exe: C:\Program Files\PowerShell\7\Modules\Foo\Foo.psm1 can be changed by BUILTIN\Users: not used, since what it runs and loads must be changeable by administrators only). The script was not run.`
	if e.Error() != want {
		t.Errorf("\n got %s\nwant %s", e.Error(), want)
	}
}
