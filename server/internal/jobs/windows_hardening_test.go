package jobs

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/paulmataruso/easyrmm/internal/winpolicy"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
)

func TestWindowsHardeningScript(t *testing.T) {
	s := windowsHardeningScript
	if len(s) == 0 || len(s) > MaxJobBody {
		t.Errorf("the Windows hardening script is %d bytes; a job carries 1 to %d", len(s), MaxJobBody)
	}
	// Windows PowerShell 5.1 reads a script without a byte order mark in
	// the computer's ANSI code page: only ASCII reads the same everywhere.
	for i, r := range s {
		if r > 126 || (r < 32 && r != '\n' && r != '\r' && r != '\t') {
			t.Fatalf("character %q at byte %d is not printable ASCII", r, i)
		}
	}
	if strings.Contains(s, windowsIncludeLine) || !strings.Contains(s, winpolicy.Reader()) ||
		!strings.Contains(s, winpolicy.AuditJSON()) || !strings.Contains(s, `"id":"laps-managed"`) {
		t.Error("the reader, the settings or the audit table is not in place of the include line")
	}
	// A here-string ends at a line that starts with '@; the JSON inside
	// must have none.
	if n := strings.Count(s, "\n'@"); n != 2 {
		t.Errorf("%d here-string ends, want 2", n)
	}
	// Whatever line ends the source has, the script has only those.
	for _, c := range []struct{ source, reader, nl string }{
		{"a\r\n#EASYRMM-INCLUDE\r\nb\r\n", "function f {\n}\n", "\r\n"},
		{"a\n#EASYRMM-INCLUDE\nb\n", "function f {\r\n}\r\n", "\n"},
	} {
		got := buildWindowsScript(c.source, c.reader)
		if strings.Count(got, "\n") != strings.Count(got, c.nl) || !strings.HasPrefix(got, "a"+c.nl+"function f {"+c.nl+"}") {
			t.Errorf("line ends %q: %q", c.nl, got[:40])
		}
	}
	defer func() {
		if recover() == nil {
			t.Error("a source without its include line was accepted")
		}
	}()
	buildWindowsScript("a\nb\n", "")
}

// The script checks its arguments again with lists of its own; they must
// be the server's.
func TestWindowsScriptKnowsTheServersNames(t *testing.T) {
	src := windowsHardeningSource
	m := regexp.MustCompile(`(?s)\$ErAllModules = @\((.*?)\)`).FindStringSubmatch(src)
	if m == nil {
		t.Fatal("no module list in windows.ps1")
	}
	var mods []string
	for _, q := range regexp.MustCompile(`'([a-z-]+)'`).FindAllStringSubmatch(m[1], -1) {
		mods = append(mods, q[1])
	}
	if !slices.Equal(mods, WindowsHardeningModules) {
		t.Errorf("windows.ps1 modules %q, server %q", mods, WindowsHardeningModules)
	}
	m = regexp.MustCompile(`(?s)\$ErOptionModule = @\{(.*?)\n\}`).FindStringSubmatch(src)
	if m == nil {
		t.Fatal("no option list in windows.ps1")
	}
	opts := map[string]string{}
	for _, q := range regexp.MustCompile(`'([a-z-]+)' = '([a-z-]*)'`).FindAllStringSubmatch(m[1], -1) {
		opts[q[1]] = q[2]
	}
	want := map[string]string{"allow-tcp": "firewall", "allow-udp": "firewall", "asr-block": "asr"}
	for _, s := range windowsSwitches {
		want[s.arg] = s.module
	}
	if len(opts) != len(want) {
		t.Errorf("windows.ps1 options %v, server %v", opts, want)
	}
	for k, v := range want {
		if got, ok := opts[k]; !ok || got != v {
			t.Errorf("option %s: windows.ps1 %q, server %q", k, got, v)
		}
	}
}

// Every module has settings, and every setting the script reads by its ID
// has a case there.
func TestWindowsSettingsCoverEveryModule(t *testing.T) {
	for _, m := range WindowsHardeningModules {
		if !slices.ContainsFunc(windowsSettings, func(s windowsSetting) bool { return s.Module == m }) {
			t.Errorf("module %s has no settings", m)
		}
	}
	for _, s := range windowsSettings {
		if s.Kind == "custom" && !strings.Contains(windowsHardeningSource, "'"+s.ID+"' {") {
			t.Errorf("setting %s is custom and windows.ps1 has no case for it", s.ID)
		}
	}
	// Every rule the module audits may be blocked, except PSExec's; the
	// three it blocks are not in the list.
	var audited []string
	for _, s := range windowsSettings {
		if s.Kind == "asr" && !s.Block && s.Rule != asrPSExec {
			audited = append(audited, s.Rule)
		}
	}
	slices.Sort(audited)
	blockable := slices.Sorted(slices.Values(ASRBlockable))
	if !slices.Equal(audited, blockable) {
		t.Errorf("audited rules %q, blockable %q", audited, blockable)
	}
}

func TestParseWindowsSettings(t *testing.T) {
	for name, body := range map[string]string{
		"not JSON":          `{`,
		"unknown field":     `{"version":1,"settings":[{"id":"wdigest-x","module":"wdigest","what":"x","kind":"custom","extra":1}]}`,
		"no settings":       `{"version":1,"settings":[]}`,
		"version 2":         `{"version":2,"settings":[{"id":"wdigest-x","module":"wdigest","what":"x","kind":"custom"}]}`,
		"bad ID":            `{"version":1,"settings":[{"id":"Wdigest","module":"wdigest","what":"x","kind":"custom"}]}`,
		"twice":             `{"version":1,"settings":[{"id":"wdigest-x","module":"wdigest","what":"x","kind":"custom"},{"id":"wdigest-x","module":"wdigest","what":"x","kind":"custom"}]}`,
		"unknown module":    `{"version":1,"settings":[{"id":"ssh-x","module":"ssh","what":"x","kind":"custom"}]}`,
		"ID of another":     `{"version":1,"settings":[{"id":"uac-x","module":"wdigest","what":"x","kind":"custom"}]}`,
		"unknown kind":      `{"version":1,"settings":[{"id":"wdigest-x","module":"wdigest","what":"x","kind":"wmi"}]}`,
		"unknown citation":  `{"version":1,"settings":[{"id":"wdigest-x","module":"wdigest","what":"x","kind":"custom","cite":"maybe"}]}`,
		"no description":    `{"version":1,"settings":[{"id":"wdigest-x","module":"wdigest","what":"","kind":"custom"}]}`,
		"unknown option":    `{"version":1,"settings":[{"id":"uac-x","module":"uac","what":"x","kind":"custom","option":"uac-off"}]}`,
		"option of another": `{"version":1,"settings":[{"id":"uac-x","module":"uac","what":"x","kind":"custom","option":"spooler-off"}]}`,
		"unknown rule":      `{"version":1,"settings":[{"id":"asr-x","module":"asr","what":"x","kind":"asr","rule":"a8f5898e-1dc8-49a9-9878-85004b8a61e6"}]}`,
		"not a CSP policy":  `{"version":1,"settings":[{"id":"wdigest-x","module":"wdigest","what":"x","kind":"custom","csp":"Firewall"}]}`,
		"firewall CSP":      `{"version":1,"settings":[{"id":"firewall-x","module":"firewall","what":"x","kind":"firewall","csp":"Firewall/DomainProfile"}]}`,
		"security CSP":      `{"version":1,"settings":[{"id":"accounts-x","module":"accounts","what":"x","kind":"secedit","csp":"DeviceLock/MinDevicePasswordLength"}]}`,
	} {
		if _, err := parseWindowsSettings([]byte(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	defer func() {
		if recover() == nil {
			t.Error("bad settings did not stop the server")
		}
	}()
	mustWindowsSettings([]byte(`{}`))
}

func TestWindowsHardeningInput(t *testing.T) {
	h := Hardening{
		Platform: HardeningWindows, Mode: HardeningCheck, Modules: []string{"uac", "firewall", "asr", "uac", "defender", "printing"},
		Options: HardeningOptions{
			AllowTCP: []string{"8443", "9000-9100"},
			WindowsHardeningOptions: WindowsHardeningOptions{
				ASRBlock:     []string{"D4F940AB-401B-4EFC-AADC-AD5F3C50688A", "01443614-cd74-433a-b99e-2ecdc07bfc25", "d4f940ab-401b-4efc-aadc-ad5f3c50688a"},
				PortsChecked: true, SmartScreenBlock: true, UACEnable: true, SpoolerOff: true, DomainController: true,
			},
		},
	}
	f := apperr.Fields{}
	h.validate(f)
	if err := f.Err(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(h.Modules, []string{"firewall", "defender", "asr", "uac", "printing"}) || h.platform() != HardeningWindows {
		t.Errorf("modules %q", h.Modules)
	}
	want := []string{"check", "firewall,defender,asr,uac,printing", "allow-tcp=8443,9000-9100",
		"asr-block=01443614-cd74-433a-b99e-2ecdc07bfc25,d4f940ab-401b-4efc-aadc-ad5f3c50688a",
		"ports-checked", "domain-controller", "smartscreen-block", "uac-enable", "spooler-off"}
	if got := h.windowsArgs(); !slices.Equal(got, want) {
		t.Errorf("args %q", got)
	}
	if l := h.windowsLabel(); l != "Check Windows hardening: firewall, defender, asr, uac, printing" {
		t.Errorf("label %q", l)
	}
	all := Hardening{Platform: HardeningWindows, Mode: HardeningCheck, Modules: slices.Clone(WindowsHardeningModules)}
	if l := all.windowsLabel(); l != "Check Windows hardening (every module)" {
		t.Errorf("label %q", l)
	}
	if (Hardening{}).modules()[0] != "ssh" || all.modules()[0] != "accounts" {
		t.Error("each platform's modules")
	}

	// A Linux request keeps no platform, as before Windows.
	lnx := Hardening{Platform: HardeningLinux, Mode: HardeningCheck, Modules: []string{"ssh"}}
	f = apperr.Fields{}
	lnx.validate(f)
	if f.Err() != nil || lnx.Platform != "" || lnx.platform() != HardeningLinux {
		t.Errorf("linux %+v, %v", lnx, f.Err())
	}

	win := func(mods []string, o HardeningOptions) Hardening {
		return Hardening{Platform: HardeningWindows, Mode: HardeningCheck, Modules: mods, Options: o}
	}
	wo := func(w WindowsHardeningOptions) HardeningOptions { return HardeningOptions{WindowsHardeningOptions: w} }
	for name, c := range map[string]struct {
		h     Hardening
		field string
	}{
		"an unknown platform":          {Hardening{Platform: "macos", Mode: HardeningCheck, Modules: []string{"ssh"}}, "platform"},
		"apply":                        {Hardening{Platform: HardeningWindows, Mode: "apply", Modules: []string{"uac"}}, "mode"},
		"no module":                    {win(nil, HardeningOptions{}), "modules"},
		"a Linux module":               {win([]string{"ssh"}, HardeningOptions{}), "modules"},
		"a Windows module on Linux":    {Hardening{Mode: HardeningCheck, Modules: []string{"uac"}}, "modules"},
		"Windows options on Linux":     {Hardening{Mode: HardeningCheck, Modules: []string{"ssh"}, Options: wo(WindowsHardeningOptions{SpoolerOff: true})}, "options"},
		"Linux options on Windows":     {win([]string{"firewall"}, HardeningOptions{EPEL: true}), "options"},
		"a bad port":                   {win([]string{"firewall"}, HardeningOptions{AllowTCP: []string{"0"}}), "options.allowTcp"},
		"a bad UDP port":               {win([]string{"firewall"}, HardeningOptions{AllowUDP: []string{"70000"}}), "options.allowUdp"},
		"ports without the firewall":   {win([]string{"uac"}, HardeningOptions{AllowTCP: []string{"80"}}), "options.allowTcp"},
		"UDP without the firewall":     {win([]string{"uac"}, HardeningOptions{AllowUDP: []string{"80"}}), "options.allowUdp"},
		"PSExec is never blocked":      {win([]string{"asr"}, wo(WindowsHardeningOptions{ASRBlock: []string{asrPSExec}})), "options.asrBlock"},
		"a rule that is not a GUID":    {win([]string{"asr"}, wo(WindowsHardeningOptions{ASRBlock: []string{"all"}})), "options.asrBlock"},
		"too many rules":               {win([]string{"asr"}, wo(WindowsHardeningOptions{ASRBlock: append(slices.Clone(ASRBlockable), ASRBlockable[0])})), "options.asrBlock"},
		"asr-block without asr":        {win([]string{"uac"}, wo(WindowsHardeningOptions{ASRBlock: ASRBlockable[:1]})), "options.asrBlock"},
		"spooler-off without printing": {win([]string{"uac"}, wo(WindowsHardeningOptions{SpoolerOff: true})), "options.spoolerOff"},
		"lsa-uefi-lock without lsa":    {win([]string{"uac"}, wo(WindowsHardeningOptions{LSAUEFILock: true})), "options.lsaUefiLock"},
	} {
		f := apperr.Fields{}
		c.h.validate(f)
		if _, ok := f[c.field]; !ok {
			t.Errorf("%s: %v, want an error for %s", name, f, c.field)
		}
	}
	// Every switch is refused without its module.
	for _, s := range windowsSwitches {
		if s.module == "" {
			continue
		}
		h := win([]string{"laps"}, HardeningOptions{})
		setSwitch(&h.Options, s.field)
		f := apperr.Fields{}
		h.validate(f)
		if _, ok := f["options."+s.field]; !ok {
			t.Errorf("%s without %s accepted", s.arg, s.module)
		}
		if !slices.Contains(h.windowsArgs(), s.arg) {
			t.Errorf("%s is not passed", s.arg)
		}
	}
}

// setSwitch turns on the option the JSON field names.
func setSwitch(o *HardeningOptions, field string) {
	w := &o.WindowsHardeningOptions
	*map[string]*bool{
		"portsChecked": &w.PortsChecked, "firewallServer": &w.FirewallServer, "domainController": &w.DomainController,
		"defenderServerRealtime": &w.DefenderServerRealtime, "smartScreenBlock": &w.SmartScreenBlock,
		"cloudBlockHigh": &w.CloudBlockHigh, "lsaUefiLock": &w.LSAUEFILock, "lsaUnaudited": &w.LSAUnaudited,
		"lockoutExposed": &w.LockoutExposed, "uacEnable": &w.UACEnable, "uacBuiltinAdmin": &w.UACBuiltinAdmin,
		"denyUserElevation": &w.DenyUserElevation, "winrmBasicOff": &w.WinRMBasicOff, "spoolerOff": &w.SpoolerOff,
	}[field] = true
}

const windowsPlatform = `{"id":"windows","versionId":"10.0.26100.4349","family":"windows","container":"none","support":"full",` +
	`"windows":{"build":26100,"ubr":4349,"displayVersion":"24H2","edition":"ServerStandard","installationType":"Server Core",` +
	`"role":"member_server","joined":"domain","mdm":false,"architecture":"amd64","languageMode":"FullLanguage",` +
	`"owners":{"groupPolicyRecord":"read","groupPolicyPreferences":false,"mdm":false,"mdmWinsOverGp":false,` +
	`"defenderForEndpoint":false,"configMgr":false,"dsc":false,"azureMachineConfiguration":false,` +
	`"osConfig":["SecurityBaseline\\WindowsServer\\2025\\MemberServer"],"tamperProtected":true},` +
	`"checkOnlyReasons":[],"notes":[],"hardening":{"folder":"absent","copySha256":"","warnings":[],"setAside":[]}}}`

func windowsLine(platform, modules string) string {
	return HardeningResultPrefix + `{"version":1,"mode":"check","platform":` + platform + `,"modules":[` + modules + `]}`
}

func TestParseWindowsHardeningResult(t *testing.T) {
	h := Hardening{Platform: HardeningWindows, Mode: HardeningCheck, Modules: []string{"accounts", "wdigest", "audit"}}
	good := `{"module":"accounts","state":"managed_elsewhere","reason":"Settings that are not in place are held by another owner.",` +
		`"settings":[{"id":"accounts-min-length","state":"managed_elsewhere","value":"7","want":">= 14"},` +
		`{"id":"accounts-max-age","state":"reported","value":"42"}],` +
		`"managed":[{"id":"accounts-min-length","owner":"group_policy","policy":"Default Domain Policy","value":"7","state":"managed_elsewhere"}],` +
		`"notes":[],"exposure":{"exposed":true,"accounts":["administrator"],"addresses":["203.0.113.9"],"bursts":["backup"],"since":"2026-11-15T10:00:00.0000000Z"}},` +
		`{"module":"wdigest","state":"not_in_place","settings":[{"id":"wdigest-logon-credential","state":"check_only","value":"1","want":"0",` +
		`"reasons":["mdm"],"mdm":{"csp":"MSSecurityGuide/WDigestAuthentication","config":"","current":"","provider":""}}],"managed":[],"notes":[]},` +
		`{"module":"audit","state":"partly","settings":[{"id":"audit-subcategories","item":"{0cce923f-69ae-11d9-bed3-505054503030}","state":"in_place","value":"success_failure","want":"success_failure"}],"managed":[],"notes":[]}`
	r, err := parseHardeningResult(windowsLine(windowsPlatform, good), h)
	if err != nil {
		t.Fatal(err)
	}
	if w := r.Platform.Windows; w == nil || w.Build != 26100 || w.Role != "member_server" || w.Owners == nil || !w.Owners.TamperProtected ||
		len(r.Modules) != 3 || len(r.Modules[0].Managed) != 1 || r.Modules[0].Exposure == nil || r.Modules[1].Settings[0].Reasons[0] != "mdm" {
		t.Errorf("parsed %+v", r)
	}
	// Constrained Language Mode: the platform's first fields only.
	clm := `{"id":"windows","versionId":"10.0.22631.1","family":"windows","container":"none","support":"check_only",` +
		`"windows":{"build":22631,"ubr":1,"displayVersion":"23H2","edition":"Enterprise","installationType":"Client",` +
		`"role":"workstation","joined":"entra","mdm":true,"architecture":"amd64","languageMode":"ConstrainedLanguage"}}`
	if _, err := parseHardeningResult(windowsLine(clm, `{"module":"accounts","state":"not_supported","reason":"Constrained."},`+
		`{"module":"wdigest","state":"not_supported"},{"module":"audit","state":"not_supported"}`), h); err != nil {
		t.Errorf("constrained language: %v", err)
	}
	// What Windows did not report is unknown, never a guess: the role and
	// join as unknown, the MDM enrolment as null.
	unread := strings.NewReplacer(`"role":"member_server"`, `"role":"unknown"`, `"joined":"domain"`, `"joined":"unknown"`,
		`"mdm":false,"architecture"`, `"mdm":null,"architecture"`, `"checkOnlyReasons":[]`, `"checkOnlyReasons":["unreadable"]`).Replace(windowsPlatform)
	if r, err := parseHardeningResult(windowsLine(unread, good), h); err != nil {
		t.Errorf("an unread role, join and enrolment: %v", err)
	} else if w := r.Platform.Windows; w.Role != "unknown" || w.Joined != "unknown" || w.MDM != nil {
		t.Errorf("an unread role, join and enrolment: %+v", w)
	}

	bad := map[string]struct{ platform, modules string }{
		"a Linux platform":          {`{"id":"ubuntu","versionId":"24.04","family":"debian","container":"none","support":"full"}`, good},
		"no Windows part":           {`{"id":"windows","versionId":"10","family":"windows","container":"none","support":"full"}`, good},
		"an unknown role":           {strings.Replace(windowsPlatform, "member_server", "router", 1), good},
		"an unknown join":           {strings.Replace(windowsPlatform, `"joined":"domain"`, `"joined":"workgroup"`, 1), good},
		"a language mode":           {strings.Replace(windowsPlatform, "FullLanguage", "Full", 1), good},
		"a container":               {strings.Replace(windowsPlatform, `"container":"none"`, `"container":"docker"`, 1), good},
		"an unknown reason":         {strings.Replace(windowsPlatform, `"checkOnlyReasons":[]`, `"checkOnlyReasons":["sccm"]`, 1), good},
		"a record state":            {strings.Replace(windowsPlatform, `"groupPolicyRecord":"read"`, `"groupPolicyRecord":"maybe"`, 1), good},
		"a folder state":            {strings.Replace(windowsPlatform, `"folder":"absent"`, `"folder":"gone"`, 1), good},
		"a bad hash":                {strings.Replace(windowsPlatform, `"copySha256":""`, `"copySha256":"abc"`, 1), good},
		"another module's setting":  {windowsPlatform, strings.Replace(good, `"id":"accounts-max-age"`, `"id":"uac-on"`, 1)},
		"an unknown setting state":  {windowsPlatform, strings.Replace(good, `"state":"reported"`, `"state":"fine"`, 1)},
		"an unknown owner":          {windowsPlatform, strings.Replace(good, `"owner":"group_policy"`, `"owner":"intune"`, 1)},
		"an unknown setting reason": {windowsPlatform, strings.Replace(good, `"reasons":["mdm"]`, `"reasons":["intune"]`, 1)},
		"a managed state":           {windowsPlatform, strings.Replace(good, `"value":"7","state":"managed_elsewhere"}`, `"value":"7","state":"partly"}`, 1)},
		"a bad time":                {windowsPlatform, strings.Replace(good, "2026-11-15T10:00:00.0000000Z", "last week", 1)},
		"exposure elsewhere":        {windowsPlatform, strings.Replace(good, `"module":"wdigest","state":"not_in_place",`, `"module":"wdigest","state":"not_in_place","exposure":{"exposed":false,"accounts":[],"addresses":[],"since":"2026-11-15T10:00:00Z"},`, 1)},
		"ports on Windows":          {windowsPlatform, strings.Replace(good, `"module":"wdigest","state":"not_in_place",`, `"module":"wdigest","state":"not_in_place","ports":{"tcp":["22"]},`, 1)},
		"an omission":               {windowsPlatform, strings.Replace(good, `"module":"wdigest","state":"not_in_place",`, `"module":"wdigest","state":"not_in_place","settingsOmitted":"some",`, 1)},
		"a long want":               {windowsPlatform, strings.Replace(good, `"want":">= 14"`, `"want":"`+strings.Repeat("x", 121)+`"`, 1)},
		"a control in an item":      {windowsPlatform, strings.Replace(good, `"item":"{0cce923f`, `"item":"{0cce923f\u0085`, 1)},
		"many bursts":               {windowsPlatform, strings.Replace(good, `"bursts":["backup"]`, `"bursts":["a","b","c","d","e","f","g","h","i","j","k"]`, 1)},
	}
	for name, c := range bad {
		if _, err := parseHardeningResult(windowsLine(c.platform, c.modules), h); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Text the computer gave is tidied, and never refuses the result: a
	// failed sign-in's user name comes from whoever tried it.
	untidy := strings.NewReplacer(
		`"accounts":["administrator"]`, `"accounts":["","   ","\u0085\u0080\u009f","admin\u0085istr\u2028ator\u2029\u202e","\u200b"]`,
		`"bursts":["backup"]`, `"bursts":[" backup\u0007 "]`,
		`"addresses":["203.0.113.9"]`, `"addresses":["203.0.113.9","somewhere"]`,
		`"value":"42"`, `"value":"`+strings.Repeat("x", 121)+`"`,
		`"config":""`, `"config":"`+strings.Repeat("y", 81)+`"`,
		`"policy":"Default Domain Policy"`, `"policy":"Default\u009b Domain Policy\u00a0"`,
	).Replace(good)
	untidyPlatform := strings.NewReplacer(`2025\\MemberServer`, `2025\\Member\u0007`, `"notes":[]`, `"notes":["a\u0007b","\u0085"]`).Replace(windowsPlatform)
	r, err = parseHardeningResult(windowsLine(untidyPlatform, untidy), h)
	if err != nil {
		t.Fatalf("untidy text refused the result: %v", err)
	}
	e, a := r.Modules[0].Exposure, r.Modules[0]
	if !slices.Equal(e.Accounts, []string{"administrator"}) || !slices.Equal(e.Bursts, []string{"backup"}) ||
		!slices.Equal(e.Addresses, []string{"203.0.113.9"}) || a.Settings[1].Value != strings.Repeat("x", 120) ||
		a.Managed[0].Policy != "Default Domain Policy" || r.Modules[1].Settings[0].MDM.Config != strings.Repeat("y", 80) ||
		r.Platform.Windows.Owners.OSConfig[0] != `SecurityBaseline\WindowsServer\2025\Member` ||
		!slices.Equal(r.Platform.Windows.Notes, []string{"ab"}) {
		t.Errorf("tidied: exposure %+v, module %+v, platform %+v", e, a, r.Platform.Windows)
	}

	// Windows' fields in a Linux result.
	lnx := Hardening{Mode: HardeningCheck, Modules: []string{"ssh"}}
	lp := `{"id":"ubuntu","versionId":"24.04","family":"debian","container":"none","support":"full"}`
	for name, l := range map[string]string{
		"a Windows platform": windowsLine(strings.Replace(lp, `"full"}`, `"full","windows":{}}`, 1), `{"module":"ssh","state":"in_place"}`),
		"Windows settings":   windowsLine(lp, `{"module":"ssh","state":"in_place","settings":[{"id":"uac-on","state":"in_place"}]}`),
	} {
		if _, err := parseHardeningResult(l, lnx); err == nil {
			t.Errorf("linux with %s: accepted", name)
		}
	}
}
