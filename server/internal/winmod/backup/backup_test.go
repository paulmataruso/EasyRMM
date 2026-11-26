package backup

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/monitoring"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/winmod"
)

func catalog(t *testing.T) *winmod.Catalog {
	t.Helper()
	c, err := winmod.NewCatalog(Actions()...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCatalogLint(t *testing.T) {
	c := catalog(t)
	if got, want := len(c.Actions()), len(scriptFiles(t)); got != want {
		t.Errorf("%d actions for %d scripts", got, want)
	}
	for _, a := range c.Actions() {
		if got := agentproto.HashScript(a.Script); got != a.ScriptSHA256 {
			t.Errorf("%s: script hashes to %s, pinned %s", a.Name, got, a.ScriptSHA256)
		}
		// A tier 3 action needs backup.destroy, a confirmation and a step-up.
		if a.Destructive {
			if a.Permission != rbac.PermBackupDestroy || a.Subject != "device" || !a.NeedsStepUp() {
				t.Errorf("%s: destructive without backup.destroy, a subject or a step-up", a.Name)
			}
		}
		// Nothing that changes state is a snapshot read, and sensitive
		// results are opened by backup.view_sensitive.
		if a.Sensitive && a.SensitivePermission != rbac.PermBackupViewSensitive {
			t.Errorf("%s: a sensitive result is not opened by backup.view_sensitive", a.Name)
		}
		if a.Changes && a.Permission == rbac.PermBackupView {
			t.Errorf("%s: a change needs more than backup.view", a.Name)
		}
	}
	// The tiers the ADR names.
	for name, destroy := range map[string]bool{
		"target_disk_set": true, "vss_full_set": true, "policy_remove": true, "restore_files_overwrite": true,
		"versions_prune": true, "feature_install": true,
		"policy_set": false, "target_network_set": false, "target_volume_set": false, "restore_files": false, "stop_recovery": false,
		"run_now": false, "stop": false, "status": false, "versions": false, "disks": false, "job": false, "versions_prune_preview": false,
	} {
		a, ok := c.Lookup("windows_backup." + name)
		if !ok {
			t.Errorf("%s is missing", name)
			continue
		}
		if a.Destructive != destroy {
			t.Errorf("%s: destructive = %v, want %v", name, a.Destructive, destroy)
		}
	}
	for _, n := range []string{"policy_set", "target_network_set", "target_volume_set", "restore_files", "stop_recovery"} {
		if a, _ := c.Lookup("windows_backup." + n); !a.Confirm || a.NeedsStepUp() {
			t.Errorf("%s: tier 2 is confirmed without a step-up", n)
		}
	}
	// No script takes a desktop action while R11 has not been run.
	if DesktopImageVerified {
		t.Error("DesktopImageVerified is true: the desktop actions must exist and be tested")
	}
	for _, a := range c.Actions() {
		if strings.Contains(a.Name, "desktop") || strings.Contains(a.Name, "filehistory") {
			t.Errorf("%s: a desktop action before R11", a.Name)
		}
	}
}

// No script gives wbadmin a password or user on a command line, or runs
// wbadmin at all: the module uses the cmdlets (ADR-0077, Credentials).
func TestScriptsNeverUseWbadminOrPlainSecrets(t *testing.T) {
	for _, f := range scriptFiles(t) {
		s := strings.ToLower(Script(f))
		for _, bad := range []string{"wbadmin", "-password", "invoke-expression", "net use", "cmdkey", "schtasks"} {
			if strings.Contains(s, bad) {
				t.Errorf("%s contains %q", f, bad)
			}
		}
		// The plain-text conversion is in the pinned helper of one script.
		if has := strings.Contains(s, "-asplaintext"); has != (f == "target_network_set") {
			t.Errorf("%s: -AsPlainText present = %v", f, has)
		}
	}
	if !strings.Contains(Script("target_network_set"), "function New-EasyRmmCredential") {
		t.Error("target_network_set lost the credential helper")
	}
}

func validate(t *testing.T, name, params string) (*winmod.Checked, error) {
	t.Helper()
	a, ok := catalog(t).Lookup("windows_backup." + name)
	if !ok {
		t.Fatalf("no action %s", name)
	}
	return a.Validate(json.RawMessage(params))
}

func TestParametersAreChecked(t *testing.T) {
	good := map[string]string{
		"policy_set":              `{"device":"SRV-1","times":"21:00,03:30","volumes":"C:|D:","files":"D:\\Data|E:\\More files","exclude":"D:\\Data\\tmp","systemState":true,"targetVolume":"E:"}`,
		"target_volume_set":       `{"device":"SRV-1","volume":"\\\\?\\Volume{9b0a2d28-6f69-4b8a-8e0f-0c1a2b3c4d5e}\\"}`,
		"target_network_set":      `{"device":"SRV-1","unc":"\\\\nas.example.net\\backups\\SRV-1","user":"EXAMPLE\\svc","password":"p@ss"}`,
		"restore_files":           `{"device":"SRV-1","version":"11/26/2026-21:00","source":"D:\\Data\\a.txt","targetPath":"D:\\EasyRMM-Restore\\x","recursive":true}`,
		"restore_files_overwrite": `{"device":"SRV-1","version":"9b0a2d28-6f69-4b8a-8e0f-0c1a2b3c4d5e","source":"D:\\Data"}`,
		"versions_prune":          `{"device":"SRV-1","keep":3,"expect":2}`,
		"versions_prune_preview":  `{}`,
		"target_disk_set":         `{"device":"SRV-1","diskNumber":2,"diskId":"{1234-ab}"}`,
		"job":                     `{"previous":20}`,
	}
	for name, p := range good {
		if _, err := validate(t, name, p); err != nil {
			t.Errorf("%s %s: %v", name, p, err)
		}
	}
	bad := map[string][]string{
		"policy_set": {
			`{"device":"S","times":"25:00"}`, `{"device":"S","times":"21:00,21:00,21:00,21:00,21:00,21:00,21:00"}`,
			`{"device":"S","times":"21:00","files":"D:\\a\\..\\b"}`, `{"device":"S","times":"21:00","files":"\\\\?\\C:\\x"}`,
			`{"device":"S","times":"21:00","files":"relative\\path"}`, `{"device":"S","times":"21:00","volumes":"C:\\"}`,
			`{"device":"S","times":"21:00","files":"D:\\a|"}`, `{"device":"S","times":"21:00","targetVolume":"\\\\.\\PhysicalDrive0"}`,
			`{"times":"21:00"}`, `{"device":"S","times":"21:00","extra":1}`,
		},
		"target_network_set": {
			`{"device":"S","unc":"\\\\nas\\share","user":"u","password":"p"}`, // no sub-folder
			`{"device":"S","unc":"\\\\nas\\share\\..\\x","user":"u","password":"p"}`,
			`{"device":"S","unc":"\\\\nas\\share\\x","user":"u;calc","password":"p"}`,
			`{"device":"S","unc":"C:\\share\\x","user":"u","password":"p"}`,
			`{"device":"S","unc":"\\\\nas\\share\\x","user":"u"}`,
		},
		"restore_files": {
			`{"device":"S","version":"yesterday","source":"D:\\a"}`, `{"device":"S","version":"11/26/2026-21:00","source":"D:\\..\\a"}`,
			`{"device":"S","version":"11/26/2026-21:00","source":"\\\\?\\D:\\a"}`, `{"device":"S","version":"11/26/2026-21:00","source":"D:\\a","targetPath":"..\\x"}`,
		},
		"versions_prune": {`{"device":"S","keep":0,"expect":1}`, `{"device":"S","keep":366,"expect":1}`, `{"device":"S","keep":1}`},
		"job":            {`{"previous":21}`, `{"previous":-1}`},
		"target_disk_set": {
			`{"device":"S","diskNumber":-1,"diskId":"x"}`, `{"device":"S","diskNumber":1}`,
		},
	}
	for name, ps := range bad {
		for _, p := range ps {
			if _, err := validate(t, name, p); err == nil {
				t.Errorf("%s accepted %s", name, p)
			}
		}
	}
}

func TestPasswordIsASecretAndNeverInParamsOrAudit(t *testing.T) {
	const pw = "Tr0ub4dor&3-marker"
	chk, err := validate(t, "target_network_set",
		`{"device":"SRV-1","unc":"\\\\nas.example.net\\b\\SRV-1","user":"EXAMPLE\\svc","password":"`+pw+`"}`)
	if err != nil {
		t.Fatal(err)
	}
	if chk.Secrets["password"] != pw {
		t.Error("the password is not held as a secret")
	}
	if strings.Contains(string(chk.Params), pw) || strings.Contains(string(chk.Params), "password") {
		t.Errorf("params hold the password: %s", chk.Params)
	}
	audit, _ := json.Marshal(chk.Audit)
	if strings.Contains(string(audit), pw) || strings.Contains(string(audit), "nas.example.net") || strings.Contains(string(audit), "svc") {
		t.Errorf("audit holds the password, share or account: %s", audit)
	}
	if chk.Subject != "SRV-1" {
		t.Errorf("subject %q", chk.Subject)
	}
}

// Hostile values arrive unchanged, and the check refuses the ones a path or
// name cannot hold.
func TestHostileValuesAreRefusedOrArriveUnchanged(t *testing.T) {
	for _, v := range []string{"$(calc)", "`calc`", "a';calc;'", "a\nb", `a"b`, "a|b"} {
		b, _ := json.Marshal(map[string]string{"device": "S", "volume": v})
		if _, err := validate(t, "target_volume_set", string(b)); err == nil {
			t.Errorf("volume %q accepted", v)
		}
	}
	chk, err := validate(t, "restore_files", `{"device":"it's a $(name)","version":"11/26/2026-21:00","source":"D:\\a"}`)
	if err == nil {
		t.Errorf("a device name with $() accepted: %+v", chk)
	}
}

func TestResultsDecodeStrictly(t *testing.T) {
	c := catalog(t)
	st, _ := c.Lookup("windows_backup.status")
	line := func(data string) string {
		return winmod.ResultPrefix + `{"ok":true,"version":1,"data":` + data + `,"error":null}` + "\n"
	}
	full := `{"installed":true,"configured":true,"running":false,"nextRun":"2026-11-27T21:00:00Z","lastSuccess":"2026-11-26T21:00:00Z","lastFailure":null,` +
		`"lastResultHR":0,"lastSuccessAgeDays":0,"versionCount":4,"oldestVersion":null,"newestVersion":null,"schedule":["21:00"],"systemState":true,` +
		`"bareMetal":false,"volumeCount":1,"fileSpecCount":0,"vssFull":false,"targets":[{"kind":"volume","freeBytes":10,"totalBytes":100,"online":true}],"job":null}`
	if r, err := st.ParseResult(line(full)); err != nil || !r.OK {
		t.Fatalf("a good result: %v", err)
	}
	for name, out := range map[string]string{
		"truncated":     line(full)[:60],
		"unknown field": line(strings.Replace(full, `"vssFull":false`, `"vssFull":false,"password":"x"`, 1)),
		"wrong version": strings.Replace(line(full), `"version":1`, `"version":2`, 1),
		"wrong type":    line(strings.Replace(full, `"installed":true`, `"installed":"yes"`, 1)),
	} {
		if _, err := st.ParseResult(out); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A failure carries a code, not data.
	fail := winmod.ResultPrefix + `{"ok":false,"version":1,"data":null,"error":{"code":"busy","message":"Windows Server Backup is running another operation."}}` + "\n"
	if r, err := st.ParseResult(fail); err != nil || r.OK || r.Error.Code != "busy" {
		t.Errorf("a failure: %+v, %v", r, err)
	}
	nd, _ := c.Lookup("windows_backup.target_network_set")
	if _, err := nd.ParseResult(line(`{"done":true,"credentialSet":true}`)); err != nil {
		t.Errorf("the share result: %v", err)
	}
	if _, err := nd.ParseResult(line(`{"done":true,"credentialSet":true,"password":"x"}`)); err == nil {
		t.Error("a share result carried a password field")
	}
}

func TestDefaultsAndKindsRegister(t *testing.T) {
	if err := monitoring.RegisterModuleAlerts(AlertKinds()); err != nil {
		t.Fatal(err)
	}
}

func at(h int) *time.Time {
	t := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC).Add(time.Duration(h) * time.Hour)
	return &t
}

func TestAlertRules(t *testing.T) {
	now = func() time.Time { return time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { now = time.Now })
	kinds := map[string]monitoring.ModuleKind{}
	for _, k := range AlertKinds().Kinds {
		kinds[k.Name] = k
	}
	total, low, high := int64(1000), int64(50), int64(500)
	tests := []struct {
		name      string
		kind      string
		threshold int
		st        Status
		holds, na bool
	}{
		{"failure after success", KindFailed, 0, Status{Installed: true, Configured: true, LastSuccess: at(-30), LastFailure: at(-5), LastResultHR: ptr(int64(-2147024891))}, true, false},
		{"success after failure", KindFailed, 0, Status{Installed: true, Configured: true, LastSuccess: at(-1), LastFailure: at(-5)}, false, false},
		{"failure, never a success", KindFailed, 0, Status{Installed: true, Configured: true, LastFailure: at(-5)}, true, false},
		{"no policy: nothing to fail", KindFailed, 0, Status{Installed: true, LastFailure: at(-5)}, false, true},
		{"no feature", KindFailed, 0, Status{LastFailure: at(-5)}, false, true},
		{"overdue by age", KindOverdue, 2, Status{Installed: true, Configured: true, LastSuccessAgeDays: ptr(3)}, true, false},
		{"recent enough", KindOverdue, 2, Status{Installed: true, Configured: true, LastSuccessAgeDays: ptr(1)}, false, false},
		{"never succeeded", KindOverdue, 2, Status{Installed: true, Configured: true}, true, false},
		{"offline target", KindTargetMissing, 0, Status{Installed: true, Configured: true, Targets: []Target{{Online: false}}}, true, false},
		{"online target", KindTargetMissing, 0, Status{Installed: true, Configured: true, Targets: []Target{{Online: true}}}, false, false},
		{"low space", KindTargetLow, 10, Status{Installed: true, Configured: true, Targets: []Target{{FreeBytes: &low, TotalBytes: &total, Online: true}}}, true, false},
		{"enough space", KindTargetLow, 10, Status{Installed: true, Configured: true, Targets: []Target{{FreeBytes: &high, TotalBytes: &total, Online: true}}}, false, false},
		{"installed, no policy", KindNotConfigured, 0, Status{Installed: true}, true, false},
		{"configured", KindNotConfigured, 0, Status{Installed: true, Configured: true}, false, false},
		{"stuck", KindStuck, 12, Status{Installed: true, Configured: true, Running: true, Job: &Job{StartTime: at(-13)}}, true, false},
		{"running, not long", KindStuck, 12, Status{Installed: true, Configured: true, Running: true, Job: &Job{StartTime: at(-2)}}, false, false},
		{"not running", KindStuck, 12, Status{Installed: true, Configured: true}, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, _ := json.Marshal(tt.st)
			th := &tt.threshold
			if tt.threshold == 0 {
				th = nil
			}
			v, err := kinds[tt.kind].Eval(data, th)
			if err != nil || v.Holds != tt.holds || v.NotApplicable != tt.na {
				t.Errorf("got %+v, %v; want holds=%v notApplicable=%v", v, err, tt.holds, tt.na)
			}
		})
	}
	// Unreadable data and a missing threshold say "unknown", not "fine".
	if _, err := kinds[KindOverdue].Eval(json.RawMessage(`{"installed":"x"}`), ptr(2)); !errors.Is(err, monitoring.ErrUnknown) {
		t.Errorf("garbage: %v", err)
	}
	data, _ := json.Marshal(Status{Installed: true, Configured: true})
	if _, err := kinds[KindOverdue].Eval(data, nil); !errors.Is(err, monitoring.ErrUnknown) {
		t.Errorf("no threshold: %v", err)
	}
	if _, err := kinds[KindTargetLow].Eval(data, ptr(10)); !errors.Is(err, monitoring.ErrUnknown) {
		t.Errorf("no space data: %v", err)
	}
}

func ptr[T any](v T) *T { return &v }
