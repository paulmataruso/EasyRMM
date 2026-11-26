package printsrv

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

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
	tier3 := []string{"spooler_restart", "queue_clear", "printer_remove", "driver_add", "driver_remove"}
	tier2 := []string{"printer_set", "printer_add", "port_add", "port_remove", "point_and_print_restrict"}
	tier1 := []string{"job_cancel", "job_pause", "job_resume", "job_restart", "printer_pause", "printer_resume"}
	for _, a := range c.Actions() {
		if agentproto.HashScript(a.Script) != a.ScriptSHA256 {
			t.Errorf("%s: pin does not match", a.Name)
		}
		if !a.Changes && a.Permission != rbac.PermPrintView && !a.Sensitive {
			t.Errorf("%s: a read needs print.view", a.Name)
		}
		if a.Sensitive && (a.SensitivePermission != rbac.PermPrintViewSensitive || a.Permission != rbac.PermPrintViewSensitive) {
			t.Errorf("%s: a sensitive result needs print.view_sensitive", a.Name)
		}
		if (a.Destructive || a.Confirm) && (!a.SubjectIsDeviceName || a.Subject != "device") {
			t.Errorf("%s: confirmed on a name the server does not compare", a.Name)
		}
		for _, banned := range []string{"-RemoveFromDriverStore", "pnputil", "Add-PrinterDriver -InfPath", "-InfPath", "Invoke-WebRequest", "Copy-Item"} {
			if strings.Contains(a.Script, banned) {
				t.Errorf("%s: names %s (no driver comes from a file, share or the internet)", a.Name, banned)
			}
		}
	}
	for _, n := range tier3 {
		a, ok := c.Lookup("print." + n)
		if !ok || !a.Destructive || !a.NeedsStepUp() || a.Permission != rbac.PermPrintDestroy {
			t.Errorf("%s: tier 3 needs print.destroy, a confirmation and a step-up", n)
		}
	}
	for _, n := range tier2 {
		if a, ok := c.Lookup("print." + n); !ok || !a.Confirm || a.NeedsStepUp() || a.Permission != rbac.PermPrintManage {
			t.Errorf("%s: tier 2 is confirmed, without a step-up", n)
		}
	}
	for _, n := range tier1 {
		if a, ok := c.Lookup("print." + n); !ok || a.Confirm || a.Destructive || a.Permission != rbac.PermPrintManage {
			t.Errorf("%s: tier 1 needs print.manage only", n)
		}
	}
}

// No action takes a value for the Point and Print settings: the restrict
// action takes none, and none of the scripts writes the two suppression values.
func TestPointAndPrintCannotBeWeakened(t *testing.T) {
	c := catalog(t)
	a, _ := c.Lookup("print.point_and_print_restrict")
	for _, p := range a.Params {
		if p.Name != "device" {
			t.Errorf("point_and_print_restrict takes %q", p.Name)
		}
	}
	for _, x := range c.Actions() {
		for _, line := range strings.Split(x.Script, "\n") {
			if !strings.Contains(line, "ItemProperty") || strings.Contains(line, "Get-ItemProperty") {
				continue
			}
			if x.Name != "print.point_and_print_restrict" || !strings.Contains(line, "'RestrictDriverInstallationToAdministrators' -Value 1 ") {
				t.Errorf("%s writes a registry value: %s", x.Name, line)
			}
		}
	}
	if !strings.Contains(a.Script, "-Value 1") {
		t.Error("the restrict action does not set 1")
	}
}

func validate(t *testing.T, c *winmod.Catalog, action, params string) error {
	t.Helper()
	a, ok := c.Lookup("print." + action)
	if !ok {
		t.Fatalf("no action %s", action)
	}
	_, err := a.Validate(json.RawMessage(params))
	return err
}

func TestParams(t *testing.T) {
	c := catalog(t)
	ok := map[string]string{
		"job_cancel":   `{"printer":"HP LaserJet (Floor 2)","ids":"1,2,30"}`,
		"port_add":     `{"device":"SRV","name":"IP_192.0.2.9","address":"192.0.2.9","port":9100}`,
		"printer_add":  `{"device":"SRV","name":"Front desk","driverName":"Microsoft PS Class Driver","portName":"IP_192.0.2.9"}`,
		"printer_set":  `{"device":"SRV","printer":"Front desk","shared":true,"shareName":"front"}`,
		"queue_clear":  `{"device":"SRV","printer":"Front desk"}`,
		"driver_add":   `{"device":"SRV","name":"Microsoft PS Class Driver"}`,
		"port_remove":  `{"device":"SRV","name":"IP_192.0.2.9"}`,
		"job_list":     `{"printer":"Front desk"}`,
		"printer_list": ``,
	}
	for a, p := range ok {
		if err := validate(t, c, a, p); err != nil {
			t.Errorf("%s %s: %v", a, p, err)
		}
	}
	bad := map[string][]string{
		"job_cancel": {`{"printer":"x","ids":"1;2"}`, `{"printer":"x","ids":""}`, `{"printer":"x","ids":"` + strings.Repeat("1,", 51) + `1"}`,
			`{"printer":"a\\b","ids":"1"}`, `{"printer":"a\"b","ids":"1"}`, `{"printer":"$(x)","ids":"1"}`, `{"printer":"a;b","ids":"1"}`},
		"port_add":    {`{"device":"SRV","name":"p","address":"printer.example.com","port":9100}`, `{"device":"SRV","name":"p","address":"192.0.2.999","port":9100}`, `{"device":"SRV","name":"p","address":"192.0.2.9","port":0}`, `{"device":"SRV","name":"p","address":"192.0.2.9 ","port":9100}`},
		"printer_set": {`{"device":"SRV","printer":"x","shareName":"a/b"}`, `{"device":"SRV","printer":"x","shareName":"a;b"}`},
	}
	for a, ps := range bad {
		for _, p := range ps {
			if err := validate(t, c, a, p); err == nil {
				t.Errorf("%s %s was accepted", a, p)
			}
		}
	}
}

func TestResultDecodes(t *testing.T) {
	c := catalog(t)
	a, _ := c.Lookup("print.hardening_status")
	line := winmod.ResultPrefix + `{"ok":true,"version":1,"data":{"restrictDriverInstall":1,"noWarningNoElevation":null,"updatePromptSettings":null,"weakened":false,"spoolerRunning":true,"domainController":false},"error":null}`
	if res, err := a.ParseResult(line); err != nil || !res.OK {
		t.Fatalf("%v %+v", err, res)
	}
	if _, err := a.ParseResult(strings.Replace(line, `"weakened":false`, `"weakened":false,"extra":1`, 1)); err == nil {
		t.Error("an unknown field was accepted")
	}
}

func i64(n int64) *int64 { return &n }

func TestStuckRule(t *testing.T) {
	for name, tc := range map[string]struct {
		p    Printer
		want bool
	}{
		"empty":             {Printer{}, false},
		"young job":         {Printer{JobCount: 1, OldestJobAgeMinutes: i64(2)}, false},
		"old job":           {Printer{JobCount: 1, OldestJobAgeMinutes: i64(90)}, true},
		"error":             {Printer{JobCount: 1, JobsInError: 1, OldestJobAgeMinutes: i64(1)}, true},
		"paused on purpose": {Printer{JobCount: 5, Paused: true, OldestJobAgeMinutes: i64(900)}, false},
		"offline":           {Printer{JobCount: 2, Offline: true}, true},
		"below threshold":   {Printer{JobCount: 1, OldestJobAgeMinutes: i64(900)}, false},
	} {
		th := 1
		if name == "below threshold" {
			th = 2
		}
		if got := stuck(tc.p, th); got != tc.want {
			t.Errorf("%s: %v", name, got)
		}
	}
}

func TestAlertKinds(t *testing.T) {
	m := AlertKinds()
	if len(m.Kinds) != 3 || len(m.Defaults) != 3 {
		t.Fatalf("%d kinds, %d defaults", len(m.Kinds), len(m.Defaults))
	}
	on := 0
	for _, d := range m.Defaults {
		if d.Enabled {
			on++
		}
	}
	if on != 2 {
		t.Errorf("%d defaults on, want 2 (queue stuck, Point and Print)", on)
	}
	eval := map[string]func(json.RawMessage, *int) (monitoring.Verdict, error){}
	for _, k := range m.Kinds {
		eval[k.Name] = k.Eval
	}
	th := 1
	v, err := eval[KindQueueStuck](json.RawMessage(`{"printers":[{"name":"a","paused":false,"jobCount":2,"jobsInError":1,"oldestJobAgeMinutes":3}],"truncated":false}`), &th)
	if err != nil || !v.Holds || v.Value != 1 {
		t.Errorf("stuck: %+v %v", v, err)
	}
	if _, err := eval[KindQueueStuck](json.RawMessage(`not json`), &th); !errors.Is(err, monitoring.ErrUnknown) {
		t.Errorf("a bad snapshot: %v", err)
	}
	v, _ = eval[KindPointAndPrint](json.RawMessage(`{"restrictDriverInstall":0,"noWarningNoElevation":null,"updatePromptSettings":null,"weakened":true,"spoolerRunning":true,"domainController":false}`), nil)
	if !v.Holds {
		t.Error("a weakened Point and Print does not alert")
	}
	v, _ = eval[KindServiceStopped](json.RawMessage(`{"serviceState":"stopped","printerCount":0,"sharedCount":0,"jobCount":0,"domainController":false}`), nil)
	if !v.Holds {
		t.Error("a stopped spooler does not alert")
	}
	// The kinds register with monitoring.
	if err := monitoring.RegisterModuleAlerts(m); err != nil {
		t.Error(err)
	}
}
