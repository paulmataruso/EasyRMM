package defender

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type scripted struct {
	calls []string
	envs  [][]string
	out   []string
	errs  []error
}

func (s *scripted) run(_ context.Context, env []string, _ string, args ...string) ([]byte, error) {
	i := len(s.calls)
	s.calls = append(s.calls, args[len(args)-1])
	s.envs = append(s.envs, env)
	return []byte(s.out[i]), s.errs[i]
}

func TestParsePrefs(t *testing.T) {
	p, err := ParsePrefs([]byte(`{"missing":false,"path":["C:\\A"],"process":[],"asr":[],"cfa":[],"disableLocalAdminMerge":true,"cfaMode":1,"asrRules":3,"runningMode":"Normal","antivirusEnabled":true,"serviceEnabled":true,"realTimeEnabled":true,"tamperProtected":true}`))
	if err != nil || !p.DisableLocalAdminMerge || !p.CFAOn || p.ASRRules != 3 || !p.TamperProtected || p.Lists["path"][0] != `C:\A` {
		t.Fatalf("%+v %v", p, err)
	}
	if p, _ := ParsePrefs([]byte(`{"missing":true}`)); !p.Missing {
		t.Fatal("missing module")
	}
	p, _ = ParsePrefs([]byte("warning\n" + `{"path":["N/A: Must be an administrator"],"runningMode":"Normal"}`))
	if p.NA == "" {
		t.Fatal("Defender's N/A is not a list")
	}
	if _, err := ParsePrefs([]byte("no json")); err == nil {
		t.Fatal("garbage was accepted")
	}
}

func TestAddPassesThePathInTheEnvironmentNeverTheScript(t *testing.T) {
	s := &scripted{out: []string{""}, errs: []error{nil}}
	p := &PowerShell{Run: s.run, Exe: "powershell.exe"}
	path := `C:\Evil"; Remove-Item C:\ -Recurse #`
	if err := p.Add(context.Background(), "path", path); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(s.calls[0], "Evil") || !strings.Contains(s.calls[0], "Add-MpPreference -ExclusionPath $env:EASYRMM_DEFENDER_PATH") {
		t.Fatalf("script = %s", s.calls[0])
	}
	if s.envs[0][0] != pathVar+"="+path || p.Method() != "powershell" {
		t.Fatalf("env = %v", s.envs[0])
	}
}

func TestEveryKindHasItsParameter(t *testing.T) {
	want := map[string]string{"path": "-ExclusionPath", "process": "-ExclusionProcess",
		"asr": "-AttackSurfaceReductionOnlyExclusions", "cfa": "-ControlledFolderAccessAllowedApplications"}
	for k, flag := range want {
		s := &scripted{out: []string{""}, errs: []error{nil}}
		if err := (&PowerShell{Run: s.run}).Remove(context.Background(), k, `C:\A`); err != nil || !strings.Contains(s.calls[0], "Remove-MpPreference "+flag) {
			t.Fatalf("%s: %v %q", k, err, s.calls)
		}
	}
	if err := (&PowerShell{Run: (&scripted{}).run}).Add(context.Background(), "extension", `.exe`); err == nil {
		t.Fatal("an extension exclusion was possible")
	}
}

func TestRefusalIsNotRetriedButOtherFailuresFallBackToWMIOnce(t *testing.T) {
	s := &scripted{out: []string{"Access is denied. Tamper Protection"}, errs: []error{errors.New("exit 1")}}
	err := (&PowerShell{Run: s.run}).Add(context.Background(), "path", `C:\A`)
	var r *Refused
	if !errors.As(err, &r) || len(s.calls) != 1 {
		t.Fatalf("err = %v, calls = %d", err, len(s.calls))
	}
	s = &scripted{out: []string{"The term 'Add-MpPreference' is not recognized", ""}, errs: []error{errors.New("exit 1"), nil}}
	p := &PowerShell{Run: s.run}
	if err := p.Add(context.Background(), "path", `C:\A`); err != nil || len(s.calls) != 2 || p.Method() != "wmi" {
		t.Fatalf("err = %v, calls = %d, method = %s", err, len(s.calls), p.Method())
	}
	if !strings.Contains(s.calls[1], "MSFT_MpPreference") || !strings.Contains(s.calls[1], "-MethodName Add") {
		t.Fatalf("wmi script = %s", s.calls[1])
	}
	s = &scripted{out: []string{"x", "y"}, errs: []error{errors.New("1"), errors.New("2")}}
	if err := (&PowerShell{Run: s.run}).Add(context.Background(), "path", `C:\A`); err == nil || errors.As(err, &r) {
		t.Fatalf("both failing is unavailable, not a refusal: %v", err)
	}
}
