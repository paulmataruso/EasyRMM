//go:build integration

package app_test

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// windowsModules are Windows hardening's modules in the order they run
// (ADR-0054).
var windowsModules = []string{
	"accounts", "firewall", "defender", "asr", "smb", "smb-signing", "ntlm", "wdigest", "lsa-protection",
	"name-resolution", "powershell", "rdp", "uac", "autoplay", "anonymous", "winrm", "printing", "features", "tls",
	"audit", "device-guard", "bitlocker", "laps",
}

// TestWindowsHardeningAPI checks an enrolled Windows device's hardening
// check through the console API with the real agent client: the job the
// agent receives, a real Windows computer's result as the device's
// hardening with each module's related controls, and the refusals
// (ADR-0054, W1).
func TestWindowsHardeningAPI(t *testing.T) {
	// The script's own output, as LocalSystem, on a Windows Server 2025
	// guest (see server/internal/jobs/testdata).
	out, err := os.ReadFile("../jobs/testdata/windows-hardening-check.txt")
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, false)
	admin, _ := setUp(t, h)
	acme := orgID(t, admin, "Acme")
	var hq idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/sites", map[string]string{"name": "HQ", "timezone": "UTC"}, &hq)
	var token struct {
		Secret string `json:"secret"`
	}
	admin.expect(http.StatusCreated, "POST", "/api/v1/sites/"+hq.ID+"/enrollment-tokens", map[string]any{"name": "Windows", "expiresInDays": 1}, &token)
	ctx := context.Background()
	ac := h.agentClient()
	key := newKey(t)
	win := facts("ws-01")
	win.Platform, win.OS = "windows", "Windows Server 2025 Datacenter"
	enr, err := ac.Enroll(ctx, token.Secret, key.Public().(ed25519.PublicKey), win)
	if err != nil {
		t.Fatal(err)
	}
	jobKey, err := agentproto.DecodeKey(enr.JobKey)
	if err != nil {
		t.Fatal(err)
	}
	ac.SetIdentity(enr.DeviceID, key)
	device := enr.DeviceID
	if _, err := h.agentClient().Enroll(ctx, token.Secret, newKey(t).Public().(ed25519.PublicKey), facts("srv-01")); err != nil {
		t.Fatal(err)
	}

	invite(t, h, admin, "tess@acme.example", []map[string]any{{"role": "technician", "organizationId": acme}})
	tech := h.client()
	tech.signIn("tess@acme.example", "a long and unusual passphrase", "")
	invite(t, h, admin, "rory@acme.example", []map[string]any{{"role": "read_only", "organizationId": acme}})
	viewer := h.client()
	viewer.signIn("rory@acme.example", "a long and unusual passphrase", "")

	var dev struct {
		CanCheckHardening bool `json:"canCheckHardening"`
	}
	tech.expect(http.StatusOK, "GET", "/api/v1/devices/"+device, nil, &dev)
	if !dev.CanCheckHardening {
		t.Error("a technician may not check the Windows device's hardening")
	}

	const path = "/api/v1/jobs/hardening"
	for _, c := range []struct {
		body map[string]any
		want string
	}{
		{map[string]any{"deviceIds": []string{device}, "mode": "check", "modules": []string{"ssh"}}, "is not a Linux device"},
		{map[string]any{"deviceIds": []string{device}, "platform": "windows", "mode": "check", "modules": []string{"ssh"}}, `"modules"`},
		{map[string]any{"deviceIds": []string{device}, "platform": "windows", "mode": "check", "modules": []string{"uac"},
			"options": map[string]any{"spoolerOff": true}}, `"options.spoolerOff"`},
		{map[string]any{"deviceIds": []string{device}, "platform": "macos", "mode": "check", "modules": []string{"uac"}}, `"platform"`},
	} {
		r := tech.do("POST", path, c.body)
		wantStatus(t, r, http.StatusUnprocessableEntity, "validation_failed")
		if !strings.Contains(string(r.body), c.want) {
			t.Errorf("%v: %s", c.body, r.body)
		}
	}
	r := tech.do("POST", path, map[string]any{"deviceIds": []string{device}, "platform": "windows", "mode": "apply", "modules": []string{"uac"}})
	wantStatus(t, r, http.StatusUnprocessableEntity, "validation_failed")

	var job struct {
		ID         string `json:"id"`
		Kind       string `json:"kind"`
		Shell      string `json:"shell"`
		ScriptName string `json:"scriptName"`
		Hardening  *struct {
			Platform string   `json:"platform"`
			Mode     string   `json:"mode"`
			Modules  []string `json:"modules"`
		} `json:"hardening"`
	}
	tech.expect(http.StatusCreated, "POST", path, map[string]any{"deviceIds": []string{device}, "platform": "windows", "mode": "check",
		"modules": []string{"laps", "accounts"}, "options": map[string]any{"lockoutExposed": true}}, &job)
	if job.Kind != "hardening" || job.Shell != "powershell" || job.ScriptName != "Check Windows hardening: accounts, laps" ||
		job.Hardening == nil || job.Hardening.Platform != "windows" || !slices.Equal(job.Hardening.Modules, []string{"accounts", "laps"}) {
		t.Errorf("job %+v", job)
	}
	var args struct {
		Args []string `json:"args"`
	}
	tech.expect(http.StatusOK, "GET", "/api/v1/jobs/"+job.ID+"/arguments", nil, &args)
	if !slices.Equal(args.Args, []string{"check", "accounts,laps", "lockout-exposed"}) {
		t.Errorf("arguments %+v", args)
	}
	poll, err := ac.Poll(ctx)
	if err != nil || len(poll.Jobs) != 1 {
		t.Fatalf("poll %+v %v", poll, err)
	}
	p, err := agentproto.VerifyJob(jobKey, poll.Jobs[0], device, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if p.Shell != agentproto.ShellPowerShell || !slices.Equal(p.Args, args.Args) || strings.Contains(p.Script, "#EASYRMM-INCLUDE") ||
		!strings.Contains(p.Script, "function Resolve-ErRegistryOwner") {
		t.Errorf("payload: shell %s, args %q, script of %d bytes", p.Shell, p.Args, len(p.Script))
	}
	if st, err := ac.Start(ctx, p.RunID); err != nil || !st.Proceed {
		t.Fatalf("start %+v %v", st, err)
	}
	// The result of a check of two modules, taken from the check of all.
	if err := ac.Result(ctx, p.RunID, agentproto.ResultRequest{Status: agentproto.RunSucceeded, ExitCode: new(int), Stdout: string(out), StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	var run struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	tech.expect(http.StatusOK, "GET", "/api/v1/job-runs/"+p.RunID, nil, &run)
	if run.Status != "failed" || !strings.Contains(run.Error, "module") {
		t.Errorf("a result for other modules than the job's: %+v", run)
	}

	tech.expect(http.StatusCreated, "POST", path, map[string]any{"deviceIds": []string{device}, "platform": "windows", "mode": "check",
		"modules": windowsModules}, &job)
	if job.ScriptName != "Check Windows hardening (every module)" {
		t.Errorf("job %+v", job)
	}
	poll, err = ac.Poll(ctx)
	if err != nil || len(poll.Jobs) != 1 {
		t.Fatalf("poll %+v %v", poll, err)
	}
	if p, err = agentproto.VerifyJob(jobKey, poll.Jobs[0], device, time.Now()); err != nil {
		t.Fatal(err)
	}
	if st, err := ac.Start(ctx, p.RunID); err != nil || !st.Proceed {
		t.Fatalf("start %+v %v", st, err)
	}
	if err := ac.Result(ctx, p.RunID, agentproto.ResultRequest{Status: agentproto.RunSucceeded, ExitCode: new(int), Stdout: string(out), StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	var got struct {
		Platform *struct {
			Family  string `json:"family"`
			Support string `json:"support"`
			Windows *struct {
				Build            int    `json:"build"`
				InstallationType string `json:"installationType"`
				Role             string `json:"role"`
				Owners           *struct {
					GroupPolicy *bool `json:"groupPolicy"`
				} `json:"owners"`
			} `json:"windows"`
		} `json:"platform"`
		JobID          string `json:"jobId"`
		ControlSources []struct {
			Name string `json:"name"`
		} `json:"controlSources"`
		Modules []struct {
			Module   string `json:"module"`
			State    string `json:"state"`
			Settings []struct {
				ID    string `json:"id"`
				State string `json:"state"`
			} `json:"settings"`
			Related *struct {
				SP80053R5 []struct {
					ID string `json:"id"`
				} `json:"sp80053R5"`
			} `json:"related"`
		} `json:"modules"`
	}
	viewer.expect(http.StatusOK, "GET", "/api/v1/devices/"+device+"/hardening", nil, &got)
	if got.Platform == nil || got.Platform.Family != "windows" || got.Platform.Windows == nil || got.Platform.Windows.Build != 26100 ||
		got.Platform.Windows.InstallationType != "Server Core" || got.Platform.Windows.Owners == nil || got.JobID != job.ID ||
		len(got.ControlSources) == 0 || len(got.Modules) != len(windowsModules) {
		t.Fatalf("hardening %+v", got)
	}
	for i, m := range got.Modules {
		if m.Module != windowsModules[i] || m.State == "" {
			t.Errorf("module %d: %+v", i, m)
		}
	}
	if a := got.Modules[0]; len(a.Settings) == 0 || a.Related == nil || len(a.Related.SP80053R5) == 0 {
		t.Errorf("accounts: %+v", a)
	}

	// The fleet's summary counts a checked Windows device.
	var one struct {
		Hardening *struct {
			States map[string]int `json:"states"`
		} `json:"hardening"`
	}
	viewer.expect(http.StatusOK, "GET", "/api/v1/devices/"+device, nil, &one)
	n := 0
	if one.Hardening != nil {
		for _, c := range one.Hardening.States {
			n += c
		}
	}
	if n != len(windowsModules) {
		t.Errorf("summary %+v", one.Hardening)
	}
}
