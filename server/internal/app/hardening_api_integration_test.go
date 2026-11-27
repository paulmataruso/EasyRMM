//go:build integration

package app_test

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// TestHardeningAPI checks an enrolled Linux device's hardening through the
// console API: the job the agent receives, its result as the device's
// hardening, and who may do what (ADR-0051).
func TestHardeningAPI(t *testing.T) {
	h := newHarness(t, false)
	admin, _ := setUp(t, h)
	acme := orgID(t, admin, "Acme")
	var hq idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/sites", map[string]string{"name": "HQ", "timezone": "UTC"}, &hq)
	var token struct {
		Secret string `json:"secret"`
	}
	admin.expect(http.StatusCreated, "POST", "/api/v1/sites/"+hq.ID+"/enrollment-tokens", map[string]any{"name": "Hardening", "expiresInDays": 1}, &token)
	ctx := context.Background()
	ac := h.agentClient()
	key := newKey(t)
	enr, err := ac.Enroll(ctx, token.Secret, key.Public().(ed25519.PublicKey), facts("srv-01"))
	if err != nil {
		t.Fatal(err)
	}
	jobKey, err := agentproto.DecodeKey(enr.JobKey)
	if err != nil {
		t.Fatal(err)
	}
	ac.SetIdentity(enr.DeviceID, key)
	device := enr.DeviceID

	invite(t, h, admin, "tess@acme.example", []map[string]any{{"role": "technician", "organizationId": acme}})
	tech := h.client()
	tech.signIn("tess@acme.example", "a long and unusual passphrase", "")
	invite(t, h, admin, "rory@acme.example", []map[string]any{{"role": "read_only", "organizationId": acme}})
	viewer := h.client()
	viewer.signIn("rory@acme.example", "a long and unusual passphrase", "")

	var dev struct {
		CanCheckHardening bool `json:"canCheckHardening"`
		CanHarden         bool `json:"canHarden"`
	}
	tech.expect(http.StatusOK, "GET", "/api/v1/devices/"+device, nil, &dev)
	if !dev.CanCheckHardening || dev.CanHarden {
		t.Errorf("a technician: %+v; checks, and does not apply", dev)
	}
	viewer.expect(http.StatusOK, "GET", "/api/v1/devices/"+device, nil, &dev)
	if dev.CanCheckHardening || dev.CanHarden {
		t.Errorf("a read-only user: %+v", dev)
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/devices/"+device, nil, &dev)
	if !dev.CanCheckHardening || !dev.CanHarden {
		t.Errorf("the administrator: %+v", dev)
	}

	var empty struct {
		Platform *struct{} `json:"platform"`
		Modules  []any     `json:"modules"`
	}
	viewer.expect(http.StatusOK, "GET", "/api/v1/devices/"+device+"/hardening", nil, &empty)
	if empty.Platform != nil || empty.Modules == nil || len(empty.Modules) != 0 {
		t.Errorf("before any check: %+v", empty)
	}

	const path = "/api/v1/jobs/hardening"
	r := tech.do("POST", path, map[string]any{"deviceIds": []string{device}, "mode": "check", "modules": []string{"ssh"},
		"options": map[string]any{"allowTcp": []string{"22; reboot"}}})
	wantStatus(t, r, http.StatusUnprocessableEntity, "validation_failed")
	if !strings.Contains(string(r.body), `"options.allowTcp"`) {
		t.Errorf("no allowTcp field error: %s", r.body)
	}
	r = tech.do("POST", path, map[string]any{"deviceIds": []string{device}, "mode": "apply", "modules": []string{"ssh"}})
	wantStatus(t, r, http.StatusUnprocessableEntity, "validation_failed")
	if !strings.Contains(string(r.body), "You cannot apply hardening on srv-01.") {
		t.Errorf("technician's apply: %s", r.body)
	}
	r = viewer.do("POST", path, map[string]any{"deviceIds": []string{device}, "mode": "check", "modules": []string{"ssh"}})
	wantStatus(t, r, http.StatusUnprocessableEntity, "validation_failed")
	if !strings.Contains(string(r.body), "You cannot check hardening on srv-01.") {
		t.Errorf("viewer: %s", r.body)
	}

	var job struct {
		ID         string `json:"id"`
		Kind       string `json:"kind"`
		ScriptName string `json:"scriptName"`
		ArgCount   int    `json:"argCount"`
		Hardening  *struct {
			Mode    string   `json:"mode"`
			Modules []string `json:"modules"`
		} `json:"hardening"`
	}
	tech.expect(http.StatusCreated, "POST", path, map[string]any{"deviceIds": []string{device}, "mode": "check", "modules": []string{"kernel", "ssh"}}, &job)
	if job.Kind != "hardening" || job.ScriptName != "Check hardening: ssh, kernel" || job.Hardening == nil || job.Hardening.Mode != "check" ||
		!slices.Equal(job.Hardening.Modules, []string{"ssh", "kernel"}) || job.ArgCount != 3 {
		t.Errorf("job %+v", job)
	}
	var args struct {
		Args []string `json:"args"`
	}
	tech.expect(http.StatusOK, "GET", "/api/v1/jobs/"+job.ID+"/arguments", nil, &args)
	if !slices.Equal(args.Args, []string{"check", "ssh,kernel", "time-limit=1800"}) {
		t.Errorf("arguments %+v", args)
	}

	poll, err := ac.Poll(ctx, nil, nil)
	if err != nil || len(poll.Jobs) != 1 {
		t.Fatalf("poll %+v %v", poll, err)
	}
	p, err := agentproto.VerifyJob(jobKey, poll.Jobs[0], device, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if p.Shell != agentproto.ShellSh || !slices.Equal(p.Args, []string{"check", "ssh,kernel", "time-limit=1800"}) || p.TimeoutSeconds != 1800 {
		t.Errorf("payload: shell %s, args %q", p.Shell, p.Args)
	}
	if st, err := ac.Start(ctx, p.RunID); err != nil || !st.Proceed {
		t.Fatalf("start %+v %v", st, err)
	}
	out := "Checking ssh\nChecking kernel\nEASYRMM-HARDENING-RESULT-V1 " +
		`{"version":1,"mode":"check","platform":{"id":"debian","versionId":"12","family":"debian","container":"none","support":"full"},` +
		`"modules":[{"module":"ssh","state":"in_place"},{"module":"kernel","state":"partly","missing":["kernel.kptr_restrict = 1"]}]}` + "\n"
	if err := ac.Result(ctx, p.RunID, agentproto.ResultRequest{Status: agentproto.RunSucceeded, ExitCode: new(int), Stdout: out, StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	var got struct {
		Platform *struct {
			ID      string `json:"id"`
			Support string `json:"support"`
		} `json:"platform"`
		JobID   string `json:"jobId"`
		Modules []struct {
			Module  string   `json:"module"`
			State   string   `json:"state"`
			Missing []string `json:"missing"`
			JobID   string   `json:"jobId"`
		} `json:"modules"`
	}
	viewer.expect(http.StatusOK, "GET", "/api/v1/devices/"+device+"/hardening", nil, &got)
	if got.Platform == nil || got.Platform.ID != "debian" || got.Platform.Support != "full" || got.JobID != job.ID || len(got.Modules) != 2 ||
		got.Modules[0].Module != "ssh" || got.Modules[0].State != "in_place" || got.Modules[1].Module != "kernel" ||
		got.Modules[1].State != "partly" || !slices.Equal(got.Modules[1].Missing, []string{"kernel.kptr_restrict = 1"}) || got.Modules[1].JobID != job.ID {
		t.Errorf("hardening %+v", got)
	}

	var list struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	tech.expect(http.StatusOK, "GET", "/api/v1/jobs?kind=hardening", nil, &list)
	if len(list.Items) != 1 || list.Items[0].ID != job.ID {
		t.Errorf("hardening jobs %+v", list.Items)
	}
	wantStatus(t, viewer.do("GET", "/api/v1/devices/00000000-0000-0000-0000-000000000000/hardening", nil), http.StatusNotFound, "")

	// The device's own hardening runs, for its Hardening tab.
	var runs struct {
		Items []struct {
			ID     string `json:"id"`
			JobID  string `json:"jobId"`
			Status string `json:"status"`
		} `json:"items"`
	}
	viewer.expect(http.StatusOK, "GET", "/api/v1/job-runs?deviceId="+device+"&kind=hardening", nil, &runs)
	if len(runs.Items) != 1 || runs.Items[0].ID != p.RunID || runs.Items[0].JobID != job.ID || runs.Items[0].Status != "succeeded" {
		t.Errorf("hardening runs %+v", runs.Items)
	}
	viewer.expect(http.StatusOK, "GET", "/api/v1/job-runs?deviceId="+device+"&kind=software", nil, &runs)
	if len(runs.Items) != 0 {
		t.Errorf("software runs %+v", runs.Items)
	}
	wantStatus(t, viewer.do("GET", "/api/v1/job-runs?deviceId="+device+"&kind=patch", nil), http.StatusUnprocessableEntity, "validation_failed")

	// The fleet: each device's summary, and the filters. A second Linux
	// device and the Windows one are not checked yet.
	if _, err := h.agentClient().Enroll(ctx, token.Secret, newKey(t).Public().(ed25519.PublicKey), facts("srv-02")); err != nil {
		t.Fatal(err)
	}
	win := facts("ws-01")
	win.Platform, win.OS = "windows", "Windows 11 Pro"
	if _, err := h.agentClient().Enroll(ctx, token.Secret, newKey(t).Public().(ed25519.PublicKey), win); err != nil {
		t.Fatal(err)
	}
	type summary struct {
		Name      string `json:"name"`
		Hardening *struct {
			CheckedAt time.Time      `json:"checkedAt"`
			States    map[string]int `json:"states"`
		} `json:"hardening"`
	}
	var one summary
	viewer.expect(http.StatusOK, "GET", "/api/v1/devices/"+device, nil, &one)
	if one.Hardening == nil || one.Hardening.CheckedAt.IsZero() || len(one.Hardening.States) != 2 ||
		one.Hardening.States["in_place"] != 1 || one.Hardening.States["partly"] != 1 {
		t.Errorf("summary %+v", one.Hardening)
	}
	names := func(filter string) []string {
		t.Helper()
		var devs struct{ Items []summary }
		viewer.expect(http.StatusOK, "GET", "/api/v1/devices?hardening="+filter, nil, &devs)
		out := []string{}
		for _, d := range devs.Items {
			out = append(out, d.Name)
			if (d.Hardening != nil) != (d.Name == "srv-01") {
				t.Errorf("%s: hardening %+v", d.Name, d.Hardening)
			}
		}
		return out
	}
	for filter, want := range map[string][]string{"": {"srv-01", "srv-02", "ws-01"}, "attention": {"srv-01"}, "in_place": {}, "unchecked": {"srv-02", "ws-01"}} {
		if got := names(filter); !slices.Equal(got, want) {
			t.Errorf("hardening=%s: %q", filter, got)
		}
	}
	wantStatus(t, viewer.do("GET", "/api/v1/devices?hardening=drifted", nil), http.StatusUnprocessableEntity, "validation_failed")

	// Once the kernel module is in place too, nothing needs attention.
	tech.expect(http.StatusCreated, "POST", path, map[string]any{"deviceIds": []string{device}, "mode": "check", "modules": []string{"kernel"}}, &job)
	poll, err = ac.Poll(ctx, nil, nil)
	if err != nil || len(poll.Jobs) != 1 {
		t.Fatalf("poll %+v %v", poll, err)
	}
	if p, err = agentproto.VerifyJob(jobKey, poll.Jobs[0], device, time.Now()); err != nil {
		t.Fatal(err)
	}
	if st, err := ac.Start(ctx, p.RunID); err != nil || !st.Proceed {
		t.Fatalf("start %+v %v", st, err)
	}
	out = "EASYRMM-HARDENING-RESULT-V1 " +
		`{"version":1,"mode":"check","platform":{"id":"debian","versionId":"12","family":"debian","container":"none","support":"full"},` +
		`"modules":[{"module":"kernel","state":"in_place"}]}` + "\n"
	if err := ac.Result(ctx, p.RunID, agentproto.ResultRequest{Status: agentproto.RunSucceeded, ExitCode: new(int), Stdout: out, StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	for filter, want := range map[string][]string{"attention": {}, "in_place": {"srv-01"}, "unchecked": {"srv-02", "ws-01"}} {
		if got := names(filter); !slices.Equal(got, want) {
			t.Errorf("after the second check, hardening=%s: %q", filter, got)
		}
	}
	one = summary{}
	viewer.expect(http.StatusOK, "GET", "/api/v1/devices/"+device, nil, &one)
	if one.Hardening == nil || len(one.Hardening.States) != 1 || one.Hardening.States["in_place"] != 2 {
		t.Errorf("summary after the second check %+v", one.Hardening)
	}
}
