//go:build integration

package app_test

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	agentclient "github.com/paulmataruso/easyrmm/agent/client"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

type scriptView struct {
	ID             string `json:"id"`
	Level          string `json:"level"`
	Name           string `json:"name"`
	Description    string `json:"description"`
	Body           string `json:"body"`
	SHA256         string `json:"sha256"`
	TimeoutSeconds int    `json:"timeoutSeconds"`
	CanEdit        bool   `json:"canEdit"`
	CanRun         bool   `json:"canRun"`
}

type runView struct {
	ID            string `json:"id"`
	DeviceName    string `json:"deviceName"`
	Status        string `json:"status"`
	ExitCode      *int   `json:"exitCode"`
	CanCancel     bool   `json:"canCancel"`
	CanViewOutput bool   `json:"canViewOutput"`
	StdoutBytes   *int   `json:"stdoutBytes"`
	Job           *struct {
		Body string `json:"body"`
	} `json:"job"`
}

type jobView struct {
	ID               string         `json:"id"`
	ArgCount         int            `json:"argCount"`
	CanViewArguments bool           `json:"canViewArguments"`
	CanDownload      bool           `json:"canDownloadOutput"`
	Counts           map[string]int `json:"counts"`
	Total            int            `json:"total"`
	Finished         bool           `json:"finished"`
	CanCancel        bool           `json:"canCancel"`
	Runs             []runView      `json:"runs"`
}

// TestJobsAPI runs a script on an enrolled device through the console API and
// the agent API (ADR-0017).
func TestJobsAPI(t *testing.T) {
	h := newHarness(t, false)
	admin, _ := setUp(t, h)
	acme := orgID(t, admin, "Acme")
	var hq idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/sites", map[string]string{"name": "HQ", "timezone": "UTC"}, &hq)
	var token struct {
		Secret string `json:"secret"`
	}
	admin.expect(http.StatusCreated, "POST", "/api/v1/sites/"+hq.ID+"/enrollment-tokens", map[string]any{"name": "Jobs", "expiresInDays": 1}, &token)

	// The agent learns the job key at enrollment and with each heartbeat.
	ctx := context.Background()
	ac := h.agentClient()
	key := newKey(t)
	enr, err := ac.Enroll(ctx, token.Secret, key.Public().(ed25519.PublicKey), facts("job-01"))
	if err != nil {
		t.Fatal(err)
	}
	jobKey, err := agentproto.DecodeKey(enr.JobKey)
	if err != nil {
		t.Fatalf("job key %q: %v", enr.JobKey, err)
	}
	ac.SetIdentity(enr.DeviceID, key)
	if hb, err := ac.Heartbeat(ctx, agentproto.HeartbeatRequest{Facts: facts("job-01")}); err != nil || hb.JobKey != enr.JobKey {
		t.Fatalf("heartbeat job key %+v %v", hb, err)
	}
	device := enr.DeviceID

	// --- Scripts -----------------------------------------------------------
	const scripts = "/api/v1/scripts"
	wantStatus(t, admin.do("POST", scripts, map[string]any{"name": "", "shell": "zsh", "body": ""}), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("POST", scripts, "not an object"), http.StatusBadRequest, "")
	var sc scriptView
	admin.expect(http.StatusCreated, "POST", scripts, map[string]any{"organizationId": acme, "name": "Uptime", "shell": "bash", "body": "uptime \"$@\"", "timeoutSeconds": 60}, &sc)
	if sc.Level != "organization" || !sc.CanEdit || !sc.CanRun || len(sc.SHA256) != 64 {
		t.Errorf("created %+v", sc)
	}
	admin.expect(http.StatusOK, "PATCH", scripts+"/"+sc.ID, map[string]any{"description": "How long it has been up"}, &sc)
	wantStatus(t, admin.do("PATCH", scripts+"/"+sc.ID, "x"), http.StatusBadRequest, "")
	wantStatus(t, admin.do("PATCH", scripts+"/nope", map[string]any{}), http.StatusNotFound, "not_found")
	admin.expect(http.StatusOK, "GET", scripts+"/"+sc.ID, nil, &sc)
	if sc.Body != "uptime \"$@\"" || sc.Description != "How long it has been up" {
		t.Errorf("read back %+v", sc)
	}
	wantStatus(t, admin.do("GET", scripts+"/nope", nil), http.StatusNotFound, "not_found")
	var scriptList struct{ Items []scriptView }
	for query, want := range map[string]int{"?organizationId=" + acme + "&q=UP": 1, "?level=shared": 0, "?deviceId=" + device: 1, "?siteId=" + hq.ID: 0} {
		admin.expect(http.StatusOK, "GET", scripts+query, nil, &scriptList)
		if len(scriptList.Items) != want || (want > 0 && scriptList.Items[0].Body != "") {
			t.Errorf("%s: %+v", query, scriptList.Items)
		}
	}
	for _, q := range []string{"organizationId", "siteId", "deviceId"} {
		wantStatus(t, admin.do("GET", scripts+"?"+q+"=nope", nil), http.StatusUnprocessableEntity, "validation_failed")
	}

	// A technician runs scripts but does not write them.
	invite(t, h, admin, "tess@acme.example", []map[string]any{{"role": "technician", "organizationId": acme}})
	tech := h.client()
	tech.signIn("tess@acme.example", "a long and unusual passphrase", "")
	wantStatus(t, tech.do("POST", scripts, map[string]any{"organizationId": acme, "name": "x", "shell": "sh", "body": "true"}), http.StatusForbidden, "forbidden")
	wantStatus(t, tech.do("DELETE", scripts+"/"+sc.ID, nil), http.StatusForbidden, "forbidden")
	var dev struct {
		CanRunScripts bool `json:"canRunScripts"`
	}
	tech.expect(http.StatusOK, "GET", "/api/v1/devices/"+device, nil, &dev)
	if !dev.CanRunScripts {
		t.Error("technician may not run scripts on the device")
	}

	// --- A job, delivered and run -----------------------------------------
	wantStatus(t, tech.do("POST", "/api/v1/jobs", "x"), http.StatusBadRequest, "")
	wantStatus(t, tech.do("POST", "/api/v1/jobs", map[string]any{"scriptId": sc.ID, "deviceIds": []string{}}), http.StatusUnprocessableEntity, "validation_failed")
	var job jobView
	tech.expect(http.StatusCreated, "POST", "/api/v1/jobs", map[string]any{"scriptId": sc.ID, "deviceIds": []string{device}, "args": []string{"-p"}}, &job)
	if job.Total != 1 || job.Counts["queued"] != 1 || len(job.Runs) != 1 || job.ArgCount != 1 || !job.CanViewArguments {
		t.Fatalf("job %+v", job)
	}
	run := job.Runs[0].ID

	wantStatus(t, h.raw("POST", agentproto.PathJobsPoll, []byte("{}"), ""), http.StatusUnauthorized, "")
	poll, err := ac.Poll(ctx, nil)
	if err != nil || len(poll.Jobs) != 1 {
		t.Fatalf("poll %+v %v", poll, err)
	}
	p, err := agentproto.VerifyJob(jobKey, poll.Jobs[0], device, time.Now())
	if err != nil || p.RunID != run || p.Script != "uptime \"$@\"" || p.Shell != "bash" || p.TimeoutSeconds != 60 {
		t.Fatalf("payload %+v %v", p, err)
	}
	for _, id := range []string{"nope", uuid.NewString()} {
		if _, err := ac.Start(ctx, id); agentclient.Code(err) != "run_not_found" {
			t.Errorf("start %s: %v", id, err)
		}
		if err := ac.Result(ctx, id, agentproto.ResultRequest{Status: "failed"}); agentclient.Code(err) != "run_not_found" {
			t.Errorf("result %s: %v", id, err)
		}
	}
	if st, err := ac.Start(ctx, run); err != nil || !st.Proceed {
		t.Fatalf("start %+v %v", st, err)
	}
	if err := ac.Result(ctx, run, agentproto.ResultRequest{Status: "exploded"}); agentclient.Code(err) != "result_invalid" {
		t.Errorf("bad result: %v", err)
	}
	huge := agentproto.ResultRequest{Status: "failed", Stdout: strings.Repeat("x", agentproto.MaxResultBody)}
	if err := ac.Result(ctx, run, huge); agentclient.Code(err) != "body_too_large" {
		t.Errorf("huge result: %v", err)
	}
	exit := 0
	if err := ac.Result(ctx, run, agentproto.ResultRequest{Status: "succeeded", ExitCode: &exit, Stdout: "up 3 days\n"}); err != nil {
		t.Fatal(err)
	}

	// --- What the console shows -------------------------------------------
	var jobs struct{ Items []jobView }
	tech.expect(http.StatusOK, "GET", "/api/v1/jobs?deviceId="+device+"&scriptId="+sc.ID, nil, &jobs)
	if len(jobs.Items) != 1 || !jobs.Items[0].Finished || jobs.Items[0].Counts["succeeded"] != 1 || jobs.Items[0].CanCancel {
		t.Errorf("jobs %+v", jobs.Items)
	}
	tech.expect(http.StatusOK, "GET", "/api/v1/jobs?status=open", nil, &jobs)
	if len(jobs.Items) != 0 {
		t.Errorf("open jobs %+v", jobs.Items)
	}
	wantStatus(t, tech.do("GET", "/api/v1/jobs?status=sleeping", nil), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, tech.do("GET", "/api/v1/jobs?deviceId=nope", nil), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, tech.do("GET", "/api/v1/jobs?scriptId=nope", nil), http.StatusUnprocessableEntity, "validation_failed")
	tech.expect(http.StatusOK, "GET", "/api/v1/jobs/"+job.ID, nil, &job)
	if len(job.Runs) != 1 || job.Runs[0].Status != "succeeded" || job.Runs[0].DeviceName != "job-01" {
		t.Errorf("job detail %+v", job)
	}
	wantStatus(t, tech.do("GET", "/api/v1/jobs/nope", nil), http.StatusNotFound, "not_found")
	var runs struct{ Items []runView }
	listed := tech.expect(http.StatusOK, "GET", "/api/v1/job-runs?deviceId="+device, nil, &runs)
	if len(runs.Items) != 1 || strings.Contains(string(listed.body), `"stdout`) || strings.Contains(string(listed.body), "canViewOutput") {
		t.Errorf("device runs %s", listed.body)
	}
	wantStatus(t, tech.do("GET", "/api/v1/job-runs", nil), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, tech.do("GET", "/api/v1/job-runs?deviceId=nope", nil), http.StatusUnprocessableEntity, "validation_failed")
	var r runView
	tech.expect(http.StatusOK, "GET", "/api/v1/job-runs/"+run, nil, &r)
	if r.Status != "succeeded" || r.ExitCode == nil || *r.ExitCode != 0 || !r.CanViewOutput || r.StdoutBytes == nil || *r.StdoutBytes != 10 ||
		r.Job == nil || r.Job.Body != "uptime \"$@\"" {
		t.Errorf("run %+v", r)
	}
	var out struct {
		Stdout string `json:"stdout"`
	}
	tech.expect(http.StatusOK, "GET", "/api/v1/job-runs/"+run+"/output", nil, &out)
	if out.Stdout != "up 3 days\n" {
		t.Errorf("output %+v", out)
	}
	wantStatus(t, tech.do("GET", "/api/v1/job-runs/nope", nil), http.StatusNotFound, "not_found")

	// --- Cancellation -------------------------------------------------------
	wantStatus(t, tech.do("POST", "/api/v1/jobs/"+job.ID+"/cancel", nil), http.StatusConflict, "job_finished")
	wantStatus(t, tech.do("POST", "/api/v1/job-runs/"+run+"/cancel", nil), http.StatusConflict, "job_finished")
	wantStatus(t, tech.do("POST", "/api/v1/jobs/nope/cancel", nil), http.StatusNotFound, "not_found")
	wantStatus(t, tech.do("POST", "/api/v1/job-runs/nope/cancel", nil), http.StatusNotFound, "not_found")
	var queued jobView
	tech.expect(http.StatusCreated, "POST", "/api/v1/jobs", map[string]any{"scriptId": sc.ID, "deviceIds": []string{device}}, &queued)
	tech.expect(http.StatusOK, "POST", "/api/v1/jobs/"+queued.ID+"/cancel", nil, &queued)
	if queued.Counts["canceled"] != 1 || !queued.Finished {
		t.Errorf("canceled job %+v", queued)
	}
	tech.expect(http.StatusCreated, "POST", "/api/v1/jobs", map[string]any{"scriptId": sc.ID, "deviceIds": []string{device}}, &queued)
	tech.expect(http.StatusOK, "POST", "/api/v1/job-runs/"+queued.Runs[0].ID+"/cancel", nil, &r)
	if r.Status != "canceled" || r.CanCancel {
		t.Errorf("canceled run %+v", r)
	}

	// Every run is audited for the device; argument values are not.
	var audit struct {
		Items []struct {
			Details map[string]any `json:"details"`
		} `json:"items"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/audit?action=device.script_run&deviceId="+device, nil, &audit)
	if len(audit.Items) != 3 || audit.Items[2].Details["argCount"] != float64(1) || audit.Items[2].Details["script"] != "Uptime" {
		t.Errorf("audit %+v", audit.Items)
	}

	// Deleting the script keeps the jobs that ran it.
	wantStatus(t, admin.do("DELETE", scripts+"/nope", nil), http.StatusNotFound, "not_found")
	admin.expect(http.StatusNoContent, "DELETE", scripts+"/"+sc.ID, nil, nil)
	tech.expect(http.StatusOK, "GET", "/api/v1/jobs/"+job.ID, nil, &job)
	if job.Runs[0].Status != "succeeded" {
		t.Errorf("job after the script was deleted %+v", job)
	}
}
