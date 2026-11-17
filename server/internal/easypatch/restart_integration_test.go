//go:build integration

package easypatch

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
)

func TestRestart(t *testing.T) {
	f := newPatching(t)
	ctx := f.ctx
	f.ep.Set(func() {
		f.ep.Version = "1.10.0"
		f.e1.RebootPending = true
		f.e2.RebootPending, f.e2.IsServer = true, true
	})

	// Who may restart what.
	_, err := f.svc.PlanRestart(ctx, f.viewer, []uuid.UUID{f.web})
	wantErr(t, err, apperr.KindForbidden, "")
	_, err = f.svc.PlanRestart(ctx, f.tech, []uuid.UUID{f.web, f.db})
	wantErr(t, err, apperr.KindNotFound, "")
	_, err = f.svc.PlanRestart(ctx, f.tech, nil)
	wantField(t, err, "deviceIds", "from 1 to 1000")

	// The plan: servers are marked; devices that cannot restart say why.
	plan, err := f.svc.PlanRestart(ctx, f.admin, []uuid.UUID{f.web, f.db, f.app, f.lab, f.web})
	if err != nil || !plan.ServersKnown || len(plan.Devices) != 4 {
		t.Fatalf("plan: %+v, %v", plan, err)
	}
	checks := map[uuid.UUID]RestartCheck{}
	for _, c := range plan.Devices {
		checks[c.DeviceID] = c
	}
	if c := checks[f.web]; !c.Restart || c.Server || !c.Online || c.DeviceName != "web-01" || c.Reason != "" {
		t.Errorf("web-01: %+v", c)
	}
	if c := checks[f.db]; !c.Restart || !c.Server {
		t.Errorf("db-01: %+v", c)
	}
	if c := checks[f.app]; c.Restart || !strings.Contains(c.Reason, "key fingerprint") {
		t.Errorf("app-01: %+v", c)
	}
	if c := checks[f.lab]; c.Restart || !strings.Contains(c.Reason, "no EasyPatch agent") {
		t.Errorf("lab-01: %+v", c)
	}
	if n := len(f.ep.RequestsTo("POST", "/api/v1/endpoints/bulk/restart")); n != 0 {
		t.Fatalf("planning restarted %d", n)
	}

	// A server is restarted only when confirmed by name.
	_, err = f.svc.Restart(ctx, f.admin, RestartInput{DeviceIDs: []uuid.UUID{f.web, f.db}})
	wantField(t, err, "confirmServers", "These are servers; confirm restarting them: db-01.")
	if n := len(f.ep.RequestsTo("POST", "/api/v1/endpoints/bulk/restart")); n != 0 {
		t.Fatalf("an unconfirmed server restart sent %d requests", n)
	}
	res, err := f.svc.Restart(ctx, f.admin, RestartInput{DeviceIDs: []uuid.UUID{f.web, f.db, f.lab}, ConfirmServers: []uuid.UUID{f.db}})
	if err != nil || res.Succeeded != 2 || res.Failed != 1 {
		t.Fatalf("restart: %+v, %v", res, err)
	}
	reqs := f.ep.RequestsTo("POST", "/api/v1/endpoints/bulk/restart")
	if len(reqs) != 1 || reqs[0].OnBehalfOf != "ada@example.com" || len(reqs[0].Body["endpointIds"].([]any)) != 2 {
		t.Fatalf("restart request: %+v", reqs)
	}
	preset := reqs[0].Body["restart"].(map[string]any)
	if preset["mode"] != "Countdown" || preset["condition"] != "OnlyIfPending" || preset["force"] != false || preset["scheduledAt"] != nil ||
		len(preset) != 3 {
		t.Fatalf("restart preset: %+v", preset)
	}
	got := f.audits("patch.restart")
	if len(got) != 2 || got[0].Details["condition"] != "only if a restart is pending" || got[0].Details["jobId"] == nil {
		t.Fatalf("restart audit: %+v", got)
	}
	for _, a := range got {
		if servers, _ := a.Details["confirmedServers"].([]any); len(servers) != 1 || servers[0] != "db-01" {
			t.Fatalf("confirmed servers in the audit: %+v", a.Details)
		}
	}

	// A technician restarts what they may manage; nothing pending, nothing sent.
	f.ep.Set(func() { f.e1.RebootPending = false })
	res, err = f.svc.Restart(ctx, f.tech, RestartInput{DeviceIDs: []uuid.UUID{f.web}})
	if err != nil || res.Failed != 1 || res.Results[0].Message != "No restart is pending." {
		t.Fatalf("nothing pending: %+v, %v", res, err)
	}
	f.ep.Set(func() { f.e1.RebootPending, f.e1.CannotRestart = true, true })
	if plan, err := f.svc.PlanRestart(ctx, f.tech, []uuid.UUID{f.web}); err != nil || plan.Devices[0].Restart ||
		!strings.Contains(plan.Devices[0].Reason, "cannot restart") {
		t.Fatalf("agent that cannot restart: %+v, %v", plan, err)
	}
	if n := len(f.ep.RequestsTo("POST", "/api/v1/endpoints/bulk/restart")); n != 1 {
		t.Fatalf("restart requests: %d", n)
	}
	f.ep.Set(func() { f.e1.CannotRestart = false })

	// Later.
	soon, far, later := time.Now().Add(30*time.Second), time.Now().Add(32*24*time.Hour), time.Now().Add(3*time.Hour)
	_, err = f.svc.Restart(ctx, f.tech, RestartInput{DeviceIDs: []uuid.UUID{f.web}, ScheduledAt: &soon})
	wantField(t, err, "scheduledAt", "in the future")
	_, err = f.svc.Restart(ctx, f.tech, RestartInput{DeviceIDs: []uuid.UUID{f.web}, ScheduledAt: &far})
	wantField(t, err, "scheduledAt", "within 31 days")
	res, err = f.svc.Restart(ctx, f.tech, RestartInput{DeviceIDs: []uuid.UUID{f.web}, ScheduledAt: &later})
	if err != nil || res.Succeeded != 1 {
		t.Fatalf("scheduled restart: %+v, %v", res, err)
	}
	reqs = f.ep.RequestsTo("POST", "/api/v1/endpoints/bulk/restart")
	if at := reqs[len(reqs)-1].Body["restart"].(map[string]any)["scheduledAt"]; at != later.UTC().Format(time.RFC3339Nano) {
		t.Fatalf("scheduledAt sent: %v", at)
	}
	got = f.audits("patch.restart")
	if last := got[len(got)-1]; last.Label != "tess@example.com" || last.Details["scheduledAt"] != later.UTC().Format(time.RFC3339) ||
		last.Details["confirmedServers"] != nil {
		t.Fatalf("scheduled restart audit: %+v", last)
	}

	// EasyPatch before 1.10.0 cannot tell servers apart: every device is
	// confirmed, and the pending restart comes from its endpoint list.
	f.ep.Set(func() { f.ep.Version = "1.9.0" })
	f.svc.fleet.clear()
	plan, err = f.svc.PlanRestart(ctx, f.tech, []uuid.UUID{f.web})
	if err != nil || plan.ServersKnown || !plan.Devices[0].Restart || !plan.Devices[0].Server {
		t.Fatalf("plan with EasyPatch 1.9.0: %+v, %v", plan, err)
	}
	_, err = f.svc.Restart(ctx, f.tech, RestartInput{DeviceIDs: []uuid.UUID{f.web}})
	wantField(t, err, "confirmServers", "EasyPatch cannot say which of these are servers; confirm restarting them: web-01.")
	if res, err := f.svc.Restart(ctx, f.tech, RestartInput{DeviceIDs: []uuid.UUID{f.web}, ConfirmServers: []uuid.UUID{f.web}}); err != nil ||
		res.Succeeded != 1 {
		t.Fatalf("confirmed restart with EasyPatch 1.9.0: %+v, %v", res, err)
	}

	// A read-only token cannot restart.
	f.ep.Set(func() { f.ep.ReadOnly = true })
	if _, err := f.svc.CheckConnection(ctx); err != nil {
		t.Fatal(err)
	}
	_, err = f.svc.PlanRestart(ctx, f.admin, []uuid.UUID{f.web})
	wantErr(t, err, apperr.KindConflict, "easypatch_read_only")
}

func TestRetryJob(t *testing.T) {
	f := newPatching(t)
	ctx := f.ctx
	res, err := f.svc.Install(ctx, f.tech, ActionInput{DeviceIDs: []uuid.UUID{f.web}})
	if err != nil || res.Succeeded != 1 {
		t.Fatalf("install: %+v, %v", res, err)
	}
	first := *res.Results[0].JobID

	// Only a finished job runs again.
	_, err = f.svc.RetryJob(ctx, f.tech, first)
	wantErr(t, err, apperr.KindConflict, "invalid_state")
	f.ep.SetJobStatus(first, "Failed")
	_, err = f.svc.RetryJob(ctx, f.viewer, first)
	wantErr(t, err, apperr.KindForbidden, "")
	_, err = f.svc.RetryJob(ctx, f.outsider, first)
	wantErr(t, err, apperr.KindNotFound, "")
	_, err = f.svc.RetryJob(ctx, f.tech, uuid.New())
	wantErr(t, err, apperr.KindNotFound, "")

	j, err := f.svc.RetryJob(ctx, f.tech, first)
	if err != nil || j.ID == first || j.ID == uuid.Nil || j.DeviceID != f.web || j.DeviceName != "web-01" || !j.CanManage ||
		j.Type != "InstallUpdates" || j.Status != "Queued" {
		t.Fatalf("retry: %+v, %v", j, err)
	}
	reqs := f.ep.RequestsTo("POST", "/api/v1/jobs/"+first.String()+"/retry")
	if len(reqs) != 2 || reqs[1].OnBehalfOf != "tess@example.com" {
		t.Fatalf("retry requests: %+v", reqs)
	}
	got := f.audits("patch.retry")
	if len(got) != 1 || got[0].Label != "tess@example.com" || *got[0].Device != f.web || got[0].Details["retryOf"] != first.String() ||
		got[0].Details["jobId"] != j.ID.String() || got[0].Details["jobType"] != "InstallUpdates" {
		t.Fatalf("retry audit: %+v", got)
	}

	f.ep.Set(func() { f.ep.ReadOnly = true })
	if _, err := f.svc.CheckConnection(ctx); err != nil {
		t.Fatal(err)
	}
	_, err = f.svc.RetryJob(ctx, f.tech, first)
	wantErr(t, err, apperr.KindConflict, "easypatch_read_only")
}

func TestEasyPatchURL(t *testing.T) {
	f := newPatching(t)
	ctx := f.ctx
	at := func(c GoTarget, who ...int) string {
		t.Helper()
		caller := f.admin
		if len(who) > 0 {
			caller = f.tech
		}
		u, err := f.svc.EasyPatchURL(ctx, caller, c)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	const base = "https://patch.example.com" // the public address EasyPatch reports
	job, update := uuid.New(), uuid.New()
	for _, c := range []struct {
		name   string
		target GoTarget
		tech   bool
		want   string
	}{
		{"a linked device", GoTarget{DeviceID: f.web, Tab: "updates"}, false, "/endpoints/" + f.e1.ID.String() + "?from=easyrmm&tab=updates"},
		{"an unknown tab", GoTarget{DeviceID: f.web, Tab: "settings"}, false, "/endpoints/" + f.e1.ID.String() + "?from=easyrmm"},
		{"a device that is not linked", GoTarget{DeviceID: f.lab}, false, "/endpoints?from=easyrmm&search=lab-01"},
		{"a device the person may not see", GoTarget{DeviceID: f.db, Tab: "jobs"}, true, "/endpoints?from=easyrmm"},
		{"a device that does not exist", GoTarget{DeviceID: uuid.New()}, false, "/endpoints?from=easyrmm"},
		{"a linked organization", GoTarget{OrganizationID: f.acme}, false, "/organizations/" + f.epAcme.String() + "?from=easyrmm"},
		{"an organization that is not linked", GoTarget{OrganizationID: f.globex}, false, "/organizations?from=easyrmm"},
		{"an organization the person may not see", GoTarget{OrganizationID: f.globex}, true, "/organizations?from=easyrmm"},
		{"a job", GoTarget{JobID: job}, true, "/jobs/" + job.String() + "?from=easyrmm"},
		{"an update", GoTarget{UpdateID: update}, false, "/updates/" + update.String() + "?from=easyrmm"},
		{"nothing", GoTarget{}, false, "/?from=easyrmm"},
	} {
		var got string
		if c.tech {
			got = at(c.target, 1)
		} else {
			got = at(c.target)
		}
		if got != base+c.want {
			t.Errorf("%s: %s, want %s", c.name, got, base+c.want)
		}
	}
	_, err := f.svc.EasyPatchURL(ctx, f.none, GoTarget{})
	wantErr(t, err, apperr.KindForbidden, "")

	// Not set up: no address.
	if err := f.svc.DeleteConnection(ctx, f.admin.Actor); err != nil {
		t.Fatal(err)
	}
	if u := at(GoTarget{DeviceID: f.web}); u != "" {
		t.Errorf("not set up: %q", u)
	}
}
