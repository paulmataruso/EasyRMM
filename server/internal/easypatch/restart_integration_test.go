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
	_, err := f.svc.PlanRestart(ctx, f.viewer, []uuid.UUID{f.web}, "")
	wantErr(t, err, apperr.KindForbidden, "")
	_, err = f.svc.PlanRestart(ctx, f.tech, []uuid.UUID{f.web, f.db}, "")
	wantErr(t, err, apperr.KindNotFound, "")
	_, err = f.svc.PlanRestart(ctx, f.tech, nil, "")
	wantField(t, err, "deviceIds", "from 1 to 1000")

	// The plan: servers are marked; devices that cannot restart say why.
	plan, err := f.svc.PlanRestart(ctx, f.admin, []uuid.UUID{f.web, f.db, f.app, f.lab, f.web}, "")
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
	if len(reqs) != 1 || reqs[0].Statement.Name != "ada@example.com" || len(reqs[0].Body["endpointIds"].([]any)) != 2 {
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
	if plan, err := f.svc.PlanRestart(ctx, f.tech, []uuid.UUID{f.web}, ""); err != nil || plan.Devices[0].Restart ||
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
	plan, err = f.svc.PlanRestart(ctx, f.tech, []uuid.UUID{f.web}, "")
	if err != nil || plan.ServersKnown || !plan.Devices[0].Restart || !plan.Devices[0].Server {
		t.Fatalf("plan with EasyPatch 1.9.0: %+v, %v", plan, err)
	}
	_, err = f.svc.Restart(ctx, f.tech, RestartInput{DeviceIDs: []uuid.UUID{f.web}})
	wantField(t, err, "confirmServers", "The patching engine cannot say which of these are servers; confirm restarting them: web-01.")
	if res, err := f.svc.Restart(ctx, f.tech, RestartInput{DeviceIDs: []uuid.UUID{f.web}, ConfirmServers: []uuid.UUID{f.web}}); err != nil ||
		res.Succeeded != 1 {
		t.Fatalf("confirmed restart with EasyPatch 1.9.0: %+v, %v", res, err)
	}
}

// TestRestartOptions: how a restart asks the people signed in, whether it
// needs a pending restart, and how long it waits for an offline computer.
func TestRestartOptions(t *testing.T) {
	f := newPatching(t)
	ctx := f.ctx
	f.ep.Set(func() {
		f.ep.Version = "1.10.0"
		f.e1.RebootPending = true
	})
	n := func(v int) *int { return &v }
	web := []uuid.UUID{f.web}

	// What EasyPatch would refuse is refused first, and nothing is sent.
	for field, o := range map[string]RestartOptions{
		"mode":                {Mode: "Reboot"},
		"condition":           {Condition: "Sometimes"},
		"countdownMinutes":    {CountdownMinutes: n(61)},
		"deadlineMinutes":     {Mode: "PromptWithDeadline", DeadlineMinutes: n(10)},
		"expiresAfterMinutes": {ExpiresAfterMinutes: n(14)},
	} {
		_, err := f.svc.Restart(ctx, f.tech, RestartInput{DeviceIDs: web, RestartOptions: o})
		wantField(t, err, field, "Choose")
	}
	_, err := f.svc.PlanRestart(ctx, f.tech, web, "Sometimes")
	wantField(t, err, "condition", "Choose")
	if n := len(f.ep.RequestsTo("POST", "/api/v1/endpoints/bulk/restart")); n != 0 {
		t.Fatalf("refused restarts sent %d requests", n)
	}

	// A prompt with a deadline: minutes the mode does not use are dropped.
	res, err := f.svc.Restart(ctx, f.tech, RestartInput{DeviceIDs: web, RestartOptions: RestartOptions{
		Mode: "PromptWithDeadline", DeadlineMinutes: n(480), CountdownMinutes: n(9), ExpiresAfterMinutes: n(60), Force: true}})
	if err != nil || res.Succeeded != 1 {
		t.Fatalf("prompt with a deadline: %+v, %v", res, err)
	}
	reqs := f.ep.RequestsTo("POST", "/api/v1/endpoints/bulk/restart")
	sent := reqs[len(reqs)-1].Body["restart"].(map[string]any)
	if sent["mode"] != "PromptWithDeadline" || sent["condition"] != "OnlyIfPending" || sent["deadlineMinutes"] != float64(480) ||
		sent["countdownMinutes"] != nil || sent["expiresAfterMinutes"] != float64(60) || sent["force"] != false {
		t.Fatalf("restart sent: %+v", sent)
	}
	got := f.audits("patch.restart")
	if last := got[len(got)-1]; last.Details["mode"] != "when a signed-in user agrees, at the latest after 480 minutes" ||
		last.Details["expiresAfterMinutes"] != float64(60) || last.Details["condition"] != "only if a restart is pending" {
		t.Fatalf("restart audit: %+v", last.Details)
	}
	for mode, want := range map[string]string{"Immediate": "at once", "PromptNoDeadline": "when a signed-in user agrees",
		"Countdown": "after a 15-minute countdown"} {
		if _, err := f.svc.Restart(ctx, f.tech, RestartInput{DeviceIDs: web,
			RestartOptions: RestartOptions{Mode: mode, CountdownMinutes: n(15), DeadlineMinutes: n(60)}}); err != nil {
			t.Fatal(err)
		}
		got := f.audits("patch.restart")
		if last := got[len(got)-1]; last.Details["mode"] != want {
			t.Fatalf("%s audit: %+v", mode, last.Details)
		}
	}

	// Whether or not a restart is pending: servers are told apart by their
	// product type, and agents that cannot restart say so.
	f.ep.Set(func() {
		f.e1.RebootPending = false
		f.e2.IsServer = true
	})
	if plan, err := f.svc.PlanRestart(ctx, f.admin, []uuid.UUID{f.web, f.db}, ""); err != nil || plan.Devices[0].Restart || plan.Devices[1].Restart {
		t.Fatalf("nothing pending: %+v, %v", plan, err)
	}
	plan, err := f.svc.PlanRestart(ctx, f.admin, []uuid.UUID{f.web, f.db}, "Always")
	if err != nil || len(plan.Devices) != 2 {
		t.Fatalf("always: %+v, %v", plan, err)
	}
	if c := plan.Devices[0]; !c.Restart || c.Server || !c.Online {
		t.Fatalf("web-01, always: %+v", c)
	}
	if c := plan.Devices[1]; !c.Restart || !c.Server {
		t.Fatalf("db-01, always: %+v", c)
	}
	always := RestartOptions{Condition: "Always"}
	_, err = f.svc.Restart(ctx, f.admin, RestartInput{DeviceIDs: []uuid.UUID{f.web, f.db}, RestartOptions: always})
	wantField(t, err, "confirmServers", "These are servers; confirm restarting them: db-01.")
	res, err = f.svc.Restart(ctx, f.admin, RestartInput{DeviceIDs: []uuid.UUID{f.web, f.db}, RestartOptions: always, ConfirmServers: []uuid.UUID{f.db}})
	if err != nil || res.Succeeded != 2 {
		t.Fatalf("restart always: %+v, %v", res, err)
	}
	reqs = f.ep.RequestsTo("POST", "/api/v1/endpoints/bulk/restart")
	if sent := reqs[len(reqs)-1].Body["restart"].(map[string]any); sent["condition"] != "Always" {
		t.Fatalf("restart always sent: %+v", sent)
	}
	got = f.audits("patch.restart")
	if last := got[len(got)-1]; last.Details["condition"] != "always" {
		t.Fatalf("restart always audit: %+v", last.Details)
	}
	f.ep.Set(func() { f.e1.CannotRestart = true })
	if plan, err := f.svc.PlanRestart(ctx, f.tech, web, "Always"); err != nil || plan.Devices[0].Restart ||
		!strings.Contains(plan.Devices[0].Reason, "cannot restart") {
		t.Fatalf("always, agent that cannot restart: %+v, %v", plan, err)
	}
	many := make([]uuid.UUID, maxAlwaysRestart+1)
	for i := range many {
		many[i] = uuid.New()
	}
	_, err = f.svc.PlanRestart(ctx, f.admin, many, "Always")
	wantField(t, err, "deviceIds", "at most 100 devices")
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
	if len(reqs) != 2 || reqs[1].Statement.Name != "tess@example.com" {
		t.Fatalf("retry requests: %+v", reqs)
	}
	got := f.audits("patch.retry")
	if len(got) != 1 || got[0].Label != "tess@example.com" || *got[0].Device != f.web || got[0].Details["retryOf"] != first.String() ||
		got[0].Details["jobId"] != j.ID.String() || got[0].Details["jobType"] != "InstallUpdates" {
		t.Fatalf("retry audit: %+v", got)
	}

	// The engine refusing EasyRMM's change.
	f.ep.Set(func() { f.ep.ReadOnly = true })
	_, err = f.svc.RetryJob(ctx, f.tech, first)
	wantErr(t, err, apperr.KindUnavailable, "patching_unavailable")
}

// TestConnectionHealth: what counts as the engine failing, and what clears it.
func TestConnectionHealth(t *testing.T) {
	f := newPatching(t)
	ctx := f.ctx
	failing := func() *time.Time {
		t.Helper()
		conn, err := f.svc.Connection(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if conn.LastErrorAt != nil && (conn.CheckedAt == nil || conn.LastErrorAt.After(*conn.CheckedAt)) {
			return conn.LastErrorAt
		}
		return nil
	}

	// The engine refusing one request says nothing about the server.
	f.ep.RemoveEndpoint(f.e2.ID)
	if d, err := f.svc.Device(ctx, f.admin, f.db); err != nil || d.Error == "" {
		t.Fatalf("device whose endpoint was deleted: %+v, %v", d, err)
	}
	if at := failing(); at != nil {
		t.Fatalf("a 404 counted as the engine failing: %v", at)
	}

	// The engine failing is recorded until a check succeeds.
	f.ep.Set(func() { f.ep.Down = true })
	if d, err := f.svc.Device(ctx, f.admin, f.web); err != nil || d.Error == "" {
		t.Fatalf("device while the engine is down: %+v, %v", d, err)
	}
	if failing() == nil {
		t.Fatal("while down: not recorded")
	}
	f.ep.Set(func() { f.ep.Down = false })
	if _, err := f.svc.CheckConnection(ctx); err != nil {
		t.Fatal(err)
	}
	if at := failing(); at != nil {
		t.Fatalf("after a good check: %v", at)
	}
}
