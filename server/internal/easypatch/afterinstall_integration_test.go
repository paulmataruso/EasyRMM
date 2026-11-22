//go:build integration

package easypatch

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/easypatch/eptest"
)

// Restarts after installs and installs of every available update, on the
// paths where the patching engine's own rules decide the outcome: its
// timeout of a silent agent, its limit of 500 chosen updates, and its
// duplicate guard on restarts. eptest, the stand-in, copies each rule from
// the engine's source; the contract test checks the stand-in against the
// real engine.

// midwayCountOf reads how many restarts an install's restart asked for
// while the install waited for one.
func (f *patchingFixture) midwayCountOf(job uuid.UUID) int {
	f.t.Helper()
	var n int
	err := f.fixture.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT midway_count FROM easypatch_install_restarts WHERE install_job_id = $1`, job).Scan(&n)
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return n
}

// restartRequests counts the restarts asked of the engine.
func (f *patchingFixture) restartRequests() int {
	return len(f.ep.RequestsTo("POST", "/api/v1/endpoints/bulk/restart"))
}

// TestRestartAfterTimedOutInstall: the engine fails an install whose agent
// stopped reporting, and takes the agent's late result after all
// (MaintenanceTasks.cs, JobTransitions.AgentMayTransition), so the restart
// waits for it.
func TestRestartAfterTimedOutInstall(t *testing.T) {
	f := newPatching(t)
	job := f.installWithRestart(AfterInstall{Condition: conditionAlways})
	f.ep.SetJobStatus(job, "Running")
	f.ep.TimeOutJob(job)
	f.sweep(f.svc)
	if state, msg, _, _, _ := f.restartRowOf(job); state != afterWaiting || !strings.Contains(msg, "timed out") ||
		!strings.Contains(msg, "waits for it until") || f.restartRequests() != 0 {
		t.Fatalf("timed out: %s %q", state, msg)
	}
	// The stand-in takes a late result only for a timed-out job.
	other := f.installWithRestart(AfterInstall{Condition: conditionAlways})
	f.ep.SetJobStatus(other, "Failed")
	if f.ep.ReportJob(other, "Completed") {
		t.Fatal("a failed job took a late result")
	}
	if !f.ep.ReportJob(job, "Completed") {
		t.Fatal("the timed-out job refused its late result")
	}
	f.sweep(f.svc)
	if state, _, restart, _, _ := f.restartRowOf(job); state != afterDone || restart == nil || f.restartRequests() != 1 {
		t.Fatalf("late result: %s %v", state, restart)
	}
	if state, msg, _, _, _ := f.restartRowOf(other); state != afterSkipped || !strings.Contains(msg, "failed") {
		t.Fatalf("failed: %s %q", state, msg)
	}
}

// TestInstallAvailableSplits: the engine takes at most 500 chosen updates
// in one install (JobService.CreateAsync), so a device with more installs
// them in several jobs, and restarts once they have all finished.
func TestInstallAvailableSplits(t *testing.T) {
	f := newPatching(t)
	ctx := f.ctx
	updates := make([]map[string]any, 1203)
	for i := range updates {
		updates[i] = eptest.NewUpdate(fmt.Sprintf("KB59%05d Security", i), "Security", "Missing")
	}
	f.setUpdates(f.e1, updates...)

	// The stand-in refuses more than 500, as the engine.
	guids := make([]uuid.UUID, MaxSelected+1)
	for i := range guids {
		guids[i] = guidOf(t, updates[i])
	}
	cl := f.svc.engine.client
	_, err := cl.Install(f.svc.as(ctx, f.tech, RoleAdmin, f.epAcme), f.e1.ID, guids, nil, "tess@example.com")
	if !IsStatus(err, http.StatusBadRequest) {
		t.Fatalf("501 updates: %v", err)
	}
	// Chosen updates: no more than one install takes.
	_, err = f.svc.Install(ctx, f.tech, InstallInput{DeviceIDs: []uuid.UUID{f.web}, UpdateIDs: guids})
	wantField(t, err, "updateIds", "at most 500 updates")

	res, err := f.svc.Install(ctx, f.tech, InstallInput{DeviceIDs: []uuid.UUID{f.web}, Updates: UpdatesAvailable,
		Restart: &AfterInstall{Condition: conditionAlways}})
	if err != nil || res.Succeeded != 1 || len(res.Results[0].JobIDs) != 3 || *res.Results[0].JobID != res.Results[0].JobIDs[2] ||
		res.Results[0].Message != "Installs its 1,203 updates in 3 jobs of at most 500, one after another." || *res.RestartAfter != 1 {
		t.Fatalf("install: %+v, %v", res, err)
	}
	jobs := res.Results[0].JobIDs
	reqs := f.ep.RequestsTo("POST", "/api/v1/endpoints/"+f.e1.ID.String()+"/install-updates")
	var sizes []int
	for _, r := range reqs[1:] {
		sizes = append(sizes, len(r.Body["updateGuids"].([]any)))
	}
	if !slices.Equal(sizes, []int{500, 500, 203}) {
		t.Fatalf("sent: %v", sizes)
	}
	got := f.audits("patch.install")
	if len(got) != 3 || got[0].Details["part"] != "1 of 3" || got[2].Details["updateCount"] != float64(203) ||
		got[2].Details["jobId"] != jobs[2].String() {
		t.Fatalf("audit: %+v", got)
	}
	if d, err := f.svc.Job(ctx, f.tech, jobs[0]); err != nil || d.RestartAfter == nil || d.RestartAfter.InstallJobs != 3 {
		t.Fatalf("first job: %+v, %v", d.RestartAfter, err)
	}

	// The restart waits for every one of them.
	f.ep.SetJobStatus(jobs[0], "Completed")
	f.ep.SetJobStatus(jobs[1], "Completed")
	f.sweep(f.svc)
	if state, _, _, _, _ := f.restartRowOf(jobs[2]); state != afterWaiting || f.restartRequests() != 0 {
		t.Fatalf("two of three: %s", state)
	}
	f.ep.SetJobStatus(jobs[2], "Completed")
	f.sweep(f.svc)
	if state, _, _, _, _ := f.restartRowOf(jobs[2]); state != afterDone || f.restartRequests() != 1 {
		t.Fatalf("all three: %s", state)
	}

	// One of them failing restarts nothing.
	res, err = f.svc.Install(ctx, f.tech, InstallInput{DeviceIDs: []uuid.UUID{f.web}, Updates: UpdatesAvailable,
		Restart: &AfterInstall{Condition: conditionAlways}})
	if err != nil || len(res.Results[0].JobIDs) != 3 {
		t.Fatalf("again: %+v, %v", res, err)
	}
	jobs = res.Results[0].JobIDs
	f.ep.SetJobStatus(jobs[0], "Completed")
	f.ep.SetJobStatus(jobs[1], "Failed")
	f.ep.SetJobStatus(jobs[2], "Completed")
	f.sweep(f.svc)
	if state, msg, _, _, _ := f.restartRowOf(jobs[2]); state != afterSkipped || msg != "One of the install's 3 jobs failed, so the device was not restarted." {
		t.Fatalf("one failed: %s %q", state, msg)
	}

	// The engine refusing a later part says what was sent.
	calls := 0
	f.ep.Set(func() {
		f.ep.LoseReply = func(_, path string) bool {
			if strings.HasSuffix(path, "/install-updates") {
				calls++
				if calls == 2 {
					f.e1.Missing = 0
				}
			}
			return false
		}
	})
	res, err = f.svc.Install(ctx, f.tech, InstallInput{DeviceIDs: []uuid.UUID{f.web}, Updates: UpdatesAvailable})
	if err != nil || res.Succeeded != 1 || len(res.Results[0].JobIDs) != 0 || res.Results[0].JobID == nil ||
		!strings.HasPrefix(res.Results[0].Message, "Installs 500 of its 1,203 updates, in 1 job; the patching engine did not take the rest:") {
		t.Fatalf("partly: %+v, %v", res, err)
	}
}

// TestRestartAfterInstallScheduledRestart: the engine refuses a second
// restart of a device as a duplicate, whenever either is to start
// (JobService.CreateAsync, dedupe key "restart"). A restart already
// scheduled for later is not taken for the one right after the install.
func TestRestartAfterInstallScheduledRestart(t *testing.T) {
	f := newPatching(t)
	ctx := f.ctx
	later := time.Now().Add(3 * time.Hour).Truncate(time.Minute)
	always := RestartOptions{Condition: conditionAlways}
	res, err := f.svc.Restart(ctx, f.tech, RestartInput{Targets: Targets{DeviceIDs: []uuid.UUID{f.web}}, RestartOptions: RestartOptions{Condition: conditionAlways, ScheduledAt: &later}})
	if err != nil || res.Succeeded != 1 {
		t.Fatalf("scheduled: %+v, %v", res, err)
	}
	scheduled := *res.Results[0].JobID

	// Midway: the install keeps waiting, and EasyRMM asks again later.
	job := f.installWithRestart(AfterInstall{Condition: conditionAlways})
	f.ep.SetJobStatus(job, "WaitingForReboot")
	f.sweep(f.svc)
	state, msg, _, midway, claimed := f.restartRowOf(job)
	if state != afterWaiting || midway != nil || claimed || !strings.Contains(msg, "already scheduled for "+whenText(later)) ||
		f.midwayCountOf(job) != 0 || len(f.restartJobs()) != 1 {
		t.Fatalf("midway: %s %q %v %v", state, msg, midway, claimed)
	}

	// Final: the install finishes when that restart runs; EasyRMM neither
	// cancels it nor asks for another, and says so.
	f.ep.SetJobStatus(job, "Completed")
	f.sweep(f.svc)
	state, msg, restart, _, _ := f.restartRowOf(job)
	if state != afterSkipped || restart == nil || *restart != scheduled || len(f.restartJobs()) != 1 ||
		msg != "A restart was already scheduled for "+whenText(later)+", so EasyRMM did not ask for another: the device restarts then, which finishes the install." {
		t.Fatalf("final: %s %q %v", state, msg, restart)
	}
	if j := f.restartJobs()[0]; j.Status != "Queued" {
		t.Fatalf("the scheduled restart: %s", j.Status)
	}
	got := f.audits("patch.restart")
	if last := got[len(got)-1]; last.Details["scheduledRestart"] != scheduled.String() || last.Details["afterInstall"] != job.String() ||
		last.Details["scheduledAt"] != later.UTC().Format(time.RFC3339) || !strings.Contains(last.Details["reason"].(string), "already scheduled") {
		t.Fatalf("audit: %+v", last)
	}

	// One that starts now is the install's restart.
	f.ep.SetJobStatus(scheduled, statusCanceled)
	res, err = f.svc.Restart(ctx, f.tech, RestartInput{Targets: Targets{DeviceIDs: []uuid.UUID{f.web}}, RestartOptions: always})
	if err != nil || res.Succeeded != 1 {
		t.Fatalf("now: %+v, %v", res, err)
	}
	now := *res.Results[0].JobID
	job = f.installWithRestart(AfterInstall{Condition: conditionAlways})
	f.ep.SetJobStatus(job, "Completed")
	f.sweep(f.svc)
	if state, _, restart, _, _ := f.restartRowOf(job); state != afterDone || restart == nil || *restart != now || len(f.restartJobs()) != 2 {
		t.Fatalf("adopted: %s %v", state, restart)
	}
}

// TestRestartClaimedOnce: each of EasyRMM's servers moves restarts on, and
// only one asks for each: a server that read an install before another
// asked for its restart does not ask again.
func TestRestartClaimedOnce(t *testing.T) {
	f := newPatching(t)
	a, b := f.engineService(f.ep), f.engineService(f.ep)
	job := f.installWithRestart(AfterInstall{Condition: conditionAlways})
	f.ep.SetJobStatus(job, "WaitingForReboot")

	// b read the install, then a asked for the midway restart, which ran.
	rows, err := b.waitingRestarts(f.ctx, time.Now())
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows: %d %v", len(rows), err)
	}
	f.sweep(a)
	f.finishRestarts()
	if ok, err := b.afterInstall(f.ctx, b.engine.client, rows[0], time.Now()); ok || err != nil || f.restartRequests() != 1 {
		t.Fatalf("stale: %v %v %d", ok, err, f.restartRequests())
	}

	// Both at once, each time the install waits for a restart again: one
	// asks.
	both := func() {
		var wg sync.WaitGroup
		for _, svc := range []*Service{a, b} {
			wg.Go(func() {
				if _, err := svc.SweepRestarts(f.ctx); err != nil {
					t.Error(err)
				}
			})
		}
		wg.Wait()
	}
	for want := 2; want <= 3; want++ {
		f.ep.ReportJob(job, "WaitingForReboot")
		both()
		both()
		if n := f.restartRequests(); n != want || f.midwayCountOf(job) != want {
			t.Fatalf("round %d: %d requests, %d midway", want, n, f.midwayCountOf(job))
		}
		f.finishRestarts()
	}
	// The final restart, too.
	f.ep.SetJobStatus(job, "Completed")
	rows, err = b.waitingRestarts(f.ctx, time.Now())
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows: %d %v", len(rows), err)
	}
	both()
	if ok, err := b.afterInstall(f.ctx, b.engine.client, rows[0], time.Now()); ok || err != nil || f.restartRequests() != 4 {
		t.Fatalf("final: %v %v %d", ok, err, f.restartRequests())
	}
	if state, _, _, _, _ := f.restartRowOf(job); state != afterDone {
		t.Fatalf("final: %s", state)
	}
}

// TestRestartMidwayBound: EasyRMM asks for a restart each time the install
// waits for one again, up to maxMidway.
func TestRestartMidwayBound(t *testing.T) {
	f := newPatching(t)
	job := f.installWithRestart(AfterInstall{Condition: conditionAlways})
	f.ep.SetJobStatus(job, "WaitingForReboot")
	for i := 1; i <= maxMidway; i++ {
		f.sweep(f.svc)
		// While the restart is to run, and once it ran without the install
		// reporting since, nothing more is asked.
		f.sweep(f.svc)
		f.finishRestarts()
		f.sweep(f.svc)
		if n := f.restartRequests(); n != i || f.midwayCountOf(job) != i {
			t.Fatalf("restart %d: %d requests", i, n)
		}
		f.ep.ReportJob(job, "WaitingForReboot")
	}
	f.sweep(f.svc)
	state, msg, _, _, _ := f.restartRowOf(job)
	if state != afterWaiting || f.restartRequests() != maxMidway || !strings.Contains(msg, "asks for no more") {
		t.Fatalf("bound: %s %q", state, msg)
	}
	if d, err := f.svc.Job(f.ctx, f.tech, job); err != nil || d.RestartAfter.MidwayCount != maxMidway {
		t.Fatalf("job: %+v, %v", d.RestartAfter, err)
	}
	// The install goes on once restarted by hand, and the last restart is
	// asked for.
	f.ep.ReportJob(job, "Completed")
	f.sweep(f.svc)
	if state, _, _, _, _ := f.restartRowOf(job); state != afterDone || f.restartRequests() != maxMidway+1 {
		t.Fatalf("final: %s", state)
	}
}

// TestInstallRequestEnds: a request that ends while a Patch all is sent
// (a closed tab) leaves no install the engine started without its restart.
func TestInstallRequestEnds(t *testing.T) {
	f := newPatching(t)
	f.svc.batchSize = 1
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	f.ep.Set(func() {
		f.ep.LoseReply = func(_, path string) bool {
			if path == "/api/v1/endpoints/bulk/install-updates" {
				cancel()
			}
			return false
		}
	})
	res, err := f.svc.Install(ctx, f.admin, InstallInput{All: true, OrganizationID: f.acme, Restart: &AfterInstall{Condition: conditionPending}})
	if err != nil || res.Succeeded != 1 || res.Failed != 1 || len(res.Batches) != 2 || res.Batches[0].Sent != 1 ||
		res.Results[1].Message != requestEnded || res.RestartAfter == nil || *res.RestartAfter != 1 {
		t.Fatalf("install: %+v, %v", res, err)
	}
	var installs int
	for _, j := range f.ep.Jobs() {
		if j.Type != "InstallUpdates" {
			continue
		}
		installs++
		if state, _, _, _, _ := f.restartRowOf(j.ID); state != afterWaiting {
			t.Fatalf("install %s: %s", j.ID, state)
		}
	}
	if installs != 1 || len(f.audits("patch.install_all")) != 1 {
		t.Fatalf("installs: %d", installs)
	}
}

// TestRestartSweepBounded: a pass of restarts after installs ends early
// when the engine keeps failing or hangs, and runs beside the patching
// loop, not in it.
func TestRestartSweepBounded(t *testing.T) {
	f := newPatching(t)
	for range 5 {
		f.installWithRestart(AfterInstall{Condition: conditionAlways})
	}
	reads := 0
	f.ep.Set(func() {
		f.ep.LoseReply = func(method, path string) bool {
			if method == http.MethodGet && strings.HasPrefix(path, "/api/v1/jobs/") {
				reads++
				return true
			}
			return false
		}
	})
	_, err := f.svc.SweepRestarts(f.ctx)
	if err == nil || !strings.Contains(err.Error(), "failed 3 times in a row; 2 installs left") {
		t.Fatalf("failing: %v", err)
	}
	f.ep.Set(func() {
		if reads != restartFailures {
			t.Errorf("read %d installs", reads)
		}
		f.ep.LoseReply = nil
	})

	// Hanging: the pass ends at its deadline.
	svc := f.engineService(f.ep)
	svc.restartPass = 300 * time.Millisecond
	f.ep.Set(func() {
		f.ep.Hang = func(method, path string) bool {
			return method == http.MethodGet && strings.HasPrefix(path, "/api/v1/jobs/")
		}
	})
	start := time.Now()
	_, err = svc.SweepRestarts(f.ctx)
	if took := time.Since(start); err == nil || !strings.Contains(err.Error(), "ran out of time") || took > 5*time.Second {
		t.Fatalf("hanging: %v after %v", err, took)
	}

	// Beside the patching loop: a hanging pass holds up no reconcile.
	svc = f.engineService(f.ep)
	svc.restartEvery, svc.restartPass = 10*time.Millisecond, time.Minute
	var hanging, others atomic.Int32
	f.ep.Set(func() {
		f.ep.Hang = func(method, path string) bool {
			if method == http.MethodGet && strings.HasPrefix(path, "/api/v1/jobs/") {
				hanging.Add(1)
				return true
			}
			others.Add(1)
			return false
		}
	})
	ctx, cancel := context.WithCancel(f.ctx)
	done := make(chan struct{})
	go func() { svc.Run(ctx); close(done) }()
	waitFor(t, "a hanging pass", func() bool { return hanging.Load() > 0 })
	svc.Kick()
	waitFor(t, "a reconcile", func() bool { return others.Load() > 0 })
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
	f.ep.Set(func() { f.ep.Hang = nil })
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("no %s", what)
}

// TestRestartAfterInstallLimits: the 40 days count from when the install
// was to start; a requester deleted since is not acted for; finished
// restarts are kept as long as the engine keeps a finished job.
func TestRestartAfterInstallLimits(t *testing.T) {
	f := newPatching(t)
	ctx := f.ctx
	at := time.Now().Add(30 * 24 * time.Hour)
	res, err := f.svc.Install(ctx, f.tech, InstallInput{DeviceIDs: []uuid.UUID{f.web}, ScheduledAt: &at,
		Restart: &AfterInstall{Condition: conditionAlways}})
	if err != nil || res.Succeeded != 1 {
		t.Fatalf("scheduled: %+v, %v", res, err)
	}
	job := *res.Results[0].JobID
	f.sweep(f.engineServiceWithClock(time.Now().Add(41 * 24 * time.Hour)))
	if state, _, _, _, _ := f.restartRowOf(job); state != afterWaiting {
		t.Fatalf("41 days: %s", state)
	}
	f.sweep(f.engineServiceWithClock(time.Now().Add(71 * 24 * time.Hour)))
	if state, msg, _, _, _ := f.restartRowOf(job); state != afterSkipped || !strings.Contains(msg, "40 days of when it was to start") {
		t.Fatalf("71 days: %s %q", state, msg)
	}

	// The technician deleted: the install's restart is not asked for on
	// their behalf.
	job = f.installWithRestart(AfterInstall{Condition: conditionAlways})
	f.ep.SetJobStatus(job, "Completed")
	f.exec(`DELETE FROM users WHERE id = $1`, f.tech.Actor.ID)
	f.sweep(f.svc)
	if state, msg, _, _, _ := f.restartRowOf(job); state != afterSkipped || !strings.Contains(msg, "was deleted") || f.restartRequests() != 0 {
		t.Fatalf("deleted: %s %q", state, msg)
	}

	// Pruned after 180 days.
	f.exec(`UPDATE easypatch_install_restarts SET finished_at = now() - interval '181 days' WHERE install_job_id = $1`, job)
	f.sweep(f.svc)
	var left int
	err = f.fixture.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM easypatch_install_restarts`).Scan(&left)
	})
	if err != nil || left != 1 {
		t.Fatalf("pruned: %d %v", left, err)
	}
}

// TestInstallAvailableCounts: approved application updates still in the
// rollout delay are installed, not "not approved"; excluded updates already
// installed are not left out; and the rollout delay can be respected.
func TestInstallAvailableCounts(t *testing.T) {
	f := newPatching(t)
	ctx := f.ctx
	soon := time.Now().Add(72 * time.Hour).UTC().Format(time.RFC3339)
	security := eptest.NewUpdate("KB5080001 Security", "Security", "Missing")
	delayed := with(eptest.NewUpdate("KB5080002 Cumulative", "Cumulative", "Missing"), "deferredUntil", soon)
	appApproved := with(eptest.NewUpdate("Some.App 3.0", "Application", "Missing"), "isRequired", true)
	appDelayed := with(eptest.NewUpdate("Other.App 4.0", "Application", "Missing"), "deferredUntil", soon)
	appNot := eptest.NewUpdate("Third.App 5.0", "Application", "Missing")
	excludedInstalled := with(eptest.NewUpdate("KB5080003 Excluded", "Security", "Installed"), "isExcluded", true)
	excludedMissing := with(eptest.NewUpdate("KB5080004 Excluded", "Security", "Missing"), "isExcluded", true)
	f.setUpdates(f.e1, security, delayed, appApproved, appDelayed, appNot, excludedInstalled, excludedMissing)

	plan, err := f.svc.PlanAvailable(ctx, f.tech, AvailableInput{Targets: Targets{DeviceIDs: []uuid.UUID{f.web}}})
	if err != nil || plan.Updates != 4 || plan.Deferred != 2 || plan.NotApproved != 1 || plan.Excluded.Count != 1 {
		t.Fatalf("plan: %+v, %v", plan, err)
	}
	plan, err = f.svc.PlanAvailable(ctx, f.tech, AvailableInput{Targets: Targets{DeviceIDs: []uuid.UUID{f.web}}, SkipDelayed: true})
	if err != nil || plan.Updates != 2 || plan.Deferred != 2 || plan.NotApproved != 1 {
		t.Fatalf("plan, skipping delayed: %+v, %v", plan, err)
	}
	_, err = f.svc.Install(ctx, f.tech, InstallInput{DeviceIDs: []uuid.UUID{f.web}, SkipDelayed: true})
	wantField(t, err, "skipDelayed", "every available update")
	res, err := f.svc.Install(ctx, f.tech, InstallInput{DeviceIDs: []uuid.UUID{f.web}, Updates: UpdatesAvailable, SkipDelayed: true})
	if err != nil || res.Succeeded != 1 {
		t.Fatalf("install: %+v, %v", res, err)
	}
	reqs := f.ep.RequestsTo("POST", "/api/v1/endpoints/"+f.e1.ID.String()+"/install-updates")
	var sent []string
	for _, g := range reqs[0].Body["updateGuids"].([]any) {
		sent = append(sent, g.(string))
	}
	want := []string{guidOf(t, security).String(), guidOf(t, appApproved).String()}
	if slices.Sort(sent); !slices.Equal(sent, slices.Sorted(slices.Values(want))) {
		t.Fatalf("sent: %v", sent)
	}
	if got := f.audits("patch.install"); got[0].Details["rolloutDelayed"] != false {
		t.Fatalf("audit: %+v", got[0].Details)
	}
}
