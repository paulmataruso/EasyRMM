//go:build integration

package jobs

import (
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Markers that must never appear outside the output and arguments reads.
const (
	outMarker = "out-marker-5d1e"
	argMarker = "arg-marker-9c4b"
)

// finish delivers, starts and ends a device's queued run with output.
func (f *fixture) finish(device, run uuid.UUID, stdout, stderr string) {
	f.t.Helper()
	if _, err := f.svc.Poll(f.ctx, device); err != nil {
		f.t.Fatal(err)
	}
	if st, err := f.svc.Start(f.ctx, device, run); err != nil || !st.Proceed {
		f.t.Fatalf("start %+v %v", st, err)
	}
	if err := f.svc.Result(f.ctx, device, run, agentproto.ResultRequest{Status: StatusSucceeded, ExitCode: ptr(0), Stdout: stdout, Stderr: stderr}); err != nil {
		f.t.Fatal(err)
	}
}

// runOn is the job's run on a device.
func (f *fixture) runOn(j *Job, device uuid.UUID) uuid.UUID {
	f.t.Helper()
	for _, r := range j.Runs {
		if r.DeviceID == device {
			return r.ID
		}
	}
	f.t.Fatalf("job %s has no run on %s", j.ID, device)
	return uuid.Nil
}

// records counts audit records of an action and outcome by an actor.
func (f *fixture) records(action, outcome, actor string) int {
	f.t.Helper()
	var n int
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT count(*) FROM audit_log WHERE action = $1 AND outcome = $2 AND actor_label = $3`,
			action, outcome, actor).Scan(&n)
	}); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func wantKind(t *testing.T, what string, err error, kind apperr.Kind, code string) {
	t.Helper()
	e, ok := apperr.As(err)
	if !ok || e.Kind != kind || (code != "" && e.Code != code) {
		t.Errorf("%s: %v, want %v %s", what, err, kind, code)
	}
}

// keys decodes v's JSON into a map.
func keys(t *testing.T, v any) map[string]any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// noMarker fails when v's JSON holds output or arguments.
func noMarker(t *testing.T, what string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if s := string(b); strings.Contains(s, outMarker) || strings.Contains(s, argMarker) {
		t.Errorf("%s carries output or arguments: %s", what, s)
	}
}

// TestOutputAndArgumentsNeedTheirPermission reads one job's output and
// arguments as every kind of caller (ADR-0063).
func TestOutputAndArgumentsNeedTheirPermission(t *testing.T) {
	f := newFixture(t)
	super := f.user("super@example.com", rbac.Assignment{Role: rbac.RoleSuperAdmin})
	sc, err := f.svc.CreateScript(f.ctx, super, ScriptInput{Name: "Everywhere", Shell: "sh", Body: "echo \"$@\""})
	if err != nil {
		t.Fatal(err)
	}
	hqPC, branchPC, plantPC := f.device(f.hq, "HQ", "linux"), f.device(f.branch, "BR", "linux"), f.device(f.plant, "PL", "linux")
	job, err := f.svc.CreateJob(f.ctx, super, JobInput{ScriptID: sc.ID, DeviceIDs: []uuid.UUID{hqPC, branchPC, plantPC}, Args: []string{argMarker, "two"}})
	if err != nil {
		t.Fatal(err)
	}
	hqRun := f.runOn(job, hqPC)
	for _, d := range []uuid.UUID{hqPC, branchPC, plantPC} {
		f.finish(d, f.runOn(job, d), "secret "+outMarker+"\n", "warn "+outMarker+"\n")
	}

	type want struct {
		output    string // "ok", "forbidden" or "not_found"
		arguments string
		// orgs and sites the success or denied records of the arguments
		// read are under, as "org/site" with "-" for no site.
		argRecords []string
	}
	acme, globex, hq, branch, plant := f.acme.String(), f.globex.String(), f.hq.String(), f.branch.String(), f.plant.String()
	callers := []struct {
		name string
		as   []rbac.Assignment
		want want
	}{
		{"super", nil, want{"ok", "ok", []string{acme + "/-", globex + "/" + plant}}},
		{"orgadmin", []rbac.Assignment{{Role: rbac.RoleOrgAdmin, OrganizationID: f.acme}}, want{"ok", "ok", []string{acme + "/-"}}},
		{"siteadmin", []rbac.Assignment{{Role: rbac.RoleSiteAdmin, OrganizationID: f.acme, SiteID: f.hq}}, want{"ok", "ok", []string{acme + "/" + hq}}},
		{"techorg", []rbac.Assignment{{Role: rbac.RoleTechnician, OrganizationID: f.acme}}, want{"ok", "ok", []string{acme + "/-"}}},
		{"techhq", []rbac.Assignment{{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq}}, want{"ok", "ok", []string{acme + "/" + hq}}},
		{"techbranch", []rbac.Assignment{{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.branch}}, want{"not_found", "ok", []string{acme + "/" + branch}}},
		{"roorg", []rbac.Assignment{{Role: rbac.RoleReadOnly, OrganizationID: f.acme}}, want{"forbidden", "forbidden", []string{acme + "/-"}}},
		{"rohq", []rbac.Assignment{{Role: rbac.RoleReadOnly, OrganizationID: f.acme, SiteID: f.hq}}, want{"forbidden", "forbidden", []string{acme + "/" + hq}}},
		// Read-Only in one organization, Technician in another: the
		// arguments are read through the other organization's run only.
		{"mixed", []rbac.Assignment{{Role: rbac.RoleReadOnly, OrganizationID: f.acme}, {Role: rbac.RoleTechnician, OrganizationID: f.globex}},
			want{"forbidden", "ok", []string{globex + "/" + plant}}},
		{"globex", []rbac.Assignment{{Role: rbac.RoleOrgAdmin, OrganizationID: f.globex}}, want{"not_found", "ok", []string{globex + "/" + plant}}},
		{"nobody", nil, want{"not_found", "not_found", nil}},
	}
	for _, tc := range callers {
		email := tc.name + "@example.com"
		c := super
		if tc.name != "super" {
			c = f.user(email, tc.as...)
		} else {
			email = "super@example.com"
		}

		// The run and the job say whether the caller may read, and carry
		// neither output nor arguments.
		run, err := f.svc.GetRun(f.ctx, c, hqRun)
		switch tc.want.output {
		case "not_found":
			wantKind(t, tc.name+" run", err, apperr.KindNotFound, "")
		default:
			if err != nil {
				t.Fatalf("%s run: %v", tc.name, err)
			}
			m := keys(t, run)
			holder := tc.want.output == "ok"
			if run.CanViewOutput != holder || m["canViewOutput"] != holder {
				t.Errorf("%s: canViewOutput %v", tc.name, m["canViewOutput"])
			}
			for _, k := range []string{"stdoutBytes", "stderrBytes", "outputRemovedAt"} {
				if _, ok := m[k]; ok != holder {
					t.Errorf("%s: run key %s present %v", tc.name, k, ok)
				}
			}
			if holder && (run.StdoutBytes != len("secret "+outMarker+"\n") || run.StderrBytes != len("warn "+outMarker+"\n")) {
				t.Errorf("%s: sizes %d %d", tc.name, run.StdoutBytes, run.StderrBytes)
			}
			noMarker(t, tc.name+" run", run)
		}
		j, err := f.svc.GetJob(f.ctx, c, job.ID)
		if tc.want.arguments == "not_found" {
			wantKind(t, tc.name+" job", err, apperr.KindNotFound, "")
		} else {
			if err != nil {
				t.Fatalf("%s job: %v", tc.name, err)
			}
			if j.ArgCount != 2 || j.CanViewArguments != (tc.want.arguments == "ok") {
				t.Errorf("%s: job %+v", tc.name, j.JobDetail)
			}
			noMarker(t, tc.name+" job", j)
			for _, r := range j.Runs {
				if r.RunDetail != nil {
					t.Errorf("%s: a job's run carries %+v", tc.name, r.RunDetail)
				}
			}
		}
		list, err := f.svc.ListJobs(f.ctx, c, JobQuery{})
		if err != nil {
			t.Fatal(err)
		}
		for _, lj := range list {
			if lj.JobDetail != nil {
				t.Errorf("%s: a listed job carries %+v", tc.name, lj.JobDetail)
			}
		}
		noMarker(t, tc.name+" jobs", list)
		runs, err := f.svc.ListRuns(f.ctx, c, RunQuery{DeviceID: hqPC})
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range runs {
			if r.RunDetail != nil || r.Job != nil {
				t.Errorf("%s: a listed run carries %+v", tc.name, r)
			}
		}
		noMarker(t, tc.name+" runs", runs)

		// The reads, and what they record.
		out, err := f.svc.ReadOutput(f.ctx, c, hqRun)
		switch tc.want.output {
		case "ok":
			if err != nil || out.Stdout != "secret "+outMarker+"\n" || out.Stderr != "warn "+outMarker+"\n" || out.StdoutTruncated {
				t.Errorf("%s output %+v %v", tc.name, out, err)
			}
			if n := f.records("job_run.output_view", "success", email); n != 1 {
				t.Errorf("%s: %d output records", tc.name, n)
			}
		case "forbidden":
			wantKind(t, tc.name+" output", err, apperr.KindForbidden, "")
			if n := f.records("job_run.output_view", "denied", email); n != 1 {
				t.Errorf("%s: %d refused output records", tc.name, n)
			}
		default:
			wantKind(t, tc.name+" output", err, apperr.KindNotFound, "")
		}
		args, err := f.svc.ReadArguments(f.ctx, c, job.ID)
		outcome := "success"
		switch tc.want.arguments {
		case "ok":
			if err != nil || !slices.Equal(args.Args, []string{argMarker, "two"}) {
				t.Errorf("%s arguments %+v %v", tc.name, args, err)
			}
		case "forbidden":
			wantKind(t, tc.name+" arguments", err, apperr.KindForbidden, "")
			outcome = "denied"
		default:
			wantKind(t, tc.name+" arguments", err, apperr.KindNotFound, "")
		}
		var got []string
		if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
			rows, err := tx.Query(f.ctx, `SELECT organization_id::text || '/' || coalesce(site_id::text, '-') FROM audit_log
				WHERE action = 'job.arguments_view' AND actor_label = $1 AND outcome = $2 AND target_id = $3 ORDER BY 1`, email, outcome, job.ID.String())
			if err != nil {
				return err
			}
			got, err = pgx.CollectRows(rows, pgx.RowTo[string])
			return err
		}); err != nil {
			t.Fatal(err)
		}
		wantRecords := slices.Clone(tc.want.argRecords)
		slices.Sort(wantRecords)
		if !slices.Equal(got, wantRecords) {
			t.Errorf("%s: arguments records %v, want %v", tc.name, got, wantRecords)
		}
	}

	// A second look is a second record.
	if _, err := f.svc.ReadOutput(f.ctx, super, hqRun); err != nil {
		t.Fatal(err)
	}
	if n := f.records("job_run.output_view", "success", "super@example.com"); n != 2 {
		t.Errorf("%d records for two reads", n)
	}
	// The records say what was read, never what it held.
	details := f.str(`SELECT details::text FROM audit_log WHERE action = 'job_run.output_view' AND outcome = 'success' LIMIT 1`)
	for _, s := range []string{`"device": "HQ"`, `"script": "Everywhere"`, `"kind": "script"`, `"stdoutBytes": 23`, job.ID.String()} {
		if !strings.Contains(details, s) {
			t.Errorf("output record %s lacks %s", details, s)
		}
	}
	if n := f.str(`SELECT count(*)::text FROM audit_log WHERE details::text LIKE '%marker%'`); n != "0" {
		t.Errorf("%s audit records hold output or arguments", n)
	}

	// An open run has no output yet; a run that printed nothing and a job
	// without arguments answer empty, with no record.
	tech := f.user("tess@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme})
	open, err := f.svc.CreateJob(f.ctx, tech, JobInput{ScriptID: sc.ID, DeviceIDs: []uuid.UUID{hqPC}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.svc.ReadOutput(f.ctx, tech, open.Runs[0].ID)
	wantKind(t, "open run", err, apperr.KindConflict, "run_open")
	f.finish(hqPC, open.Runs[0].ID, "", "")
	if out, err := f.svc.ReadOutput(f.ctx, tech, open.Runs[0].ID); err != nil || out.Stdout != "" || out.Stderr != "" {
		t.Errorf("no output: %+v %v", out, err)
	}
	if args, err := f.svc.ReadArguments(f.ctx, tech, open.ID); err != nil || args.Args == nil || len(args.Args) != 0 {
		t.Errorf("no arguments: %+v %v", args, err)
	}
	if n := f.records("job_run.output_view", "success", "tess@example.com") + f.records("job.arguments_view", "success", "tess@example.com"); n != 0 {
		t.Errorf("%d records of nothing read", n)
	}
	_, err = f.svc.ReadOutput(f.ctx, tech, uuid.New())
	wantKind(t, "no such run", err, apperr.KindNotFound, "")
	_, err = f.svc.ReadArguments(f.ctx, tech, uuid.New())
	wantKind(t, "no such job", err, apperr.KindNotFound, "")
}

// TestRefusedReadsAreRecordedWithinABound: a refusal is recorded once per
// user and run in 10 minutes, at most 20 per user in 10 minutes, and two
// requests at once record it once.
func TestRefusedReadsAreRecordedWithinABound(t *testing.T) {
	f := newFixture(t)
	super := f.user("super@example.com", rbac.Assignment{Role: rbac.RoleSuperAdmin})
	viewer := f.user("viewer@example.com", rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: f.acme})
	sc, _ := f.svc.CreateScript(f.ctx, super, ScriptInput{Name: "Many", Shell: "sh", Body: "true"})
	var devices []uuid.UUID
	for i := range 25 {
		devices = append(devices, f.device(f.hq, "PC-"+string(rune('A'+i)), "linux"))
	}
	job, err := f.svc.CreateJob(f.ctx, super, JobInput{ScriptID: sc.ID, DeviceIDs: devices, Args: []string{"x"}})
	if err != nil {
		t.Fatal(err)
	}
	f.at = time.Now()

	// Ten requests at once for one run: one record.
	first := job.Runs[0].ID
	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			if _, err := f.svc.ReadOutput(f.ctx, viewer, first); !errors.Is(err, apperr.ErrForbidden) {
				t.Errorf("concurrent read: %v", err)
			}
		})
	}
	wg.Wait()
	if n := f.records("job_run.output_view", "denied", "viewer@example.com"); n != 1 {
		t.Fatalf("%d records for one run read at once", n)
	}
	// Every run once: 20 records in all, then none.
	for _, r := range job.Runs {
		_, err := f.svc.ReadOutput(f.ctx, viewer, r.ID)
		wantKind(t, "refused", err, apperr.KindForbidden, "")
	}
	_, err = f.svc.ReadArguments(f.ctx, viewer, job.ID)
	wantKind(t, "refused arguments", err, apperr.KindForbidden, "")
	if n := f.records("job_run.output_view", "denied", "viewer@example.com"); n != 20 {
		t.Errorf("%d records, want 20", n)
	}
	if n := f.records("job.arguments_view", "denied", "viewer@example.com"); n != 0 {
		t.Errorf("%d arguments records past the bound", n)
	}
	// Ten minutes later, refusals are recorded again; the bound is per
	// user, so another user's are recorded meanwhile.
	other := f.user("other@example.com", rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: f.acme, SiteID: f.hq})
	if _, err := f.svc.ReadArguments(f.ctx, other, job.ID); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("other: %v", err)
	}
	if n := f.records("job.arguments_view", "denied", "other@example.com"); n != 1 {
		t.Errorf("%d records for another user", n)
	}
	f.at = f.at.Add(10*time.Minute + time.Second)
	if _, err := f.svc.ReadArguments(f.ctx, viewer, job.ID); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("later: %v", err)
	}
	if _, err := f.svc.ReadOutput(f.ctx, viewer, first); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("later: %v", err)
	}
	if n := f.records("job.arguments_view", "denied", "viewer@example.com") + f.records("job_run.output_view", "denied", "viewer@example.com"); n != 22 {
		t.Errorf("%d records after ten minutes, want 22", n)
	}
}

// TestOutputRetentionAndRemoval: output is kept from when it arrived, can
// be removed at once, and never comes back with a late result.
func TestOutputRetentionAndRemoval(t *testing.T) {
	f := newFixture(t)
	super := f.user("super@example.com", rbac.Assignment{Role: rbac.RoleSuperAdmin})
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq})
	branchTech := f.user("branch@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.branch})
	viewer := f.user("viewer@example.com", rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: f.acme})
	sc, _ := f.svc.CreateScript(f.ctx, super, ScriptInput{Name: "Key", Shell: "sh", Body: "true"})
	pc := f.device(f.hq, "HQ", "linux")
	newRun := func() uuid.UUID {
		t.Helper()
		j, err := f.svc.CreateJob(f.ctx, tech, JobInput{ScriptID: sc.ID, DeviceIDs: []uuid.UUID{pc}})
		if err != nil {
			t.Fatal(err)
		}
		return j.Runs[0].ID
	}
	purge := func(want int64) {
		t.Helper()
		if p, err := f.svc.Purge(f.ctx); err != nil || p.Outputs != want {
			t.Errorf("purge %+v %v, want %d emptied", p, err, want)
		}
	}
	lose := func(run uuid.UUID) {
		t.Helper()
		if _, err := f.svc.Poll(f.ctx, pc); err != nil {
			t.Fatal(err)
		}
		if _, err := f.svc.Start(f.ctx, pc, run); err != nil {
			t.Fatal(err)
		}
		f.exec(`UPDATE job_runs SET deadline_at = now() - interval '1 second' WHERE id = $1`, run)
		if s, err := f.svc.Sweep(f.ctx); err != nil || s.Lost != 1 {
			t.Fatalf("sweep %+v %v", s, err)
		}
	}
	late := func(run uuid.UUID, stdout string) {
		t.Helper()
		if err := f.svc.Result(f.ctx, pc, run, agentproto.ResultRequest{Status: StatusFailed, ExitCode: ptr(3), Stdout: stdout, StdoutTruncated: true}); err != nil {
			t.Fatal(err)
		}
	}
	state := func(run uuid.UUID) string {
		t.Helper()
		return f.str(`SELECT status || ' ' || coalesce(exit_code::text, '-') || ' ' || stdout_bytes || ' ' || (output_stored_at IS NOT NULL) || ' ' ||
			(output_removed_at IS NOT NULL) FROM job_runs WHERE id = $1`, run)
	}

	// Output is emptied once it is older than the output retention,
	// counted from when it arrived; the run stays.
	kept := newRun()
	f.finish(pc, kept, "key "+outMarker, "")
	f.asOwner(`UPDATE job_runs SET created_at = now() - interval '40 days', finished_at = now() - interval '40 days' WHERE id = $1`, kept)
	purge(0)
	f.asOwner(`UPDATE job_runs SET output_stored_at = now() - interval '30 days 1 minute' WHERE id = $1`, kept)
	purge(1)
	if s := state(kept); s != "succeeded 0 0 false true" {
		t.Errorf("after retention: %s", s)
	}
	_, err := f.svc.ReadOutput(f.ctx, tech, kept)
	wantKind(t, "removed by retention", err, apperr.KindConflict, "output_removed")
	if r, err := f.svc.GetRun(f.ctx, tech, kept); err != nil || r.OutputRemovedAt == nil || r.StdoutBytes != 0 {
		t.Errorf("run after retention %+v %v", r, err)
	}
	purge(0)

	// (a) A lost run has no output: retention and removal leave it alone,
	// and a late result's output is stored.
	lost := newRun()
	lose(lost)
	purge(0)
	_, err = f.svc.RemoveOutput(f.ctx, tech, lost)
	wantKind(t, "removing nothing", err, apperr.KindConflict, "no_output")
	late(lost, "late "+outMarker)
	if s := state(lost); s != "failed 3 "+strconv.Itoa(len("late "+outMarker))+" true false" {
		t.Errorf("late result: %s", s)
	}
	if out, err := f.svc.ReadOutput(f.ctx, tech, lost); err != nil || out.Stdout != "late "+outMarker || !out.StdoutTruncated {
		t.Errorf("late output %+v %v", out, err)
	}

	// (b) Its retention counts from the late result, not from the run.
	f.asOwner(`UPDATE job_runs SET created_at = now() - interval '40 days' WHERE id = $1`, lost)
	purge(0)
	f.asOwner(`UPDATE job_runs SET output_stored_at = now() - interval '31 days' WHERE id = $1`, lost)
	purge(1)
	if s := state(lost); s != "failed 3 0 false true" {
		t.Errorf("late output after retention: %s", s)
	}

	// A late result for a run whose output was removed records how it
	// ended, without output. The server removes only output that exists,
	// so the state is made here as the owner.
	removedLost := newRun()
	lose(removedLost)
	f.asOwner(`UPDATE job_runs SET output_removed_at = now() WHERE id = $1`, removedLost)
	late(removedLost, "late "+outMarker)
	if s := state(removedLost); s != "failed 3 0 false true" {
		t.Errorf("late result after removal: %s", s)
	}
	if n := f.str(`SELECT count(*)::text FROM job_runs WHERE id = $1 AND (stdout_truncated OR stderr_truncated)`, removedLost); n != "0" {
		t.Error("a removed run keeps a truncation flag")
	}

	// Remove output at once.
	now := newRun()
	_, err = f.svc.RemoveOutput(f.ctx, tech, now)
	wantKind(t, "open run", err, apperr.KindConflict, "run_open")
	f.finish(pc, now, "recovery "+outMarker, "e")
	_, err = f.svc.RemoveOutput(f.ctx, viewer, now)
	wantKind(t, "read-only", err, apperr.KindForbidden, "")
	_, err = f.svc.RemoveOutput(f.ctx, branchTech, now)
	wantKind(t, "another site", err, apperr.KindNotFound, "")
	_, err = f.svc.RemoveOutput(f.ctx, tech, uuid.New())
	wantKind(t, "no such run", err, apperr.KindNotFound, "")
	r, err := f.svc.RemoveOutput(f.ctx, tech, now)
	if err != nil || r.OutputRemovedAt == nil || r.StdoutBytes != 0 || r.StderrBytes != 0 || !r.CanViewOutput {
		t.Fatalf("removed %+v %v", r, err)
	}
	_, err = f.svc.RemoveOutput(f.ctx, tech, now)
	wantKind(t, "again", err, apperr.KindConflict, "output_removed")
	_, err = f.svc.ReadOutput(f.ctx, tech, now)
	wantKind(t, "read after removal", err, apperr.KindConflict, "output_removed")
	details := f.str(`SELECT details::text FROM audit_log WHERE action = 'job_run.output_remove'`)
	for _, s := range []string{`"stdoutBytes": ` + strconv.Itoa(len("recovery "+outMarker)), `"stderrBytes": 1`, `"device": "HQ"`} {
		if !strings.Contains(details, s) {
			t.Errorf("removal record %s lacks %s", details, s)
		}
	}
	if n := f.records("job_run.output_remove", "success", "tech@example.com"); n != 1 {
		t.Errorf("%d removal records", n)
	}
	// A repeated result after removal is ignored, as any repeat is.
	late(now, "again "+outMarker)
	if s := state(now); s != "succeeded 0 0 false true" {
		t.Errorf("repeat after removal: %s", s)
	}
}

// TestTheServerRoleCannotReadOutputOrArguments: the runtime role reads
// them only through the functions (migration 00028).
func TestTheServerRoleCannotReadOutputOrArguments(t *testing.T) {
	f := newFixture(t)
	super := f.user("super@example.com", rbac.Assignment{Role: rbac.RoleSuperAdmin})
	sc, _ := f.svc.CreateScript(f.ctx, super, ScriptInput{Name: "Key", Shell: "sh", Body: "true"})
	pc := f.device(f.hq, "HQ", "linux")
	job, err := f.svc.CreateJob(f.ctx, super, JobInput{ScriptID: sc.ID, DeviceIDs: []uuid.UUID{pc}, Args: []string{argMarker}})
	if err != nil {
		t.Fatal(err)
	}
	f.finish(pc, job.Runs[0].ID, outMarker, "")

	denied := func(sql string, args ...any) {
		t.Helper()
		err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
			_, err := tx.Exec(f.ctx, sql, args...)
			return err
		})
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != "42501" {
			t.Errorf("%s: %v, want permission denied", sql, err)
		}
	}
	denied(`SELECT stdout FROM job_runs`)
	denied(`SELECT stderr FROM job_runs`)
	denied(`SELECT * FROM job_runs`)
	denied(`SELECT args FROM jobs`)
	denied(`SELECT j FROM jobs j`)
	denied(`UPDATE job_runs SET error = 'x' RETURNING stdout`)
	denied(`SELECT easyrmm_job_scope_covers(true, '{}', '{}', NULL, NULL)`)
	denied(`SELECT easyrmm_job_refusal(now(), 'user', NULL, 'x', NULL, NULL, NULL, 'job_run.output_view', 'job_run', 'x', NULL, '', '{}')`)

	// Every other column stays readable.
	var missing []string
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(f.ctx, `SELECT table_name || '.' || column_name FROM information_schema.columns
			WHERE table_schema = 'public' AND table_name IN ('jobs', 'job_runs')
			  AND NOT has_column_privilege('easyrmm_app', format('%I', table_name), column_name, 'SELECT')
			ORDER BY 1`)
		if err != nil {
			return err
		}
		missing, err = pgx.CollectRows(rows, pgx.RowTo[string])
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(missing, []string{"job_runs.stderr", "job_runs.stdout", "jobs.args"}) {
		t.Errorf("columns the server cannot read: %v", missing)
	}

	// The delivery function answers only under the system scope.
	user := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme})
	f.exec(`UPDATE job_runs SET status = 'sent', finished_at = NULL, started_at = NULL WHERE id = $1`, job.Runs[0].ID)
	count := func(scope database.Scope) int {
		var n int
		if err := f.db.ReadTx(f.ctx, scope, func(tx pgx.Tx) error {
			return tx.QueryRow(f.ctx, `SELECT count(*) FROM easyrmm_job_delivery_args($1, $2)`, pc, []uuid.UUID{job.Runs[0].ID}).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if count(user.Scope) != 0 || count(database.System) != 1 {
		t.Error("the delivery function answers outside the system scope, or not within it")
	}

	// If the read cannot be recorded, nothing is returned.
	f.asOwner(`CREATE FUNCTION test_refuse_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'no audit'; END $$`)
	f.asOwner(`CREATE TRIGGER test_refuse_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION test_refuse_audit()`)
	f.exec(`UPDATE job_runs SET status = 'succeeded', finished_at = now(), started_at = now() WHERE id = $1`, job.Runs[0].ID)
	if out, err := f.svc.ReadOutput(f.ctx, super, job.Runs[0].ID); err == nil || out != nil {
		t.Errorf("read without a record: %+v %v", out, err)
	}
	if args, err := f.svc.ReadArguments(f.ctx, super, job.ID); err == nil || args != nil {
		t.Errorf("arguments without a record: %+v %v", args, err)
	}
	viewer := f.user("viewer@example.com", rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: f.acme})
	if _, err := f.svc.ReadOutput(f.ctx, viewer, job.Runs[0].ID); err == nil || errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("a refusal that cannot be recorded: %v", err)
	}
}
