//go:build integration

package jobs

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"io"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// downloads counts successful output reads of a run that downloaded what.
func (f *fixture) downloads(run uuid.UUID, what string) int {
	f.t.Helper()
	var n int
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT count(*) FROM audit_log WHERE action = 'job_run.output_view' AND outcome = 'success'
			AND target_id = $1 AND details->>'download' = $2`, run.String(), what).Scan(&n)
	}); err != nil {
		f.t.Fatal(err)
	}
	return n
}

// refuseAudit makes every audit append fail until the test ends.
func (f *fixture) refuseAudit() {
	f.t.Helper()
	f.asOwner(`CREATE FUNCTION test_refuse_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'no audit'; END $$`)
	f.asOwner(`CREATE TRIGGER test_refuse_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION test_refuse_audit()`)
}

// TestDownloadingOneRun downloads a run's streams and the run as JSON as
// every kind of caller: each download is ADR-0063's read, recorded with
// what was downloaded (ADR-0064).
func TestDownloadingOneRun(t *testing.T) {
	f := newFixture(t)
	super := f.user("super@example.com", rbac.Assignment{Role: rbac.RoleSuperAdmin})
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme})
	viewer := f.user("viewer@example.com", rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: f.acme})
	outsider := f.user("outsider@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.globex})
	sc, err := f.svc.CreateScript(f.ctx, super, ScriptInput{Name: "Key / reader", Shell: "sh", Body: "echo key"})
	if err != nil {
		t.Fatal(err)
	}
	pc := f.device(f.hq, "../HQ 01", "linux")
	quiet := f.device(f.hq, "HQ-02", "linux")
	job, err := f.svc.CreateJob(f.ctx, tech, JobInput{ScriptID: sc.ID, DeviceIDs: []uuid.UUID{pc, quiet}})
	if err != nil {
		t.Fatal(err)
	}
	run, quietRun := f.runOn(job, pc), f.runOn(job, quiet)
	f.finish(pc, run, "key "+outMarker+"\n", "warn "+outMarker+"\n")
	f.finish(quiet, quietRun, "", "")

	// Each stream as text, the run as JSON.
	base := "__HQ_01_" + run.String()
	for what, want := range map[string]File{
		DownloadStdout: {Name: base + "_stdout.txt", Body: []byte("key " + outMarker + "\n")},
		DownloadStderr: {Name: base + "_stderr.txt", Body: []byte("warn " + outMarker + "\n")},
	} {
		got, err := f.svc.DownloadOutput(f.ctx, tech, run, what)
		if err != nil || got.Name != want.Name || !bytes.Equal(got.Body, want.Body) {
			t.Errorf("%s: %+v %v, want %s", what, got, err, want.Name)
		}
		if n := f.downloads(run, what); n != 1 {
			t.Errorf("%s recorded %d times", what, n)
		}
	}
	got, err := f.svc.DownloadOutput(f.ctx, tech, run, DownloadJSON)
	if err != nil || got.Name != base+".json" {
		t.Fatalf("json: %+v %v", got, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(got.Body, &doc); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]any{
		"runId": run.String(), "jobId": job.ID.String(), "device": "../HQ 01", "deviceId": pc.String(), "organization": "Acme",
		"organizationId": f.acme.String(), "site": "HQ", "siteId": f.hq.String(), "kind": KindScript, "scriptName": "Key / reader",
		"sha256": job.SHA256, "shell": "sh", "startedBy": "tech@example.com", "status": StatusSucceeded, "exitCode": float64(0),
		"error": "", "stdout": "key " + outMarker + "\n", "stderr": "warn " + outMarker + "\n", "stdoutTruncated": false, "stderrTruncated": false,
	} {
		if doc[k] != v {
			t.Errorf("json %s = %v, want %v", k, doc[k], v)
		}
	}
	for _, k := range []string{"queuedAt", "deliveredAt", "startedAt", "finishedAt"} {
		if s, _ := doc[k].(string); s == "" {
			t.Errorf("json %s = %v", k, doc[k])
		}
	}
	if n := f.downloads(run, DownloadJSON); n != 1 {
		t.Errorf("json recorded %d times", n)
	}

	// A run that printed nothing downloads empty and records nothing.
	if got, err := f.svc.DownloadOutput(f.ctx, tech, quietRun, DownloadStdout); err != nil || len(got.Body) != 0 {
		t.Errorf("empty stream: %+v %v", got, err)
	}
	if got, err := f.svc.DownloadOutput(f.ctx, tech, quietRun, DownloadJSON); err != nil || !strings.Contains(string(got.Body), `"stdout": ""`) {
		t.Errorf("empty run: %+v %v", got, err)
	}
	if n := f.downloads(quietRun, DownloadStdout) + f.downloads(quietRun, DownloadJSON); n != 0 {
		t.Errorf("an empty run was recorded %d times", n)
	}

	// Without job.view_sensitive: refused and recorded as denied, with what
	// was asked for; another organization does not find it.
	for _, what := range []string{DownloadStdout, DownloadJSON} {
		_, err := f.svc.DownloadOutput(f.ctx, viewer, run, what)
		wantKind(t, "read-only "+what, err, apperr.KindForbidden, "")
		_, err = f.svc.DownloadOutput(f.ctx, outsider, run, what)
		wantKind(t, "outsider "+what, err, apperr.KindNotFound, "")
	}
	if n := f.records("job_run.output_view", "denied", "viewer@example.com"); n != 1 {
		t.Errorf("denied records = %d (one per run within the bound)", n)
	}
	if s := f.str(`SELECT details->>'download' FROM audit_log WHERE outcome = 'denied'`); s != DownloadStdout {
		t.Errorf("the refusal recorded download %q", s)
	}
	_, err = f.svc.DownloadOutput(f.ctx, tech, run, "zip")
	wantKind(t, "an unknown download", err, apperr.KindInvalid, "")

	// Open runs and removed output, as the page's read answers.
	open, err := f.svc.CreateJob(f.ctx, tech, JobInput{ScriptID: sc.ID, DeviceIDs: []uuid.UUID{pc}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.svc.DownloadOutput(f.ctx, tech, open.Runs[0].ID, DownloadJSON)
	wantKind(t, "an open run", err, apperr.KindConflict, "run_open")
	if _, err := f.svc.RemoveOutput(f.ctx, tech, run); err != nil {
		t.Fatal(err)
	}
	_, err = f.svc.DownloadOutput(f.ctx, tech, run, DownloadStdout)
	wantKind(t, "removed output", err, apperr.KindConflict, "output_removed")

	// No record, no download.
	f.finish(pc, open.Runs[0].ID, outMarker, "")
	f.refuseAudit()
	if got, err := f.svc.DownloadOutput(f.ctx, tech, open.Runs[0].ID, DownloadStdout); err == nil || got != nil {
		t.Errorf("a download without its record: %+v %v", got, err)
	}
}

// archive reads a ZIP archive's files by name.
func archive(t *testing.T, b []byte) map[string]string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	safe := regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9._-]*(/[A-Za-z0-9_-][A-Za-z0-9._-]*)?$`)
	for _, zf := range zr.File {
		if !safe.MatchString(zf.Name) || strings.Contains(zf.Name, "..") {
			t.Errorf("unsafe name in the archive: %q", zf.Name)
		}
		rc, err := zf.Open()
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		out[zf.Name] = string(body)
	}
	return out
}

// csvRows parses CSV written by reports.WriteCSV.
func csvRows(t *testing.T, s string) [][]string {
	t.Helper()
	rows, err := csv.NewReader(strings.NewReader(strings.TrimPrefix(s, "\xef\xbb\xbf"))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

// TestDownloadingAJobsOutput downloads a whole job as a ZIP archive: each
// run's read recorded before anything is written, the runs chosen there,
// and output removed in between listed as removed (ADR-0064).
func TestDownloadingAJobsOutput(t *testing.T) {
	f := newFixture(t)
	super := f.user("super@example.com", rbac.Assignment{Role: rbac.RoleSuperAdmin})
	// A Technician at HQ who is Read-Only at the organization's other
	// sites: Branch's runs are hidden from them.
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq},
		rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: f.acme})
	viewer := f.user("viewer@example.com", rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: f.acme})
	outsider := f.user("outsider@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.globex})
	sc, err := f.svc.CreateScript(f.ctx, super, ScriptInput{Name: "Inventory check", Shell: "sh", Body: "echo"})
	if err != nil {
		t.Fatal(err)
	}
	loud, quiet, gone, busy := f.device(f.hq, "=HQ-01", "linux"), f.device(f.hq, "HQ-02", "linux"), f.device(f.hq, "HQ-03", "linux"), f.device(f.hq, "HQ-04", "linux")
	branch, plant := f.device(f.branch, "BR-01", "linux"), f.device(f.plant, "PL-01", "linux")
	job, err := f.svc.CreateJob(f.ctx, super, JobInput{ScriptID: sc.ID, DeviceIDs: []uuid.UUID{loud, quiet, gone, busy, branch, plant}})
	if err != nil {
		t.Fatal(err)
	}
	f.finish(loud, f.runOn(job, loud), "loud "+outMarker+"\n", "err "+outMarker+"\n")
	f.finish(quiet, f.runOn(job, quiet), "", "")
	f.finish(gone, f.runOn(job, gone), "gone "+outMarker+"\n", "")
	f.finish(branch, f.runOn(job, branch), "branch "+outMarker+"\n", "")
	f.finish(plant, f.runOn(job, plant), "plant "+outMarker+"\n", "")
	if _, err := f.svc.RemoveOutput(f.ctx, super, f.runOn(job, gone)); err != nil {
		t.Fatal(err)
	}

	// The records are written, and committed, before anything is sent: one
	// per run whose output goes in, none for a run that printed nothing.
	arc, err := f.svc.OutputArchive(f.ctx, tech, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if arc.Name != "Inventory_check_"+job.ID.String()+"_output.zip" {
		t.Errorf("name %q", arc.Name)
	}
	for d, want := range map[uuid.UUID]int{loud: 1, quiet: 0, gone: 0, busy: 0, branch: 0, plant: 0} {
		if n := f.downloads(f.runOn(job, d), "zip"); n != want {
			t.Errorf("%s: %d zip records, want %d", d, n, want)
		}
	}
	var buf bytes.Buffer
	if err := arc.Write(f.ctx, &buf); err != nil {
		t.Fatal(err)
	}
	files := archive(t, buf.Bytes())
	dir := "_HQ-01_" + f.runOn(job, loud).String() + "/"
	if files[dir+"stdout.txt"] != "loud "+outMarker+"\n" || files[dir+"stderr.txt"] != "err "+outMarker+"\n" {
		t.Errorf("loud run's files: %q %q", files[dir+"stdout.txt"], files[dir+"stderr.txt"])
	}
	var res map[string]any
	if err := json.Unmarshal([]byte(files[dir+"result.json"]), &res); err != nil || res["stdout"] != "loud "+outMarker+"\n" || res["device"] != "=HQ-01" {
		t.Errorf("result.json %v %v", res, err)
	}
	quietDir := "HQ-02_" + f.runOn(job, quiet).String() + "/"
	if _, ok := files[quietDir+"stdout.txt"]; !ok {
		t.Errorf("the quiet run has no folder: %v", keysOf(files))
	}
	for name, body := range files {
		if strings.Contains(body, "branch "+outMarker) || strings.Contains(body, "plant "+outMarker) || strings.Contains(body, "gone "+outMarker) {
			t.Errorf("%s holds output the caller may not read", name)
		}
	}
	if len(files) != 7 {
		t.Errorf("files %v", keysOf(files))
	}
	rows := csvRows(t, files["runs.csv"])
	if got := strings.Join(rows[0], ","); got != "Device,Organization,Site,Status,Exit code,Error,Queued (UTC),Started (UTC),Finished (UTC),Run,Output,Folder" {
		t.Errorf("header %s", got)
	}
	state := outputStates(t, files)
	if rows[1][0] != "'=HQ-01" || rows[1][3] != "Succeeded" || rows[1][11] != strings.TrimSuffix(dir, "/") {
		t.Errorf("the loud run's row: %q", rows[1])
	}
	for name, want := range map[string]string{
		"'=HQ-01": archiveIncluded, "HQ-02": archiveEmpty, "HQ-03": archiveRemoved, "HQ-04": archiveOpen, "BR-01": archiveHidden,
	} {
		if state[name] != want {
			t.Errorf("runs.csv: %s is %q, want %q (%v)", name, state[name], want, state)
		}
	}
	if _, ok := state["PL-01"]; ok || len(state) != 5 {
		t.Errorf("runs.csv lists %v", state)
	}

	// Output removed between the records and its read: listed as removed,
	// without files; the record stays.
	arc, err = f.svc.OutputArchive(f.ctx, tech, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.RemoveOutput(f.ctx, tech, f.runOn(job, loud)); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	if err := arc.Write(f.ctx, &buf); err != nil {
		t.Fatal(err)
	}
	files = archive(t, buf.Bytes())
	if _, ok := files[dir+"stdout.txt"]; ok {
		t.Error("removed output was sent")
	}
	if st := outputStates(t, files)["'=HQ-01"]; st != archiveRemoved {
		t.Errorf("the loud run is %q:\n%s", st, files["runs.csv"])
	}
	if n := f.downloads(f.runOn(job, loud), "zip"); n != 2 {
		t.Errorf("zip records of the loud run: %d", n)
	}

	// Callers who may read none of it, and who see none of it.
	_, err = f.svc.OutputArchive(f.ctx, viewer, job.ID)
	wantKind(t, "read-only", err, apperr.KindForbidden, "")
	if n := f.records("job_run.output_view", "denied", "viewer@example.com"); n != 1 {
		t.Errorf("denied records = %d", n)
	}
	if s := f.str(`SELECT target_type || ' ' || target_id || ' ' || (details->>'download') || ' ' || coalesce(site_id::text, '-')
			FROM audit_log WHERE outcome = 'denied'`); s != "job "+job.ID.String()+" zip -" {
		t.Errorf("the refusal: %s", s)
	}
	_, err = f.svc.OutputArchive(f.ctx, outsider, uuid.New())
	wantKind(t, "a job that does not exist", err, apperr.KindNotFound, "")
	only, err := f.svc.CreateJob(f.ctx, super, JobInput{ScriptID: sc.ID, DeviceIDs: []uuid.UUID{loud}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.svc.OutputArchive(f.ctx, outsider, only.ID)
	wantKind(t, "another organization's job", err, apperr.KindNotFound, "")
}

// outputStates reads runs.csv's Output column by device.
func outputStates(t *testing.T, files map[string]string) map[string]string {
	t.Helper()
	state := map[string]string{}
	for _, r := range csvRows(t, files["runs.csv"])[1:] {
		state[r[0]] = r[10]
	}
	return state
}

func keysOf(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestRecordedReadsNeedTheirRecord reads a run's output for an archive
// only against a record of its read: the same run, by the same caller, of
// a zip download, within a day by the database's clock.
func TestRecordedReadsNeedTheirRecord(t *testing.T) {
	f := newFixture(t)
	super := f.user("super@example.com", rbac.Assignment{Role: rbac.RoleSuperAdmin})
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme})
	other := f.user("other@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme})
	sc, err := f.svc.CreateScript(f.ctx, super, ScriptInput{Name: "Key", Shell: "sh", Body: "echo"})
	if err != nil {
		t.Fatal(err)
	}
	a, b := f.device(f.hq, "A", "linux"), f.device(f.hq, "B", "linux")
	job, err := f.svc.CreateJob(f.ctx, super, JobInput{ScriptID: sc.ID, DeviceIDs: []uuid.UUID{a, b}})
	if err != nil {
		t.Fatal(err)
	}
	runA, runB := f.runOn(job, a), f.runOn(job, b)
	f.finish(a, runA, outMarker, "")
	f.finish(b, runB, outMarker, "")
	f.at = time.Now().Add(-time.Hour)
	arc, err := f.svc.OutputArchive(f.ctx, tech, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	recA := arc.included[runA]
	if _, err := f.svc.ReadOutput(f.ctx, tech, runA); err != nil {
		t.Fatal(err)
	}
	var pageRecord int64
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT max(id) FROM audit_log WHERE action = 'job_run.output_view' AND details->>'download' IS NULL`).Scan(&pageRecord)
	}); err != nil {
		t.Fatal(err)
	}
	if out, err := f.svc.recordedOutput(f.ctx, tech, runA, recA); err != nil || out.Stdout != outMarker {
		t.Fatalf("against its record: %+v %v", out, err)
	}
	for what, read := range map[string]func() error{
		"another run":       func() error { _, err := f.svc.recordedOutput(f.ctx, tech, runB, recA); return err },
		"another caller":    func() error { _, err := f.svc.recordedOutput(f.ctx, other, runA, recA); return err },
		"the page's record": func() error { _, err := f.svc.recordedOutput(f.ctx, tech, runA, pageRecord); return err },
		"no record":         func() error { _, err := f.svc.recordedOutput(f.ctx, tech, runA, recA+1000); return err },
	} {
		wantKind(t, what, read(), apperr.KindForbidden, "")
	}

	// The day is the database's. A record written a day ago no longer
	// allows the read although the server's clock is set back to its time:
	// the server passes no time to the read.
	f.at = time.Now().Add(-25 * time.Hour)
	old, err := f.svc.OutputArchive(f.ctx, tech, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.svc.recordedOutput(f.ctx, tech, runA, old.included[runA])
	wantKind(t, "a record a day old", err, apperr.KindForbidden, "")
	// A record up to 5 minutes ahead of the database's clock is within the
	// skew allowed between the two clocks; one further ahead is refused.
	for ahead, ok := range map[time.Duration]bool{2 * time.Minute: true, 10 * time.Minute: false} {
		f.at = time.Now().Add(ahead)
		arc, err := f.svc.OutputArchive(f.ctx, tech, job.ID)
		if err != nil {
			t.Fatal(err)
		}
		f.at = time.Now()
		_, err = f.svc.recordedOutput(f.ctx, tech, runA, arc.included[runA])
		if ok && err != nil {
			t.Errorf("a record %s ahead: %v", ahead, err)
		}
		if !ok {
			wantKind(t, "a record "+ahead.String()+" ahead", err, apperr.KindForbidden, "")
		}
	}
	f.at = time.Now().Add(-time.Hour)
	// The caller's permission is checked again at the read.
	viewer := f.user("viewer@example.com", rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: f.acme})
	viewer.Actor.ID = tech.Actor.ID
	_, err = f.svc.recordedOutput(f.ctx, viewer, runA, recA)
	wantKind(t, "without the permission now", err, apperr.KindForbidden, "")
	outsider := f.user("outsider@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.globex})
	outsider.Actor.ID = tech.Actor.ID
	_, err = f.svc.recordedOutput(f.ctx, outsider, runA, recA)
	wantKind(t, "out of sight now", err, apperr.KindNotFound, "")

	// No archive is prepared when its records cannot be written.
	f.refuseAudit()
	if arc, err := f.svc.OutputArchive(f.ctx, tech, job.ID); err == nil || arc != nil {
		t.Errorf("an archive without its records: %+v %v", arc, err)
	}
}

// TestJobResultsCSV exports a job's results, without output, to everyone
// who sees the job, recorded as an export (ADR-0064).
func TestJobResultsCSV(t *testing.T) {
	f := newFixture(t)
	super := f.user("super@example.com", rbac.Assignment{Role: rbac.RoleSuperAdmin})
	viewer := f.user("viewer@example.com", rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: f.acme})
	outsider := f.user("outsider@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.globex})
	sc, err := f.svc.CreateScript(f.ctx, super, ScriptInput{Name: "=Report", Shell: "sh", Body: "echo"})
	if err != nil {
		t.Fatal(err)
	}
	hq, br, pl := f.device(f.hq, "@HQ-01", "linux"), f.device(f.branch, "BR-01", "linux"), f.device(f.plant, "PL-01", "linux")
	job, err := f.svc.CreateJob(f.ctx, super, JobInput{ScriptID: sc.ID, DeviceIDs: []uuid.UUID{hq, br, pl}})
	if err != nil {
		t.Fatal(err)
	}
	f.finish(hq, f.runOn(job, hq), outMarker, outMarker)

	got, err := f.svc.ResultsCSV(f.ctx, viewer, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "_Report_"+job.ID.String()+"_results.csv" {
		t.Errorf("name %q", got.Name)
	}
	if strings.Contains(string(got.Body), outMarker) {
		t.Error("the results carry output")
	}
	rows := csvRows(t, string(got.Body))
	if len(rows) != 3 || rows[1][0] != "'@HQ-01" || rows[1][3] != "Succeeded" || rows[1][4] != "0" || rows[2][0] != "BR-01" || rows[2][3] != "Queued" ||
		rows[2][4] != "" || rows[1][9] != f.runOn(job, hq).String() {
		t.Errorf("rows %q", rows)
	}
	// One record for Acme, the organization of both runs, at no one site.
	var org, site, details string
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT organization_id::text, coalesce(site_id::text, ''), details::text FROM audit_log
			WHERE action = 'job.results_export'`).Scan(&org, &site, &details)
	}); err != nil {
		t.Fatal(err)
	}
	if org != f.acme.String() || site != "" || !strings.Contains(details, `"rows": 2`) || !strings.Contains(details, job.ID.String()) {
		t.Errorf("record %s %s %s", org, site, details)
	}
	// The super administrator's export is recorded once per organization,
	// Globex's under its one site.
	if _, err := f.svc.ResultsCSV(f.ctx, super, job.ID); err != nil {
		t.Fatal(err)
	}
	if n := f.records("job.results_export", "success", "super@example.com"); n != 2 {
		t.Errorf("super administrator's records = %d", n)
	}
	if s := f.str(`SELECT site_id::text FROM audit_log WHERE action = 'job.results_export' AND organization_id = $1`, f.globex); s != f.plant.String() {
		t.Errorf("Globex's record is at %s", s)
	}
	got, err = f.svc.ResultsCSV(f.ctx, outsider, job.ID)
	if err != nil || len(csvRows(t, string(got.Body))) != 2 {
		t.Errorf("another organization's administrator: %v", err)
	}
	stranger := f.user("nobody@example.com")
	_, err = f.svc.ResultsCSV(f.ctx, stranger, job.ID)
	wantKind(t, "no role", err, apperr.KindNotFound, "")

	f.refuseAudit()
	if got, err := f.svc.ResultsCSV(f.ctx, viewer, job.ID); err == nil || got != nil {
		t.Errorf("an export without its record: %+v %v", got, err)
	}
}
