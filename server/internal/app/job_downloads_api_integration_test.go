//go:build integration

package app_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// zipFiles reads a ZIP archive's files by name.
func zipFiles(t *testing.T, b []byte) map[string]string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("not an archive: %v: %.200s", err, b)
	}
	out := map[string]string{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		out[f.Name] = string(body)
	}
	return out
}

// TestJobDownloadsAPI downloads a run's output, a job's output as an
// archive and its results as CSV through the console API, as every kind of
// caller, and checks what each download holds, how it is sent, and what it
// recorded (ADR-0064).
func TestJobDownloadsAPI(t *testing.T) {
	h := newHarness(t, false)
	admin, _ := setUp(t, h)
	acme := orgID(t, admin, "Acme")
	var hq, branch, globex, plant idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/sites", map[string]string{"name": "HQ", "timezone": "UTC"}, &hq)
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/sites", map[string]string{"name": "Branch", "timezone": "UTC"}, &branch)
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations", map[string]any{"name": "Globex"}, &globex)
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+globex.ID+"/sites", map[string]string{"name": "Plant", "timezone": "UTC"}, &plant)
	hqPC := enrollAt(t, h, admin, hq.ID, "hq-01")
	branchPC := enrollAt(t, h, admin, branch.ID, "br-01")
	plantPC := enrollAt(t, h, admin, plant.ID, "pl-01")

	signIn := func(email string, assignments ...map[string]any) *client {
		invite(t, h, admin, email, assignments)
		c := h.client()
		c.signIn(email, "a long and unusual passphrase", "")
		return c
	}
	tech := signIn("tess@acme.example", map[string]any{"role": "technician", "organizationId": acme, "siteId": hq.ID})
	viewer := signIn("rory@acme.example", map[string]any{"role": "read_only", "organizationId": acme})
	siteAdmin := signIn("sam@acme.example", map[string]any{"role": "site_admin", "organizationId": acme, "siteId": hq.ID})
	outsider := signIn("oscar@globex.example", map[string]any{"role": "org_admin", "organizationId": globex.ID})

	var sc scriptView
	admin.expect(http.StatusCreated, "POST", "/api/v1/scripts", map[string]any{"name": "=Collect", "shell": "bash", "body": "echo"}, &sc)
	var job jobView
	admin.expect(http.StatusCreated, "POST", "/api/v1/jobs", map[string]any{
		"scriptId": sc.ID, "deviceIds": []string{hqPC.id, branchPC.id, plantPC.id},
	}, &job)
	hqRun := hqPC.runIt(t, "hq "+outputMarker+"\n")
	branchPC.runIt(t, "branch "+outputMarker+"\n")
	plantRun := plantPC.runIt(t, "plant "+outputMarker+"\n")

	// Every answer that is not an output download is kept, to be searched
	// for the marker.
	var others []string
	get := func(c *client, path string, status int) response {
		t.Helper()
		r := c.do("GET", path, nil)
		if r.status != status {
			t.Fatalf("GET %s: %d, want %d: %s", path, r.status, status, r.body)
		}
		if !strings.Contains(path, "download=") && !strings.HasSuffix(path, "/output.zip") {
			others = append(others, path+": "+string(r.body))
		}
		return r
	}
	file := func(r response, contentType, name string) {
		t.Helper()
		if got := r.header.Get("Content-Type"); got != contentType {
			t.Errorf("Content-Type %q, want %q", got, contentType)
		}
		if got := r.header.Get("Content-Disposition"); got != `attachment; filename="`+name+`"` {
			t.Errorf("Content-Disposition %q, want %s", got, name)
		}
		if got := r.header.Get("Cache-Control"); got != "no-store" {
			t.Errorf("Cache-Control %q", got)
		}
	}

	type caller struct {
		name      string
		c         *client
		run       int    // each of the run's downloads
		zip       int    // the job's archive
		zipHolds  string // whose output the archive holds
		csvRows   int    // runs in the results
		canDownld bool
	}
	callers := []caller{
		{"technician", tech, 200, 200, "hq", 1, true},
		{"read-only", viewer, 403, 403, "", 2, false},
		{"site admin", siteAdmin, 200, 200, "hq", 1, true},
		{"other organization", outsider, 404, 200, "plant", 1, true},
		{"super admin", admin, 200, 200, "hq branch plant", 3, true},
	}
	base := "hq-01_" + hqRun
	for _, cl := range callers {
		var j jobView
		get(cl.c, "/api/v1/jobs/"+job.ID, 200).decode(t, &j)
		if j.CanDownload != cl.canDownld {
			t.Errorf("%s: canDownloadOutput %v", cl.name, j.CanDownload)
		}
		// In this order, so the one refusal recorded is the first.
		for _, d := range []struct{ what, contentType, name string }{
			{"stdout", "text/plain; charset=utf-8", base + "_stdout.txt"},
			{"stderr", "text/plain; charset=utf-8", base + "_stderr.txt"},
			{"json", "application/json; charset=utf-8", base + ".json"},
		} {
			r := get(cl.c, "/api/v1/job-runs/"+hqRun+"/output?download="+d.what, cl.run)
			if cl.run != 200 {
				if strings.Contains(string(r.body), outputMarker) {
					t.Errorf("%s: a refused %s download holds output", cl.name, d.what)
				}
				continue
			}
			file(r, d.contentType, d.name)
			// The run wrote to stdout only.
			if (d.what != "stderr") != strings.Contains(string(r.body), "hq "+outputMarker) {
				t.Errorf("%s: %s download %q", cl.name, d.what, r.body)
			}
		}

		r := get(cl.c, "/api/v1/jobs/"+job.ID+"/output.zip", cl.zip)
		if cl.zip == 200 {
			file(r, "application/zip", "_Collect_"+job.ID+"_output.zip")
			files := zipFiles(t, r.body)
			var all strings.Builder
			for name, body := range files {
				all.WriteString(name + "\n" + body)
			}
			for _, who := range []string{"hq", "branch", "plant"} {
				if strings.Contains(cl.zipHolds, who) != strings.Contains(all.String(), who+" "+outputMarker) {
					t.Errorf("%s: the archive's %s output: %v", cl.name, who, strings.Contains(all.String(), who+" "+outputMarker))
				}
			}
			if _, ok := files["runs.csv"]; !ok {
				t.Errorf("%s: no runs.csv in %d files", cl.name, len(files))
			}
		} else if strings.Contains(string(r.body), outputMarker) {
			t.Errorf("%s: a refused archive holds output", cl.name)
		}

		r = get(cl.c, "/api/v1/jobs/"+job.ID+"/runs.csv", 200)
		file(r, "text/csv; charset=utf-8", "_Collect_"+job.ID+"_results.csv")
		if n := strings.Count(string(r.body), "\n"); n != cl.csvRows+1 || !strings.HasPrefix(string(r.body), "\xef\xbb\xbfDevice,") {
			t.Errorf("%s: results %q", cl.name, r.body)
		}
	}

	// Asking for something else, and asking without signing in.
	wantStatus(t, tech.do("GET", "/api/v1/job-runs/"+hqRun+"/output?download=zip", nil), http.StatusUnprocessableEntity, "")
	wantStatus(t, tech.do("GET", "/api/v1/job-runs/"+hqRun+"/output?download=", nil), http.StatusUnprocessableEntity, "")
	wantStatus(t, tech.do("GET", "/api/v1/jobs/nope/output.zip", nil), http.StatusNotFound, "not_found")
	wantStatus(t, tech.do("GET", "/api/v1/jobs/"+job.ID+"x/runs.csv", nil), http.StatusNotFound, "not_found")
	anon := h.client()
	for _, path := range []string{"/api/v1/job-runs/" + hqRun + "/output?download=json", "/api/v1/jobs/" + job.ID + "/output.zip",
		"/api/v1/jobs/" + job.ID + "/runs.csv"} {
		wantStatus(t, anon.do("GET", path, nil), http.StatusUnauthorized, "")
	}

	// What was recorded: each run download with what it downloaded, the
	// archive once per run it held, the results as an export.
	var l struct {
		Items []struct {
			Action     string         `json:"action"`
			ActorLabel string         `json:"actorLabel"`
			Outcome    string         `json:"outcome"`
			TargetType string         `json:"targetType"`
			TargetID   string         `json:"targetId"`
			Details    map[string]any `json:"details"`
		} `json:"items"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/audit?limit=500", nil, &l)
	count := map[string]int{}
	for _, e := range l.Items {
		d, _ := e.Details["download"].(string)
		count[e.Action+" "+e.ActorLabel+" "+e.Outcome+" "+e.TargetType+" "+d]++
		if e.Action == "job.results_export" && (e.TargetID != job.ID || e.Details["rows"] == nil) {
			t.Errorf("results record %+v", e)
		}
		if e.Action == "job_run.output_view" && e.Outcome == "success" && d == "zip" && e.ActorLabel == "oscar@globex.example" && e.TargetID != plantRun {
			t.Errorf("another organization's archive recorded %s", e.TargetID)
		}
	}
	for key, want := range map[string]int{
		"job_run.output_view tess@acme.example success job_run stdout":    1,
		"job_run.output_view tess@acme.example success job_run stderr":    1,
		"job_run.output_view tess@acme.example success job_run json":      1,
		"job_run.output_view tess@acme.example success job_run zip":       1,
		"job_run.output_view admin@msp.example success job_run zip":       3,
		"job_run.output_view oscar@globex.example success job_run zip":    1,
		"job_run.output_view rory@acme.example denied job_run stdout":     1,
		"job_run.output_view rory@acme.example denied job zip":            1,
		"job.results_export rory@acme.example success job ":               1,
		"job.results_export admin@msp.example success job ":               2,
		"job_run.output_view oscar@globex.example denied job_run stdout":  0,
		"job_run.output_view oscar@globex.example success job_run stdout": 0,
	} {
		if count[key] != want {
			t.Errorf("%q recorded %d times, want %d", key, count[key], want)
		}
	}

	// The marker reached no answer but the downloads, and not the log.
	for where, text := range map[string]string{
		"an answer":         strings.Join(others, "\n"),
		"the server's log":  h.logs.String(),
		"the audit records": mustAudit(t, admin),
	} {
		if strings.Contains(text, outputMarker) {
			t.Errorf("%s holds output", where)
		}
	}

	// No record, no download: with audit appends failing, the archive is
	// refused before anything is sent.
	ctx := context.Background()
	super, err := pgx.Connect(ctx, h.db.SuperDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = super.Close(ctx) }()
	for _, sql := range []string{
		`CREATE FUNCTION test_refuse_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'no audit'; END $$`,
		`CREATE TRIGGER test_refuse_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION test_refuse_audit()`,
	} {
		if _, err := super.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{"/api/v1/jobs/" + job.ID + "/output.zip", "/api/v1/job-runs/" + hqRun + "/output?download=stdout",
		"/api/v1/jobs/" + job.ID + "/runs.csv"} {
		r := tech.do("GET", path, nil)
		var body struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if r.status != http.StatusInternalServerError || json.Unmarshal(r.body, &body) != nil || body.Error.Code != "internal_error" ||
			strings.Contains(string(r.body), outputMarker) {
			t.Errorf("%s without its record: %d %.200s", path, r.status, r.body)
		}
	}
}

// TestJobOutputZipLimit: one person may download six jobs' archives a
// minute; the seventh is answered 429 with Retry-After before anything is
// recorded, and another person is not held back (ADR-0064).
func TestJobOutputZipLimit(t *testing.T) {
	h := newHarness(t, false)
	admin, _ := setUp(t, h)
	acme := orgID(t, admin, "Acme")
	var hq idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/sites", map[string]string{"name": "HQ", "timezone": "UTC"}, &hq)
	pc := enrollAt(t, h, admin, hq.ID, "hq-01")
	invite(t, h, admin, "tess@acme.example", []map[string]any{{"role": "technician", "organizationId": acme, "siteId": hq.ID}})
	tech := h.client()
	tech.signIn("tess@acme.example", "a long and unusual passphrase", "")

	var sc scriptView
	admin.expect(http.StatusCreated, "POST", "/api/v1/scripts", map[string]any{"name": "Collect", "shell": "bash", "body": "echo"}, &sc)
	var job jobView
	admin.expect(http.StatusCreated, "POST", "/api/v1/jobs", map[string]any{"scriptId": sc.ID, "deviceIds": []string{pc.id}}, &job)
	pc.runIt(t, "hq "+outputMarker+"\n")

	path := "/api/v1/jobs/" + job.ID + "/output.zip"
	for i := range 6 {
		if r := tech.do("GET", path, nil); r.status != http.StatusOK {
			t.Fatalf("archive %d: %d %.200s", i+1, r.status, r.body)
		}
	}
	r := tech.do("GET", path, nil)
	wantStatus(t, r, http.StatusTooManyRequests, "rate_limited")
	if got := r.header.Get("Retry-After"); got != "10" {
		t.Errorf("Retry-After %q", got)
	}
	if strings.Contains(string(r.body), outputMarker) {
		t.Error("a refused archive holds output")
	}
	if r := admin.do("GET", path, nil); r.status != http.StatusOK {
		t.Errorf("another person's archive: %d %.200s", r.status, r.body)
	}

	var l struct {
		Items []struct {
			Action     string         `json:"action"`
			ActorLabel string         `json:"actorLabel"`
			Details    map[string]any `json:"details"`
		} `json:"items"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/audit?limit=500", nil, &l)
	n := 0
	for _, e := range l.Items {
		if e.Action == "job_run.output_view" && e.ActorLabel == "tess@acme.example" && e.Details["download"] == "zip" {
			n++
		}
	}
	if n != 6 {
		t.Errorf("%d archive records for the technician, want 6", n)
	}
}
