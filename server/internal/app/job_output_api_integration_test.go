//go:build integration

package app_test

import (
	"context"
	"crypto/ed25519"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	agentclient "github.com/paulmataruso/easyrmm/agent/client"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/reports"
)

// Markers that must reach no one but the output and arguments reads.
const (
	outputMarker   = "out-marker-a41c"
	argumentMarker = "arg-marker-07be"
)

// collector is a TCP syslog collector that keeps everything it receives.
type collector struct {
	ln  net.Listener
	mu  sync.Mutex
	got strings.Builder
}

func newCollector(t *testing.T) *collector {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c := &collector{ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				buf := make([]byte, 32<<10)
				for {
					n, err := conn.Read(buf)
					c.mu.Lock()
					c.got.Write(buf[:n])
					c.mu.Unlock()
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	return c
}

func (c *collector) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.got.String()
}

// enrolled is a device enrolled through the agent API, with its client
// and the key its jobs are signed with.
type enrolled struct {
	id  string
	ac  *agentclient.Client
	key ed25519.PublicKey
}

func enrollAt(t *testing.T, h *harness, admin *client, site, name string) enrolled {
	t.Helper()
	var token struct {
		Secret string `json:"secret"`
	}
	admin.expect(http.StatusCreated, "POST", "/api/v1/sites/"+site+"/enrollment-tokens", map[string]any{"name": name, "expiresInDays": 1}, &token)
	ac := h.agentClient()
	key := newKey(t)
	enr, err := ac.Enroll(context.Background(), token.Secret, key.Public().(ed25519.PublicKey), facts(name))
	if err != nil {
		t.Fatal(err)
	}
	ac.SetIdentity(enr.DeviceID, key)
	jobKey, err := agentproto.DecodeKey(enr.JobKey)
	if err != nil {
		t.Fatal(err)
	}
	return enrolled{id: enr.DeviceID, ac: ac, key: jobKey}
}

// runIt runs the device's waiting job and reports output.
func (e enrolled) runIt(t *testing.T, stdout string) string {
	t.Helper()
	ctx := context.Background()
	poll, err := e.ac.Poll(ctx)
	if err != nil || len(poll.Jobs) != 1 {
		t.Fatalf("poll %+v %v", poll, err)
	}
	p, err := agentproto.VerifyJob(e.key, poll.Jobs[0], e.id, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if st, err := e.ac.Start(ctx, p.RunID); err != nil || !st.Proceed {
		t.Fatalf("start %+v %v", st, err)
	}
	zero := 0
	if err := e.ac.Result(ctx, p.RunID, agentproto.ResultRequest{Status: agentproto.RunSucceeded, ExitCode: &zero, Stdout: stdout}); err != nil {
		t.Fatal(err)
	}
	return p.RunID
}

// TestJobOutputAPI reads a job's output and arguments through the console
// API as callers with and without job.view_sensitive, and looks for them
// everywhere else they could leak: every other job and run answer,
// reports and their downloads, the audit log and its forwarding, and the
// server's log (ADR-0063).
func TestJobOutputAPI(t *testing.T) {
	h := newHarness(t, false)
	admin, _ := setUp(t, h)
	ctx := context.Background()
	acme := orgID(t, admin, "Acme")
	var hq, branch, globex, plant idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/sites", map[string]string{"name": "HQ", "timezone": "UTC"}, &hq)
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/sites", map[string]string{"name": "Branch", "timezone": "UTC"}, &branch)
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations", map[string]any{"name": "Globex"}, &globex)
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+globex.ID+"/sites", map[string]string{"name": "Plant", "timezone": "UTC"}, &plant)
	hqPC := enrollAt(t, h, admin, hq.ID, "hq-01")
	branchPC := enrollAt(t, h, admin, branch.ID, "br-01")
	plantPC := enrollAt(t, h, admin, plant.ID, "pl-01")

	// Audit records are forwarded from here on.
	col := newCollector(t)
	admin.expect(http.StatusOK, "PUT", "/api/v1/settings/audit-forwarding", map[string]any{
		"enabled": true, "transport": "tcp", "host": "127.0.0.1", "port": col.ln.Addr().(*net.TCPAddr).Port, "facility": 13, "startFrom": "now",
	}, nil)

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
	admin.expect(http.StatusCreated, "POST", "/api/v1/scripts", map[string]any{"name": "Everywhere", "shell": "bash", "body": "echo \"$@\""}, &sc)
	var job jobView
	admin.expect(http.StatusCreated, "POST", "/api/v1/jobs", map[string]any{
		"scriptId": sc.ID, "deviceIds": []string{hqPC.id, branchPC.id, plantPC.id}, "args": []string{argumentMarker},
	}, &job)
	hqRun := hqPC.runIt(t, "key "+outputMarker+"\n")
	branchPC.runIt(t, "key "+outputMarker+"\n")
	plantPC.runIt(t, "key "+outputMarker+"\n")

	// Every answer but the two reads, for every caller, is kept to be
	// searched for the markers.
	var others []string
	get := func(c *client, path string, status int) response {
		t.Helper()
		r := c.do("GET", path, nil)
		if r.status != status {
			t.Fatalf("GET %s: %d, want %d: %s", path, r.status, status, r.body)
		}
		if !strings.HasSuffix(path, "/output") && !strings.HasSuffix(path, "/arguments") {
			others = append(others, path+": "+string(r.body))
		}
		return r
	}
	type caller struct {
		name             string
		c                *client
		run, output      int
		job, args        int
		canViewOutput    bool
		canViewArguments bool
	}
	callers := []caller{
		{"technician", tech, 200, 200, 200, 200, true, true},
		{"read-only", viewer, 200, 403, 200, 403, false, false},
		{"site admin", siteAdmin, 200, 200, 200, 200, true, true},
		{"other organization", outsider, 404, 404, 200, 200, false, true},
		{"super admin", admin, 200, 200, 200, 200, true, true},
	}
	for _, cl := range callers {
		get(cl.c, "/api/v1/jobs", 200)
		get(cl.c, "/api/v1/job-runs?deviceId="+hqPC.id, 200)
		get(cl.c, "/api/v1/job-runs?deviceId="+plantPC.id, 200)
		var r struct {
			CanViewOutput *bool `json:"canViewOutput"`
		}
		rr := get(cl.c, "/api/v1/job-runs/"+hqRun, cl.run)
		if cl.run == 200 {
			rr.decode(t, &r)
			hasSizes := strings.Contains(string(rr.body), `"stdoutBytes":`) && strings.Contains(string(rr.body), `"outputRemovedAt":`)
			if r.CanViewOutput == nil || *r.CanViewOutput != cl.canViewOutput || hasSizes != cl.canViewOutput {
				t.Errorf("%s: run %s", cl.name, rr.body)
			}
		}
		var j jobView
		get(cl.c, "/api/v1/jobs/"+job.ID, cl.job).decode(t, &j)
		if j.ArgCount != 1 || j.CanViewArguments != cl.canViewArguments {
			t.Errorf("%s: job %+v", cl.name, j)
		}
		out := get(cl.c, "/api/v1/job-runs/"+hqRun+"/output", cl.output)
		if (cl.output == 200) != strings.Contains(string(out.body), outputMarker) {
			t.Errorf("%s: output %s", cl.name, out.body)
		}
		args := get(cl.c, "/api/v1/jobs/"+job.ID+"/arguments", cl.args)
		if (cl.args == 200) != strings.Contains(string(args.body), argumentMarker) {
			t.Errorf("%s: arguments %s", cl.name, args.body)
		}
	}
	anon := h.client()
	for _, path := range []string{"/api/v1/job-runs/" + hqRun + "/output", "/api/v1/jobs/" + job.ID + "/arguments"} {
		wantStatus(t, anon.do("GET", path, nil), http.StatusUnauthorized, "")
	}
	wantStatus(t, anon.do("DELETE", "/api/v1/job-runs/"+hqRun+"/output", nil), http.StatusUnauthorized, "")
	wantStatus(t, tech.do("GET", "/api/v1/job-runs/nope/output", nil), http.StatusNotFound, "not_found")

	// An open run has no output yet.
	var open jobView
	tech.expect(http.StatusCreated, "POST", "/api/v1/jobs", map[string]any{"scriptId": sc.ID, "deviceIds": []string{hqPC.id}}, &open)
	if open.ArgCount != 0 || !open.CanViewArguments {
		t.Errorf("new job %+v", open)
	}
	wantStatus(t, tech.do("GET", "/api/v1/job-runs/"+open.Runs[0].ID+"/output", nil), http.StatusConflict, "run_open")
	wantStatus(t, tech.do("DELETE", "/api/v1/job-runs/"+open.Runs[0].ID+"/output", nil), http.StatusConflict, "run_open")
	hqPC.runIt(t, "")
	wantStatus(t, tech.do("DELETE", "/api/v1/job-runs/"+open.Runs[0].ID+"/output", nil), http.StatusConflict, "no_output")

	// Removing output at once.
	wantStatus(t, viewer.do("DELETE", "/api/v1/job-runs/"+hqRun+"/output", nil), http.StatusForbidden, "forbidden")
	wantStatus(t, outsider.do("DELETE", "/api/v1/job-runs/"+hqRun+"/output", nil), http.StatusNotFound, "not_found")
	var removed struct {
		OutputRemovedAt *time.Time `json:"outputRemovedAt"`
		StdoutBytes     int        `json:"stdoutBytes"`
	}
	tech.expect(http.StatusOK, "DELETE", "/api/v1/job-runs/"+hqRun+"/output", nil, &removed)
	if removed.OutputRemovedAt == nil || removed.StdoutBytes != 0 {
		t.Errorf("removed %+v", removed)
	}
	wantStatus(t, tech.do("GET", "/api/v1/job-runs/"+hqRun+"/output", nil), http.StatusConflict, "output_removed")
	wantStatus(t, tech.do("DELETE", "/api/v1/job-runs/"+hqRun+"/output", nil), http.StatusConflict, "output_removed")

	// The site's administrators see who read and who was refused; another
	// organization's do not.
	type auditList struct {
		Items []struct {
			Action     string         `json:"action"`
			ActorLabel string         `json:"actorLabel"`
			Outcome    string         `json:"outcome"`
			TargetID   string         `json:"targetId"`
			Details    map[string]any `json:"details"`
		} `json:"items"`
	}
	seen := func(c *client) map[string]bool {
		t.Helper()
		got := map[string]bool{}
		for _, prefix := range []string{"job", "job_run"} {
			var l auditList
			c.expect(http.StatusOK, "GET", "/api/v1/audit?action="+prefix, nil, &l)
			for _, e := range l.Items {
				got[e.Action+" "+e.ActorLabel+" "+e.Outcome] = true
			}
		}
		return got
	}
	site := seen(siteAdmin)
	for _, want := range []string{
		"job_run.output_view tess@acme.example success",
		"job_run.output_view rory@acme.example denied",
		"job_run.output_view sam@acme.example success",
		"job_run.output_remove tess@acme.example success",
		"job.arguments_view tess@acme.example success",
		"job.arguments_view sam@acme.example success",
	} {
		if !site[want] {
			t.Errorf("the site's administrator does not see %q in %v", want, site)
		}
	}
	for k := range seen(outsider) {
		if strings.HasPrefix(k, "job_run.") || !strings.Contains(k, "oscar@globex.example") && !strings.Contains(k, "admin@msp.example") {
			t.Errorf("another organization sees %q", k)
		}
	}

	// Reports and their downloads.
	for _, name := range reports.Names() {
		for _, c := range []*client{viewer, tech} {
			get(c, "/api/v1/reports/"+name+"?organizationId="+acme, 200)
			get(c, "/api/v1/reports/"+name+"/csv?organizationId="+acme, 200)
		}
	}

	// Forwarding sends the new records, and nothing they did not hold.
	for i := 0; i < 20; i++ {
		n, err := h.deps.AuditFwd.Forward(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			break
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(col.String(), "job_run.output_remove") && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	forwarded := col.String()
	for _, action := range []string{"job_run.output_view", "job.arguments_view", "job_run.output_remove"} {
		if !strings.Contains(forwarded, action) {
			t.Errorf("%s was not forwarded", action)
		}
	}

	for where, text := range map[string]string{
		"an answer":         strings.Join(others, "\n"),
		"forwarding":        forwarded,
		"the server's log":  h.logs.String(),
		"the audit records": mustAudit(t, admin),
	} {
		if strings.Contains(text, outputMarker) || strings.Contains(text, argumentMarker) {
			t.Errorf("%s holds output or arguments", where)
		}
		for _, key := range []string{`"stdout"`, `"stderr"`, `"args"`} {
			if where == "an answer" && strings.Contains(text, key) {
				t.Errorf("an answer has the key %s", key)
			}
		}
	}
}

// mustAudit returns every audit record the super administrator sees, as
// the API answers them.
func mustAudit(t *testing.T, admin *client) string {
	t.Helper()
	r := admin.do("GET", "/api/v1/audit?limit=500", nil)
	if r.status != http.StatusOK {
		t.Fatalf("audit: %d %s", r.status, r.body)
	}
	return string(r.body)
}
