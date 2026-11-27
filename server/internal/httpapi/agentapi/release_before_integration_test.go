//go:build integration

package agentapi_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/agents"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devices"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/agentapi"
	"github.com/paulmataruso/easyrmm/server/internal/inventory"
	"github.com/paulmataruso/easyrmm/server/internal/jobkeys"
	"github.com/paulmataruso/easyrmm/server/internal/jobs"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

// TestAgentOfTheReleaseBefore runs the agent of the release before this
// one, built from its tag (make agent-release-before), against this
// server's agent API and runs every kind of job it ran on Linux (ADR-0009,
// ADR-0064): each shell with arguments and exit codes, a timeout and a
// cancel. It sends no accepts and no program: its device never gets a
// PowerShell 7 job, its runs say the program was not reported, and every
// other job runs as before.
func TestAgentOfTheReleaseBefore(t *testing.T) {
	bin := os.Getenv("EASYRMM_TEST_AGENT_RELEASE_BEFORE")
	if bin == "" {
		t.Fatal("EASYRMM_TEST_AGENT_RELEASE_BEFORE is not set (the agent of the release before; make agent-release-before builds it)")
	}
	inst := testdb.New(t)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	auditLog := audit.New(inst.DB, time.Now)
	svc := agents.New(inst.DB, auditLog, nil, log)
	_, jobKey, _ := ed25519.GenerateKey(rand.Reader)
	js := jobs.New(inst.DB, auditLog, jobkeys.Static(jobKey), 24*time.Hour, 24*time.Hour, log)
	t.Cleanup(js.Close)
	svc.SetUpdates(&agents.Builds{}, jobkeys.Static(jobKey))
	invs := inventory.New(inst.DB, 24*time.Hour, log)

	// The agent API on loopback, over HTTP, which the agent allows there.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := "http://127.0.0.1:" + strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	api, err := agentapi.New(svc, &agents.Builds{}, []agentapi.Address{{URL: server}}, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	api.WithJobs(js)
	api.WithInventory(invs)
	srv := &http.Server{Handler: api.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	var org, site, userID uuid.UUID
	if err := inst.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO organizations (name) VALUES ('Acme') RETURNING id`).Scan(&org); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO sites (organization_id, name) VALUES ($1, 'HQ') RETURNING id`, org).Scan(&site); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO users (email, display_name) VALUES ('tess@acme.example', 'Tess') RETURNING id`).Scan(&userID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO role_assignments (user_id, role, organization_id) VALUES ($1, 'technician', $2)`, userID, org)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	as := []rbac.Assignment{{Role: rbac.RoleTechnician, OrganizationID: org}}
	p, err := rbac.NewPrincipal(userID, as)
	if err != nil {
		t.Fatal(err)
	}
	tech := access.User(p, auth.DataScope(p), audit.Actor{Type: audit.ActorUser, ID: userID, Label: "tess@acme.example"})
	sys := access.System("test")
	tok, err := svc.CreateToken(ctx, sys, site, agents.TokenInput{Name: "Release before", ExpiresInDays: 1})
	if err != nil {
		t.Fatal(err)
	}

	// The agent of the release before enrolls and runs, its files under a
	// root of its own.
	root := t.TempDir()
	env := append(os.Environ(), "EASYRMM_AGENT_ROOT="+root, "EASYRMM_TOKEN="+tok.Secret)
	enroll := exec.Command(bin, "enroll", "--server", server) //nolint:gosec // the test's own build
	enroll.Env = env
	if out, err := enroll.CombinedOutput(); err != nil {
		t.Fatalf("enrolling: %v\n%s", err, out)
	}
	var logs bytes.Buffer
	agent := exec.Command(bin, "run") //nolint:gosec // as above
	agent.Env, agent.Stdout, agent.Stderr = env, &logs, &logs
	if err := agent.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = agent.Process.Kill()
		_ = agent.Wait()
		if t.Failed() {
			t.Logf("the agent's output:\n%s", logs.String())
		}
	})
	dev := devices.New(inst.DB, false)
	var device *devices.Device
	waitFor(t, time.Minute, "the agent to report", func() bool {
		list, err := dev.List(ctx, tech, devices.Query{})
		if err != nil || len(list) != 1 || list[0].Agent == nil || !list[0].Agent.Online {
			return false
		}
		device = list[0]
		return true
	})
	if device.Agent.Version != "1.0.0-rc.4" || device.Agent.Accepts != nil || device.Agent.PowerShell7 != nil {
		t.Errorf("the agent of the release before: %+v", device.Agent)
	}

	run := func(shell, body string, args []string, timeout int) *jobs.Run {
		t.Helper()
		sc, err := js.CreateScript(ctx, sys, jobs.ScriptInput{OrganizationID: &org, Name: shell + " " + uuid.NewString()[:8], Shell: shell, Body: body, TimeoutSeconds: timeout})
		if err != nil {
			t.Fatal(err)
		}
		job, err := js.CreateJob(ctx, tech, jobs.JobInput{ScriptID: sc.ID, DeviceIDs: []uuid.UUID{device.ID}, Args: args})
		if err != nil {
			t.Fatal(err)
		}
		var r *jobs.Run
		waitFor(t, time.Minute, shell+" to finish", func() bool {
			r, err = js.GetRun(ctx, tech, job.Runs[0].ID)
			return err == nil && r.FinishedAt != nil
		})
		return r
	}
	output := func(r *jobs.Run) (string, string) {
		t.Helper()
		out, err := js.ReadOutput(ctx, tech, r.ID)
		if err != nil {
			t.Fatal(err)
		}
		return out.Stdout, out.Stderr
	}

	r := run("bash", "echo \"args: $1|$2\"\necho warning >&2\nexit 4\n", []string{"one", "two words"}, 60)
	if stdout, stderr := output(r); r.Status != jobs.StatusFailed || r.ExitCode == nil || *r.ExitCode != 4 || stdout != "args: one|two words\n" || stderr != "warning\n" {
		t.Errorf("bash: %+v %q %q", r, stdout, stderr)
	}
	// It reports no program: nothing is guessed.
	if r.Program != nil {
		t.Errorf("a program for the release before: %+v", r.Program)
	}
	r = run("sh", "echo \"$EASYRMM_RUN_ID\"", nil, 60)
	if stdout, _ := output(r); r.Status != jobs.StatusSucceeded || stdout != r.ID.String()+"\n" {
		t.Errorf("sh: %+v %q", r, stdout)
	}
	r = run("python3", "import sys\nprint(sys.argv[1:])\nsys.exit(2)\n", []string{"x y"}, 60)
	if stdout, _ := output(r); r.Status != jobs.StatusFailed || r.ExitCode == nil || *r.ExitCode != 2 || stdout != "['x y']\n" {
		t.Errorf("python3: %+v %q", r, stdout)
	}
	r = run("sh", "echo started; sleep 60", nil, 2)
	if stdout, _ := output(r); r.Status != jobs.StatusTimedOut || stdout != "started\n" {
		t.Errorf("a timeout: %+v %q", r, stdout)
	}

	// A cancel stops a running script.
	slow, err := js.CreateScript(ctx, sys, jobs.ScriptInput{OrganizationID: &org, Name: "Slow", Shell: "sh", Body: "echo started; sleep 600"})
	if err != nil {
		t.Fatal(err)
	}
	job, err := js.CreateJob(ctx, tech, jobs.JobInput{ScriptID: slow.ID, DeviceIDs: []uuid.UUID{device.ID}})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Minute, "the slow script to start", func() bool {
		r, err = js.GetRun(ctx, tech, job.Runs[0].ID)
		return err == nil && r.Status == jobs.StatusRunning
	})
	if _, err := js.CancelJob(ctx, tech, job.ID); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Minute, "the canceled script to stop", func() bool {
		r, err = js.GetRun(ctx, tech, job.Runs[0].ID)
		return err == nil && r.FinishedAt != nil
	})
	if r.Status != jobs.StatusCanceled {
		t.Errorf("canceled: %+v", r)
	}

	// Its device never gets a PowerShell 7 job: the agent never said it can
	// run one.
	seven, err := js.CreateScript(ctx, sys, jobs.ScriptInput{OrganizationID: &org, Name: "Seven", Shell: "pwsh", Body: "$PSVersionTable"})
	if err != nil {
		t.Fatal(err)
	}
	if err := inst.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE devices SET platform = 'windows' WHERE id = $1`, device.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	_, err = js.CreateJob(ctx, tech, jobs.JobInput{ScriptID: seven.ID, DeviceIDs: []uuid.UUID{device.ID}})
	var e *apperr.Error
	if !errors.As(err, &e) || !strings.Contains(e.Fields["deviceIds"], "agent has not yet said whether it can run PowerShell 7 scripts") {
		t.Errorf("a PowerShell 7 job for the release before: %v", err)
	}
}

func waitFor(t *testing.T, limit time.Duration, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(limit); !ok(); time.Sleep(200 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}
