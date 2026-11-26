//go:build integration

package jobs

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	agentjobs "github.com/paulmataruso/easyrmm/agent/jobs"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// A job with params goes only to agents that list job.params, is signed
// with the script and params hashes, and its audit holds the hash, never
// the params (ADR-0073).
func TestParamsJobs(t *testing.T) {
	f := newFixture(t)
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq})
	oldAgent := f.device(f.hq, "HQ-OLD", "windows")
	newAgent := f.device(f.hq, "HQ-NEW", "windows")
	const script = "$p = [Console]::In.ReadToEnd() | ConvertFrom-Json\n"
	create := func(device uuid.UUID, params string) (*Job, error) {
		sp := &spec{
			kind: KindScript, name: "params test", shell: agentproto.ShellPowerShell, body: script, args: []string{},
			params: json.RawMessage(params), timeout: 60, auditAction: "device.script_run",
		}
		return f.svc.create(f.ctx, tech, []uuid.UUID{device}, 1, sp, func(ctx context.Context, tx pgx.Tx) ([]target, error) {
			return f.svc.targets(ctx, tx, tech, []uuid.UUID{device}, rule{
				perm: rbac.PermScriptRun, verb: "run scripts", platforms: []string{"windows"}, runsOn: "x runs on", what: "x",
			})
		})
	}

	// The agents say what they accept in their polls.
	if _, err := f.svc.Poll(f.ctx, oldAgent, []string{agentproto.CapJobPwsh}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Poll(f.ctx, newAgent, []string{agentproto.CapJobPwsh, agentproto.CapJobParams}); err != nil {
		t.Fatal(err)
	}

	// Protocol level: an agent without job.params is refused at creation.
	fieldErr(t, errOf(create(oldAgent, `{"name":"alice"}`)), "deviceIds", "too old")
	fieldErr(t, errOf(create(newAgent, `["not an object"]`)), "params", "JSON object")

	job, err := create(newAgent, `{"zeta": 1, "name": "alice"}`)
	if err != nil {
		t.Fatal(err)
	}
	canon := `{"name":"alice","zeta":1}`
	if got := f.str(`SELECT params::text FROM jobs WHERE id = $1`, job.ID); !strings.Contains(got, "alice") {
		t.Errorf("stored params %s", got)
	}
	if got := f.str(`SELECT array_to_string(requires, ',') FROM jobs WHERE id = $1`, job.ID); got != agentproto.CapJobParams {
		t.Errorf("requires %q", got)
	}

	// Delivery: signed, hashes verify, params canonical.
	resp, err := f.svc.Poll(f.ctx, newAgent, []string{agentproto.CapJobPwsh, agentproto.CapJobParams})
	if err != nil || len(resp.Jobs) != 1 {
		t.Fatalf("poll %+v, %v", resp, err)
	}
	p, err := agentproto.VerifyJob(f.key, resp.Jobs[0], newAgent.String(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	h, _ := agentproto.HashParams([]byte(canon))
	if p.V != agentproto.JobPayloadVersionParams || string(p.Params) != canon || p.ParamsSHA256 != h || p.ScriptSHA256 != agentproto.HashScript(script) {
		t.Errorf("payload %+v", p)
	}

	// The audit has the hash and never the params.
	audited := f.str(`SELECT details::text FROM audit_log WHERE action = 'device.script_run' AND device_id = $1`, newAgent)
	if !strings.Contains(audited, `"paramsSha256": "`+h+`"`) || strings.Contains(audited, "alice") || strings.Contains(audited, "zeta") {
		t.Errorf("audit %s", audited)
	}
	if got := f.str(`SELECT encode(params_sha256, 'hex') FROM jobs WHERE id = $1`, job.ID); got != h || hex.EncodedLen(32) != len(h) {
		t.Errorf("stored hash %s", got)
	}

	// An agent that reports a build without job.params after the job was
	// queued is not sent it.
	job2, err := create(newAgent, `{"name":"bob"}`)
	if err != nil {
		t.Fatal(err)
	}
	resp, err = f.svc.Poll(f.ctx, newAgent, []string{agentproto.CapJobPwsh})
	if err != nil || len(resp.Jobs) != 0 {
		t.Errorf("a params job %s went to an agent without job.params: %+v, %v", job2.ID, resp, err)
	}
}

func errOf(_ *Job, err error) error { return err }

// agentClient lets the real agent worker talk to the service as one device.
type agentClient struct {
	s   *Service
	dev uuid.UUID
}

func (a agentClient) Poll(ctx context.Context, accepts []string) (*agentproto.PollResponse, error) {
	return a.s.Poll(ctx, a.dev, accepts)
}

func (a agentClient) Start(ctx context.Context, run string) (*agentproto.StartResponse, error) {
	return a.s.Start(ctx, a.dev, uuid.MustParse(run))
}

func (a agentClient) Result(ctx context.Context, run string, r agentproto.ResultRequest) error {
	return a.s.Result(ctx, a.dev, uuid.MustParse(run), r)
}

// The real agent worker verifies and runs a params job from the real
// service: the script reads the params on stdin and finds them nowhere on
// its command line.
func TestParamsJobEndToEndWithTheAgent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the script is sh")
	}
	f := newFixture(t)
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq})
	dev := f.device(f.hq, "HQ-LNX", "linux")
	sp := &spec{
		kind: KindScript, name: "params e2e", shell: agentproto.ShellSh, args: []string{}, timeout: 60, auditAction: "device.script_run",
		body:   "[ \"$(cat)\" = '{\"name\":\"alice\",\"zeta\":1}' ] || exit 1\ncase \"$(tr '\\0' ' ' < /proc/$$/cmdline)\" in *alice*) exit 2;; esac\n",
		params: json.RawMessage(`{"zeta": 1, "name": "alice"}`),
	}
	create := func() *Job {
		job, err := f.svc.create(f.ctx, tech, []uuid.UUID{dev}, 1, sp, func(ctx context.Context, tx pgx.Tx) ([]target, error) {
			return f.svc.targets(ctx, tx, tech, []uuid.UUID{dev}, rule{
				perm: rbac.PermScriptRun, verb: "run scripts", platforms: []string{"linux"}, runsOn: "x runs on", what: "x",
				requires: []string{agentproto.CapJobParams},
			})
		})
		if err != nil {
			t.Fatal(err)
		}
		return job
	}
	// The agent reports what it accepts before a params job can be made.
	if _, err := f.svc.Poll(f.ctx, dev, agentjobs.Accepts()); err != nil {
		t.Fatal(err)
	}
	job := create()
	run := f.runOn(job, dev)

	w := &agentjobs.Worker{
		Client: agentClient{f.svc, dev}, DeviceID: dev.String(), Dir: t.TempDir(), Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		MinRetry: 10 * time.Millisecond, MaxRetry: 50 * time.Millisecond,
	}
	if err := w.SetKey(agentproto.EncodeKey(f.key)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(f.ctx)
	done := make(chan struct{})
	go func() { _ = w.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		st := f.str(`SELECT status || ' ' || coalesce(exit_code::text, '-') FROM job_runs WHERE id = $1`, run)
		if st == "succeeded 0" {
			break
		}
		if strings.HasPrefix(st, "failed") || time.Now().After(deadline) {
			t.Fatalf("run ended as %q", st)
		}
	}
}
