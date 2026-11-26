//go:build integration

package jobs

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	agentjobs "github.com/paulmataruso/easyrmm/agent/jobs"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
	"github.com/paulmataruso/easyrmm/server/internal/winmod"
	"github.com/paulmataruso/easyrmm/server/internal/winmod/defender"
)

const winmodSecret = "Tr0ub4dor&3-secret-marker"

// winmodTestScript reads its params on stdin, refuses to find them on its
// own command line, and prints a typed result: the name it was given and
// whether a password arrived.
const winmodTestScript = `in=$(cat)
case "$(tr '\0' ' ' < /proc/$$/cmdline)" in *needle*|*Tr0ub4dor*) exit 2;; esac
name=$(printf %s "$in" | sed -n 's/.*"name":"\([^"]*\)".*/\1/p')
pw=false
case "$in" in *Tr0ub4dor*) pw=true;; esac
printf 'EASYRMM-WINMOD-RESULT-V1 {"ok":true,"version":1,"data":{"name":"%s","passwordSeen":%s},"error":null}\n' "$name" "$pw"
`

type winmodTestData struct {
	Name         string `json:"name"`
	PasswordSeen bool   `json:"passwordSeen"`
}

func winmodTestAction(name string, mut func(*winmod.Action)) winmod.Action {
	a := winmod.Action{
		Module: modules.Defender, Name: name, Label: "Test " + name, Version: 1, Shell: agentproto.ShellSh,
		Script: winmodTestScript, ScriptSHA256: agentproto.HashScript(winmodTestScript),
		Permission: rbac.PermDefenderManage, Timeout: 60, Keep: time.Hour, Decode: winmod.Typed[winmodTestData](),
		Params: []winmod.Param{{Name: "name", Type: winmod.Name, Required: true, Max: 40}},
	}
	if mut != nil {
		mut(&a)
	}
	return a
}

// winmodFixture is the jobs fixture with a catalog of the real
// defender.status and test actions, the real module gate and a real sealer.
func winmodFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	acts := append(defender.Actions(),
		winmodTestAction("defender.test_read", func(a *winmod.Action) { a.Permission = rbac.PermDefenderView }),
		winmodTestAction("defender.test_destroy", func(a *winmod.Action) { a.Destructive, a.Subject = true, "name" }),
		winmodTestAction("defender.test_secret", func(a *winmod.Action) {
			a.Credential = true
			a.Params = append(a.Params, winmod.Param{Name: "password", Type: winmod.Text, Required: true, Min: 8, Max: 64, Secret: true})
		}),
	)
	cat, err := winmod.NewCatalog(acts...)
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	sealer, err := secrets.NewSealer(secrets.Key{ID: "k1", Raw: raw})
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	f.svc.SetWinmod(cat, modules.New(f.db, audit.New(f.db, time.Now), log), sealer)
	return f
}

func (f *fixture) winmodDevice(name, platform string) uuid.UUID {
	f.t.Helper()
	d := f.device(f.hq, name, platform)
	if _, err := f.svc.Poll(f.ctx, d, []string{agentproto.CapJobPwsh, agentproto.CapJobParams}); err != nil {
		f.t.Fatal(err)
	}
	return d
}

func (f *fixture) count(sql string, args ...any) int {
	f.t.Helper()
	return mustAtoi(f.t, f.str(`SELECT (`+sql+`)::text`, args...))
}

func mustAtoi(t *testing.T, s string) int {
	t.Helper()
	n := 0
	for _, r := range s {
		n = n*10 + int(r-'0')
	}
	return n
}

// statusResult is a plausible defender.status output.
const statusResult = `EASYRMM-WINMOD-RESULT-V1 {"ok":true,"version":1,"data":{"antivirusEnabled":true,"antispywareEnabled":true,` +
	`"realTimeProtectionEnabled":true,"behaviorMonitorEnabled":true,"ioavProtectionEnabled":true,"onAccessProtectionEnabled":true,` +
	`"nisEnabled":true,"tamperProtected":false,"runningMode":"Normal","computerState":0,"engineVersion":"1.1.24090.11",` +
	`"productVersion":"4.18.24090.11","serviceVersion":"4.18.24090.11","signatureVersion":"1.421.1.0",` +
	`"signatureUpdatedAt":"2026-11-26T08:00:00Z","signatureAgeDays":0,"quickScanAgeDays":1,"fullScanAgeDays":null},"error":null}` + "\n"

func TestWinmodDefenderStatus(t *testing.T) {
	f := winmodFixture(t)
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq})
	admin := f.user("root@example.com", rbac.Assignment{Role: rbac.RoleSuperAdmin})
	// Read-Only holds job.view but not job.view_sensitive.
	viewer := f.user("ro@example.com", rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: f.acme, SiteID: f.hq})
	dev := f.winmodDevice("HQ-WIN", "windows")

	run, err := f.svc.RunWinmod(f.ctx, tech, WinmodInput{DeviceID: dev, Action: "defender.status"})
	if err != nil {
		t.Fatal(err)
	}

	// Hidden: not in the Jobs list, the job's page, the run list or the
	// run's page, for anyone; a caller with job.view_sensitive finds it
	// only by asking for the kind.
	if got, _ := f.svc.ListJobs(f.ctx, admin, JobQuery{}); len(got) != 0 {
		t.Errorf("the Jobs list shows %d winmod jobs", len(got))
	}
	if got, _ := f.svc.ListJobs(f.ctx, viewer, JobQuery{Kind: KindWinmod}); len(got) != 0 {
		t.Errorf("a caller without job.view_sensitive lists %d winmod jobs", len(got))
	}
	if got, err := f.svc.ListJobs(f.ctx, admin, JobQuery{Kind: KindWinmod}); err != nil || len(got) != 1 {
		t.Errorf("job.view_sensitive with kind=winmod: %d, %v", len(got), err)
	}
	if _, err := f.svc.GetJob(f.ctx, viewer, run.JobID); !errors.Is(err, apperr.NotFound()) {
		t.Errorf("a viewer reads a winmod job: %v", err)
	}
	if got, _ := f.svc.ListRuns(f.ctx, admin, RunQuery{DeviceID: dev}); len(got) != 0 {
		t.Errorf("the run list shows %d winmod runs", len(got))
	}
	if _, err := f.svc.GetRun(f.ctx, viewer, run.RunID); !errors.Is(err, apperr.NotFound()) {
		t.Errorf("a viewer reads a winmod run: %v", err)
	}

	// Delivered signed, with the pinned script and the params hashes.
	resp, err := f.svc.Poll(f.ctx, dev, []string{agentproto.CapJobParams})
	if err != nil || len(resp.Jobs) != 1 {
		t.Fatalf("poll %+v, %v", resp, err)
	}
	p, err := agentproto.VerifyJob(f.key, resp.Jobs[0], dev.String(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	a, _ := f.svc.catalog.Lookup("defender.status")
	if p.V != agentproto.JobPayloadVersionParams || p.Shell != agentproto.ShellPowerShell || p.ScriptSHA256 != a.ScriptSHA256 ||
		string(p.Params) != `{}` || p.Script != a.Script {
		t.Errorf("payload %+v", p)
	}

	// The agent reports; the typed value is stored, not the text.
	if st, err := f.svc.Start(f.ctx, dev, run.RunID); err != nil || !st.Proceed {
		t.Fatal(st, err)
	}
	if err := f.svc.Result(f.ctx, dev, run.RunID, agentproto.ResultRequest{Status: StatusSucceeded, ExitCode: ptr(0), Stdout: "noise\n" + statusResult}); err != nil {
		t.Fatal(err)
	}
	if got := f.str(`SELECT status FROM job_runs WHERE id = $1`, run.RunID); got != "succeeded" {
		t.Errorf("status %s", got)
	}
	if n := f.count(`SELECT stdout_bytes + stderr_bytes FROM job_runs WHERE id = $1`, run.RunID); n != 0 {
		t.Errorf("the raw text of a typed result was kept (%d bytes)", n)
	}
	res, err := f.svc.ReadWinmodResult(f.ctx, tech, run.RunID)
	if err != nil || res.OK == nil || !*res.OK {
		t.Fatalf("%+v, %v", res, err)
	}
	var st defender.Status
	if err := json.Unmarshal(res.Data, &st); err != nil || st.SignatureVersion != "1.421.1.0" || st.TamperProtected == nil || *st.TamperProtected {
		t.Errorf("typed result %s, %v", res.Data, err)
	}

	// Audit: the request and the result, compact.
	if n := f.records("winmod.defender.status", "success", "tech@example.com"); n != 1 {
		t.Errorf("%d request rows", n)
	}
	got := f.str(`SELECT details::text FROM audit_log WHERE action = 'winmod.defender.status.result'`)
	if !strings.Contains(got, `"ok": true`) || !strings.Contains(got, `"module": "defender"`) {
		t.Errorf("result row %s", got)
	}
}

func TestWinmodRefusals(t *testing.T) {
	f := winmodFixture(t)
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq})
	ro := f.user("ro@example.com", rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: f.acme, SiteID: f.hq})
	globexTech := f.user("g@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.globex, SiteID: f.plant})
	admin := f.user("root@example.com", rbac.Assignment{Role: rbac.RoleSuperAdmin})
	dev := f.winmodDevice("HQ-WIN", "windows")
	linux := f.winmodDevice("HQ-LNX", "linux")
	jobsBefore := f.count(`SELECT count(*) FROM jobs`)
	run := func(c access.Caller, d uuid.UUID, action, params string) error {
		_, err := f.svc.RunWinmod(f.ctx, c, WinmodInput{DeviceID: d, Action: action, Params: json.RawMessage(params)})
		return err
	}

	// No such action, no such device, wrong platform.
	if err := run(tech, dev, "defender.nope", ``); !errors.Is(err, apperr.NotFound()) {
		t.Errorf("unknown action: %v", err)
	}
	fieldErr(t, run(tech, dev, "defender.status", `{"x":1}`), "params.x", "no parameter")
	fieldErr(t, run(tech, dev, "defender.test_read", `{"name":"a; Remove-Item *"}`), "params.name", "letters")
	fieldErr(t, run(tech, dev, "defender.test_read", `{}`), "params.name", "required")
	fieldErr(t, run(tech, linux, "defender.status", ``), "deviceIds", "Windows")

	// A caller without the permission.
	fieldErr(t, run(ro, dev, "defender.status", ``), "deviceIds", "cannot")

	// An organization the caller cannot see.
	fieldErr(t, run(globexTech, dev, "defender.status", ``), "deviceIds", "not visible")

	// A module switched off is not found, for the organization and for the site.
	f.exec(`INSERT INTO windows_module_settings (organization_id, module, enabled) VALUES ($1, 'defender', false)`, f.acme)
	if err := run(tech, dev, "defender.status", ``); !errors.Is(err, apperr.NotFound()) {
		t.Errorf("a disabled module was run: %v", err)
	}
	f.exec(`INSERT INTO windows_module_settings (organization_id, site_id, module, enabled) VALUES ($1, $2, 'defender', true)`, f.acme, f.hq)
	if err := run(tech, dev, "defender.status", ``); err != nil {
		t.Errorf("the site's own setting wins: %v", err)
	}
	f.exec(`DELETE FROM windows_module_settings`)

	// An organization outside the development scope gets nothing.
	restore := devscope.Set(f.globex)
	err := run(admin, dev, "defender.status", ``)
	restore()
	if !errors.Is(err, apperr.NotFound()) {
		t.Errorf("an organization outside the dev scope was served: %v", err)
	}
	if got := f.count(`SELECT count(*) FROM jobs`) - jobsBefore; got != 1 {
		t.Errorf("%d jobs were created, want the one from the site setting", got)
	}

	// No catalog, no job.
	bare := &Service{}
	if _, err := bare.RunWinmod(f.ctx, tech, WinmodInput{DeviceID: dev, Action: "defender.status"}); err == nil {
		t.Error("a service without a catalog ran an action")
	}
}

func TestWinmodConfirmationAndStepUp(t *testing.T) {
	f := winmodFixture(t)
	admin := f.user("admin@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.acme})
	dev := f.winmodDevice("HQ-LNX", "linux")
	in := func(action, params, confirm string) WinmodInput {
		return WinmodInput{DeviceID: dev, Action: action, Params: json.RawMessage(params), Confirm: confirm}
	}
	jobs := func() int { return f.count(`SELECT count(*) FROM jobs`) }
	stepUpRequired := errors.New("step up required")

	// Destructive: the confirmation must name the action and the subject.
	f.svc.SetStepUp(stepUpStub{})
	for _, confirm := range []string{"", "defender.test_destroy", "defender.test_destroy:other", "defender.test_read:alice"} {
		_, err := f.svc.RunWinmod(f.ctx, admin, in("defender.test_destroy", `{"name":"alice"}`, confirm))
		fieldErr(t, err, "confirm", "defender.test_destroy:alice")
	}
	if jobs() != 0 {
		t.Fatal("a job was created without confirmation")
	}

	// No step-up available: refused. A step-up that fails: refused, and no
	// job is written. One that passes: the job.
	f.svc.SetStepUp(nil)
	_, err := f.svc.RunWinmod(f.ctx, admin, in("defender.test_destroy", `{"name":"alice"}`, "defender.test_destroy:alice"))
	if e, ok := apperr.As(err); !ok || e.Code != "step_up_required" {
		t.Errorf("without a step-up service: %v", err)
	}
	f.svc.SetStepUp(stepUpStub{err: stepUpRequired})
	for _, in := range []WinmodInput{
		in("defender.test_destroy", `{"name":"alice"}`, "defender.test_destroy:alice"),
		in("defender.test_secret", `{"name":"alice","password":"`+winmodSecret+`"}`, ""),
	} {
		if _, err := f.svc.RunWinmod(f.ctx, admin, in); !errors.Is(err, stepUpRequired) {
			t.Errorf("%s without a fresh step-up: %v", in.Action, err)
		}
	}
	if jobs() != 0 || f.count(`SELECT count(*) FROM winmod_job_secrets`) != 0 {
		t.Fatal("a refused action left a job or a secret")
	}
	f.svc.SetStepUp(stepUpStub{})
	if _, err := f.svc.RunWinmod(f.ctx, admin, in("defender.test_destroy", `{"name":"alice"}`, "defender.test_destroy:alice")); err != nil {
		e, _ := apperr.As(err)
		t.Fatalf("%v %+v", err, e.Fields)
	}
	got := f.str(`SELECT details::text FROM audit_log WHERE action = 'winmod.defender.test_destroy'`)
	if !strings.Contains(got, `"confirmed": true`) || !strings.Contains(got, `"stepUp": true`) {
		t.Errorf("audit %s", got)
	}

	// A read needs neither, even with no step-up service.
	f.svc.SetStepUp(nil)
	if _, err := f.svc.RunWinmod(f.ctx, admin, in("defender.test_read", `{"name":"alice"}`, "")); err != nil {
		t.Errorf("a read: %v", err)
	}
}

func TestWinmodSecretsAreSealedAndDeliveredOnce(t *testing.T) {
	f := winmodFixture(t)
	f.svc.SetStepUp(stepUpStub{})
	admin := f.user("admin@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.acme})
	dev := f.winmodDevice("HQ-LNX", "linux")
	run, err := f.svc.RunWinmod(f.ctx, admin, WinmodInput{DeviceID: dev, Action: "defender.test_secret",
		Params: json.RawMessage(`{"name":"alice","password":"` + winmodSecret + `"}`)})
	if err != nil {
		e, _ := apperr.As(err)
		t.Fatalf("%v %+v", err, e)
	}

	// At rest: sealed, and nowhere else.
	if n := f.count(`SELECT count(*) FROM winmod_job_secrets WHERE job_id = $1 AND sealed <> '' AND sealed NOT LIKE '%' || $2 || '%'`, run.JobID, winmodSecret); n != 1 {
		t.Errorf("%d sealed secret rows", n)
	}
	for _, q := range []string{
		`SELECT params::text FROM jobs WHERE id = $1`, `SELECT winmod::text FROM jobs WHERE id = $1`,
		`SELECT body FROM jobs WHERE id = $1`, `SELECT string_agg(details::text, ' ') FROM audit_log WHERE details->>'jobId' = $1::text`,
	} {
		if got := f.str(q, run.JobID); strings.Contains(got, winmodSecret) || got == "" {
			t.Errorf("%s: %q", q, got)
		}
	}
	if got := f.str(`SELECT params::text FROM jobs WHERE id = $1`, run.JobID); !strings.Contains(got, "alice") || strings.Contains(got, "password") {
		t.Errorf("stored params %s", got)
	}
	if got := f.str(`SELECT details::text FROM audit_log WHERE action = 'winmod.defender.test_secret'`); !strings.Contains(got, "(secret)") {
		t.Errorf("audit %s", got)
	}

	// Delivery: the secret is in the signed params, once; the row is gone.
	resp, err := f.svc.Poll(f.ctx, dev, []string{agentproto.CapJobParams})
	if err != nil || len(resp.Jobs) != 1 {
		t.Fatalf("poll %+v, %v", resp, err)
	}
	p, err := agentproto.VerifyJob(f.key, resp.Jobs[0], dev.String(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if err := json.Unmarshal(p.Params, &got); err != nil || got["password"] != winmodSecret || got["name"] != "alice" {
		t.Errorf("delivered params %s, %v", p.Params, err)
	}
	if h, _ := agentproto.HashParams(p.Params); p.ParamsSHA256 != h {
		t.Error("the signed params hash does not cover the secret")
	}
	if f.count(`SELECT count(*) FROM winmod_job_secrets`) != 0 {
		t.Error("the secret row survived delivery")
	}
	if got := f.str(`SELECT params::text FROM jobs WHERE id = $1`, run.JobID); strings.Contains(got, winmodSecret) {
		t.Error("the job row holds the secret after delivery")
	}

	// A redelivery after a lost response is refused.
	f.asOwner(`UPDATE job_runs SET sent_at = now() - interval '1 hour' WHERE id = $1`, run.RunID)
	resp, err = f.svc.Poll(f.ctx, dev, []string{agentproto.CapJobParams})
	if err != nil || len(resp.Jobs) != 0 {
		t.Fatalf("a secret job was redelivered: %+v, %v", resp, err)
	}
	if got := f.str(`SELECT status || ': ' || error FROM job_runs WHERE id = $1`, run.RunID); !strings.HasPrefix(got, "expired: ") {
		t.Errorf("the redelivered run %q", got)
	}

	// The result keeps no raw output when the request held a secret, even if
	// the script printed it, and the failure text is generic.
	run2, err := f.svc.RunWinmod(f.ctx, admin, WinmodInput{DeviceID: dev, Action: "defender.test_secret",
		Params: json.RawMessage(`{"name":"bob","password":"` + winmodSecret + `"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Poll(f.ctx, dev, []string{agentproto.CapJobParams}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Start(f.ctx, dev, run2.RunID); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Result(f.ctx, dev, run2.RunID, agentproto.ResultRequest{Status: StatusFailed, ExitCode: ptr(1),
		Stdout: "password was " + winmodSecret, Stderr: winmodSecret, Error: "bad " + winmodSecret}); err != nil {
		t.Fatal(err)
	}
	if got := f.str(`SELECT error || '|' || stdout_bytes::text || '|' || stderr_bytes::text FROM job_runs WHERE id = $1`, run2.RunID); strings.Contains(got, winmodSecret) || !strings.HasSuffix(got, "|0|0") {
		t.Errorf("a failed secret run kept %q", got)
	}

	// An undelivered secret goes at expiry, and when its job has no open run.
	run3, err := f.svc.RunWinmod(f.ctx, admin, WinmodInput{DeviceID: dev, Action: "defender.test_secret",
		Params: json.RawMessage(`{"name":"carol","password":"` + winmodSecret + `"}`)})
	if err != nil {
		t.Fatal(err)
	}
	f.asOwner(`UPDATE winmod_job_secrets SET expires_at = now() - interval '1 minute' WHERE job_id = $1`, run3.JobID)
	if _, err := f.svc.Sweep(f.ctx); err != nil {
		t.Fatal(err)
	}
	if f.count(`SELECT count(*) FROM winmod_job_secrets`) != 0 {
		t.Error("an expired secret was kept")
	}
}

func TestWinmodForgedScriptIsNotSent(t *testing.T) {
	f := winmodFixture(t)
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq})
	dev := f.winmodDevice("HQ-WIN", "windows")
	run, err := f.svc.RunWinmod(f.ctx, tech, WinmodInput{DeviceID: dev, Action: "defender.status"})
	if err != nil {
		t.Fatal(err)
	}
	// Someone with the database changes the job's script after the request.
	f.asOwner(`UPDATE jobs SET body = body || E'\nRemove-Item C:\\ -Recurse' WHERE id = $1`, run.JobID)
	resp, err := f.svc.Poll(f.ctx, dev, []string{agentproto.CapJobParams})
	if err != nil || len(resp.Jobs) != 0 {
		t.Fatalf("a script that does not match its pin was sent: %+v, %v", resp, err)
	}
	if got := f.str(`SELECT status || ': ' || error FROM job_runs WHERE id = $1`, run.RunID); !strings.HasPrefix(got, "failed: The script does not match") {
		t.Errorf("run %q", got)
	}
}

func TestWinmodResultsMustBeTyped(t *testing.T) {
	f := winmodFixture(t)
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq})
	dev := f.winmodDevice("HQ-WIN", "windows")
	end := func(stdout string) (string, uuid.UUID) {
		run, err := f.svc.RunWinmod(f.ctx, tech, WinmodInput{DeviceID: dev, Action: "defender.status"})
		if err != nil {
			t.Fatal(err)
		}
		f.finish(dev, run.RunID, stdout, "")
		return f.str(`SELECT status || ': ' || error FROM job_runs WHERE id = $1`, run.RunID), run.RunID
	}
	for name, out := range map[string]string{
		"plain text":    "all fine\n",
		"wrong version": strings.Replace(statusResult, `"version":1`, `"version":2`, 1),
		"extra field":   strings.Replace(statusResult, `"runningMode"`, `"surprise":1,"runningMode"`, 1),
		"wrong type":    strings.Replace(statusResult, `"antivirusEnabled":true`, `"antivirusEnabled":"yes"`, 1),
	} {
		if got, _ := end(out); !strings.HasPrefix(got, "failed: The script finished, but its output was not a valid result") {
			t.Errorf("%s: run %q", name, got)
		}
	}

	// A typed failure from the script is a failed run with its reason.
	got, runID := end(`EASYRMM-WINMOD-RESULT-V1 {"ok":false,"version":1,"data":null,"error":{"code":"module_missing","message":"The Defender module is not installed."}}` + "\n")
	if !strings.HasPrefix(got, "failed: module_missing:") {
		t.Errorf("typed failure: %q", got)
	}
	res, err := f.svc.ReadWinmodResult(f.ctx, tech, runID)
	if err != nil || res.OK == nil || *res.OK || !strings.Contains(string(res.Failure), "module_missing") {
		t.Errorf("%+v, %v", res, err)
	}
}

func TestWinmodRetention(t *testing.T) {
	f := winmodFixture(t)
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq})
	dev := f.winmodDevice("HQ-WIN", "windows")
	run, err := f.svc.RunWinmod(f.ctx, tech, WinmodInput{DeviceID: dev, Action: "defender.status"})
	if err != nil {
		t.Fatal(err)
	}
	f.finish(dev, run.RunID, statusResult, "")
	other, _ := f.svc.RunWinmod(f.ctx, tech, WinmodInput{DeviceID: dev, Action: "defender.status"})

	if p, err := f.svc.Purge(f.ctx); err != nil || p.Jobs != 0 {
		t.Fatalf("a fresh read was purged: %+v, %v", p, err)
	}
	f.asOwner(`UPDATE jobs SET created_at = now() - interval '2 hours' WHERE id = ANY ($1)`, []uuid.UUID{run.JobID, other.JobID})
	if p, err := f.svc.Purge(f.ctx); err != nil || p.Jobs != 1 {
		t.Fatalf("purged %+v, %v (the open run's job must stay)", p, err)
	}
	if f.count(`SELECT count(*) FROM winmod_run_results`) != 0 || f.count(`SELECT count(*) FROM jobs WHERE id = $1`, run.JobID) != 0 {
		t.Error("the job or its typed result outlived its retention")
	}
	if f.records("winmod.defender.status", "success", "tech@example.com") != 2 {
		t.Error("the audit rows must stay")
	}
}

// The real agent worker runs a winmod job from the real service on stdin
// params, with a secret delivered once, and its typed result is stored. The
// scripts are shell: the PowerShell path is Windows-only and is covered by
// the Windows runner's test.
func TestWinmodEndToEndWithTheAgent(t *testing.T) {
	f := winmodFixture(t)
	f.svc.SetStepUp(stepUpStub{})
	admin := f.user("admin@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.acme})
	dev := f.device(f.hq, "HQ-LNX", "linux")
	if _, err := f.svc.Poll(f.ctx, dev, agentjobs.Accepts()); err != nil {
		t.Fatal(err)
	}
	read, err := f.svc.RunWinmod(f.ctx, admin, WinmodInput{DeviceID: dev, Action: "defender.test_read", Params: json.RawMessage(`{"name":"alice"}`)})
	if err != nil {
		t.Fatal(err)
	}
	withSecret, err := f.svc.RunWinmod(f.ctx, admin, WinmodInput{DeviceID: dev, Action: "defender.test_secret",
		Params: json.RawMessage(`{"name":"needle-free","password":"` + winmodSecret + `"}`)})
	if err != nil {
		t.Fatal(err)
	}

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
	for _, id := range []uuid.UUID{read.RunID, withSecret.RunID} {
		for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(50 * time.Millisecond) {
			st := f.str(`SELECT status FROM job_runs WHERE id = $1`, id)
			if st == "succeeded" {
				break
			}
			if st == "failed" || time.Now().After(deadline) {
				t.Fatalf("run %s ended as %q: %s", id, st, f.str(`SELECT error FROM job_runs WHERE id = $1`, id))
			}
		}
	}
	for id, want := range map[uuid.UUID]winmodTestData{
		read.RunID:       {Name: "alice"},
		withSecret.RunID: {Name: "needle-free", PasswordSeen: true},
	} {
		res, err := f.svc.ReadWinmodResult(f.ctx, admin, id)
		if err != nil || res.OK == nil || !*res.OK {
			t.Fatalf("%+v, %v", res, err)
		}
		var got winmodTestData
		if err := json.Unmarshal(res.Data, &got); err != nil || got != want {
			t.Errorf("result %s, want %+v (%v)", res.Data, want, err)
		}
	}
	if f.count(`SELECT count(*) FROM job_runs WHERE stdout_bytes + stderr_bytes > 0`) != 0 {
		t.Error("raw output was kept for typed results")
	}
}
