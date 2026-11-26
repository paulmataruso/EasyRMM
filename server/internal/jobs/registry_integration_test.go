//go:build integration

package jobs

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// What an agent that has the registry editor lists in its poll.
var registryAccepts = []string{agentproto.CapJobStructured, agentproto.CapBuiltin(agentproto.BuiltinRegistry, 1), agentproto.CapJobParams}

// registryFixture is a technician, a Windows device with an agent that
// lists the editor, and what a test needs to answer as that agent.
type registryFixture struct {
	*fixture
	tech, other, reader access.Caller
	pc                  uuid.UUID
}

func newRegistryFixture(t *testing.T) *registryFixture {
	t.Helper()
	f := newFixture(t)
	r := &registryFixture{fixture: f}
	r.tech = f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq})
	r.other = f.user("other@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq})
	r.reader = f.user("reader@example.com", rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: f.acme, SiteID: f.hq})
	r.pc = f.device(f.hq, "PC-12", "windows")
	if _, err := f.svc.Poll(f.ctx, r.pc, registryAccepts); err != nil {
		t.Fatal(err)
	}
	return r
}

// ask starts a read of a key as the technician.
func (r *registryFixture) ask(in RegistryQueryInput) *RegistryRun {
	r.t.Helper()
	in.DeviceID = r.pc
	run, err := r.svc.CreateRegistryQuery(r.ctx, r.tech, in)
	if err != nil {
		r.t.Fatal(err)
	}
	return run
}

// line makes one result line.
func line(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// result is the lines of a finished list of HKLM\SOFTWARE, as the agent
// writes them, with one value named by the caller.
func listLines(path []string, extra ...string) []string {
	out := []string{
		line(agentproto.RegBegin{T: "begin", V: 1, Op: "list", Hive: "HKLM", View: "64", Path: path, Rules: 1, AgentVersion: "1.5.0", Arch: "x64"}),
		line(agentproto.RegKey{T: "key", Kernel: `\REGISTRY\MACHINE\SOFTWARE`, Subkeys: 1, Values: 1, ReadAt: "2026-11-26T10:00:00Z"}),
		line(agentproto.RegSubkey{T: "subkey", Name: "Vendor", Subkeys: 2, Values: 0}),
	}
	out = append(out, extra...)
	return append(out, line(agentproto.RegEnd{T: "end", Complete: true, ElapsedMS: 12}))
}

// answer runs the run as the agent would: delivered by a poll, started, and
// reported with the lines.
func (r *registryFixture) answer(run uuid.UUID, status string, lines []string, extra func(*agentproto.ResultRequest)) {
	r.t.Helper()
	if _, err := r.svc.Start(r.ctx, r.pc, run); err != nil {
		r.t.Fatal(err)
	}
	code := 0
	req := agentproto.ResultRequest{Status: status, ExitCode: &code, StartedAt: time.Now(), FinishedAt: time.Now(), AgentVersion: "1.5.0"}
	if status != agentproto.RunSucceeded {
		req.ExitCode = nil
	}
	if lines != nil {
		req.Result = base64.StdEncoding.EncodeToString([]byte(strings.Join(lines, "\n") + "\n"))
	}
	if extra != nil {
		extra(&req)
	}
	if err := r.svc.Result(r.ctx, r.pc, run, req); err != nil {
		r.t.Fatal(err)
	}
}

func (r *registryFixture) deliver() []agentproto.JobPayload {
	r.t.Helper()
	resp, err := r.svc.Poll(r.ctx, r.pc, registryAccepts)
	if err != nil {
		r.t.Fatal(err)
	}
	var out []agentproto.JobPayload
	for _, j := range resp.Jobs {
		p, err := agentproto.VerifyJob(r.key, j, r.pc.String(), time.Now())
		if err != nil {
			r.t.Fatalf("a delivered job does not verify: %v", err)
		}
		out = append(out, p)
	}
	return out
}

func forbidden(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("want forbidden, got %v", err)
	}
}

// TestRegistryQueryIsCheckedAndRecorded: who may ask, of which devices, the
// refusals, the record of a read (a search term's length and never the
// term), and what is kept.
func TestRegistryQueryIsCheckedAndRecorded(t *testing.T) {
	r := newRegistryFixture(t)
	const marker = "TermMarker-9f3a"

	run := r.ask(RegistryQueryInput{Op: "search", Text: `HKLM\SOFTWARE`, Term: marker})
	if run.Hive != "HKLM" || strings.Join(run.Path, `\`) != "SOFTWARE" || run.View != "64" {
		t.Fatalf("the key as read: %+v", run)
	}
	if k := r.str(`SELECT kind||' '||executor||' '||builtin||' '||lane||' '||hidden||' '||array_to_string(requires, ',') FROM jobs WHERE id = $1`, run.JobID); k !=
		"registry_query builtin registry quick true job.structured,builtin.registry.v1" {
		t.Errorf("the job: %s", k)
	}
	if n := r.str(`SELECT body||shell||script_name FROM jobs WHERE id = $1`, run.JobID); n != "Registry read" {
		t.Errorf("a builtin job holds no script, but %q", n)
	}
	if n := r.str(`SELECT (signed_bytes > 0 AND signed_bytes < 4096)::text FROM jobs WHERE id = $1`, run.JobID); n != "true" {
		t.Errorf("signed bytes: %s", n)
	}
	// One record, with the term's length.
	if n := r.str(`SELECT count(*)::text FROM audit_log WHERE action = 'registry.read'`); n != "1" {
		t.Fatalf("%s registry.read records, want 1", n)
	}
	if d := r.str(`SELECT details::text FROM audit_log WHERE action = 'registry.read'`); strings.Contains(d, marker) || !strings.Contains(d, `"termLength": 15`) || !strings.Contains(d, `"operation": "search"`) {
		t.Errorf("the record: %s", d)
	}
	if n := r.str(`SELECT count(*)::text FROM audit_log WHERE action = 'device.script_run'`); n != "0" {
		t.Errorf("a registry read is not a script run: %s records", n)
	}
	// Nothing in the audit log holds the term.
	if n := r.str(`SELECT count(*)::text FROM audit_log WHERE details::text LIKE '%' || $1 || '%'`, marker); n != "0" {
		t.Errorf("the term is in %s records", n)
	}

	// Who may ask.
	_, err := r.svc.CreateRegistryQuery(r.ctx, r.reader, RegistryQueryInput{DeviceID: r.pc, Op: "list", Hive: "HKLM", Path: []string{"SOFTWARE"}})
	fieldErr(t, err, "deviceIds", "You cannot read the registry on PC-12")
	// Devices: a Linux one, and an agent that does not list the editor.
	tux := r.device(r.hq, "TUX", "linux")
	_, err = r.svc.CreateRegistryQuery(r.ctx, r.tech, RegistryQueryInput{DeviceID: tux, Op: "list", Hive: "HKLM"})
	fieldErr(t, err, "deviceIds", "The registry editor runs on Windows")
	old := r.device(r.hq, "PC-OLD", "windows")
	if _, err := r.svc.Poll(r.ctx, old, []string{agentproto.CapJobPwsh, agentproto.CapJobParams}); err != nil {
		t.Fatal(err)
	}
	_, err = r.svc.CreateRegistryQuery(r.ctx, r.tech, RegistryQueryInput{DeviceID: old, Op: "list", Hive: "HKLM"})
	fieldErr(t, err, "deviceIds", "PC-OLD's agent cannot open the registry editor; update the agent.")
	// An older agent still takes the jobs it took before.
	sc, _ := r.svc.CreateScript(r.ctx, r.sys, ScriptInput{Name: "Old", Shell: "powershell", Body: "Get-Date"})
	if _, err := r.svc.CreateJob(r.ctx, r.sys, JobInput{ScriptID: sc.ID, DeviceIDs: []uuid.UUID{old}}); err != nil {
		t.Errorf("a script for an older agent: %v", err)
	}

	// The input is checked as the agent will check it.
	for name, in := range map[string]RegistryQueryInput{
		"an empty name":     {Op: "list", Hive: "HKLM", Path: []string{"a", ""}},
		"a dot":             {Op: "list", Hive: "HKLM", Path: []string{".."}},
		"a bad operation":   {Op: "delete", Hive: "HKLM"},
		"a search term":     {Op: "search", Hive: "HKLM", Term: ""},
		"a term in a list":  {Op: "list", Hive: "HKLM", Term: "x"},
		"HKEY_CURRENT_USER": {Op: "list", Text: `HKCU\Software`},
		"a bad hive":        {Op: "list", Hive: "HKXX"},
		"a long name":       {Op: "list", Hive: "HKLM", Path: []string{strings.Repeat("x", 256)}},
	} {
		in.DeviceID = r.pc
		if _, err := r.svc.CreateRegistryQuery(r.ctx, r.tech, in); !isInvalid(err) {
			t.Errorf("%s: %v", name, err)
		}
	}

	// Refused paths, in several spellings, are refused and recorded within
	// the bound: once per caller, action and device in 10 minutes.
	for _, text := range []string{`HKLM\SAM`, `HKEY_LOCAL_MACHINE\security\SAM`, `\Registry\Machine\SOFTWARE\WOW6432Node\EasyRMM`, `Computer\HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EasyRMMAgent`} {
		_, err := r.svc.CreateRegistryQuery(r.ctx, r.tech, RegistryQueryInput{DeviceID: r.pc, Op: "list", Text: text})
		fieldErr(t, err, "path", "Refused by EasyRMM")
	}
	if n := r.str(`SELECT count(*)::text FROM audit_log WHERE action = 'registry.refused' AND outcome = 'denied'`); n != "1" {
		t.Errorf("%s registry.refused records for one caller and device, want 1", n)
	}

	// Two reads open at once; a third waits.
	r.ask(RegistryQueryInput{Op: "list", Hive: "HKLM"})
	_, err = r.svc.CreateRegistryQuery(r.ctx, r.tech, RegistryQueryInput{DeviceID: r.pc, Op: "list", Hive: "HKLM"})
	if e, ok := apperr.As(err); !ok || e.Code != "reads_open" {
		t.Errorf("a third open read: %v", err)
	}
	// Another person has reads of their own.
	if _, err := r.svc.CreateRegistryQuery(r.ctx, r.other, RegistryQueryInput{DeviceID: r.pc, Op: "list", Hive: "HKLM"}); err != nil {
		t.Errorf("another technician: %v", err)
	}

	// A device that stopped answering: the read expires after 2 minutes, with the reason.
	if d := r.str(`SELECT (expires_at - created_at <= interval '2 minutes 1 second')::text FROM job_runs WHERE id = $1`, run.RunID); d != "true" {
		t.Errorf("a read waits at most 2 minutes: %s", d)
	}
}

func isInvalid(err error) bool {
	e, ok := apperr.As(err)
	return ok && e.Kind == apperr.KindInvalid
}

// TestRegistryResultIsKeptGuardedAndChecked: a delivered query is signed with
// its input, its result is checked against the input, kept as lines the
// server's role cannot read, read only by the person who asked, and emptied
// with its input after an hour.
func TestRegistryResultIsKeptGuardedAndChecked(t *testing.T) {
	r := newRegistryFixture(t)

	// An older agent is sent nothing; the run stays queued with the reason it is held.
	run := r.ask(RegistryQueryInput{Op: "list", Hive: "HKLM", Path: []string{"SOFTWARE"}})
	if resp, _ := r.svc.Poll(r.ctx, r.pc, []string{agentproto.CapJobParams}); len(resp.Jobs) != 0 {
		t.Fatalf("an agent without the editor was sent %d jobs", len(resp.Jobs))
	}
	if st := r.str(`SELECT status FROM job_runs WHERE id = $1`, run.RunID); st != "queued" {
		t.Errorf("status %s", st)
	}
	// A poll that lists it gets the signed job with the input.
	if _, err := r.svc.Poll(r.ctx, r.pc, registryAccepts); err != nil {
		t.Fatal(err)
	}
	got := r.deliver()
	_ = got
	f := r.fixture
	f.exec(`UPDATE job_runs SET status = 'queued', sent_at = NULL WHERE id = $1`, run.RunID)
	got = r.deliver()
	if len(got) != 1 {
		t.Fatalf("%d jobs delivered", len(got))
	}
	p := got[0]
	if p.V != agentproto.JobPayloadVersionStructured || p.Executor != "builtin" || p.Builtin != "registry" || p.Lane != "quick" || p.Shell != "" || p.Script != "" || p.TimeoutSeconds != 60 {
		t.Errorf("payload: %+v", p)
	}
	in, err := agentproto.DecodeRegistryInput(p.Input)
	if err != nil || in.Op != "list" || in.Hive != "HKLM" || strings.Join(in.Path, `\`) != "SOFTWARE" || in.MaxSubkeys != 1000 {
		t.Errorf("input %s: %+v %v", p.Input, in, err)
	}
	if f.str(`SELECT (ran_agent_sha256 IS NULL)::text FROM job_runs WHERE id = $1`, run.RunID) == "" {
		t.Error("the build that was sent the run is kept")
	}

	// The run's result: a masked name from an agent whose rules missed it is dropped.
	secret := line(agentproto.RegValue{T: "value", Name: "DbPassword", Type: 1, Size: 14, Text: ptr("hunter2-marker")})
	plain := line(agentproto.RegValue{T: "value", Name: "Version", Type: 4, Size: 4, Number: ptr32(7)})
	r.answer(run.RunID, agentproto.RunSucceeded, listLines([]string{"SOFTWARE"}, secret, plain), nil)

	// Nobody but the functions reads it: the server's own role is refused.
	for _, sql := range []string{`SELECT result FROM job_runs`, `SELECT input FROM job_inputs`, `SELECT data FROM registry_masked_values`, `SELECT * FROM job_inputs`, `SELECT j FROM job_runs j`} {
		err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
			_, err := tx.Exec(f.ctx, sql)
			return err
		})
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != "42501" {
			t.Errorf("%s: %v, want permission denied", sql, err)
		}
	}
	if n := f.str(`SELECT (result_bytes > 0 AND result_complete AND ran_agent_version = '1.5.0')::text FROM job_runs WHERE id = $1`, run.RunID); n != "true" {
		t.Errorf("sizes and version: %s", n)
	}

	view, err := r.svc.ReadRegistryResult(f.ctx, r.tech, run.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if view.State != "reported" || !view.Complete || len(view.Subkeys) != 1 || len(view.Values) != 2 || view.AgentVersion != "1.5.0" {
		t.Fatalf("view %+v", view)
	}
	var pw *agentproto.RegValue
	for i := range view.Values {
		if view.Values[i].Name == "DbPassword" {
			pw = &view.Values[i]
		}
	}
	if pw == nil || !pw.Masked || pw.Text != nil || pw.Size != 14 {
		t.Errorf("a masked value the agent did not mask: %+v", pw)
	}
	// The data is in no record either.
	if n := f.str(`SELECT count(*)::text FROM audit_log WHERE details::text LIKE '%hunter2%'`); n != "0" {
		t.Errorf("the data is in %s audit records", n)
	}

	// Another technician of the site is refused, recorded as denied; a Read-Only user finds nothing... a
	// reader can see the run (job.view) but not read it.
	_, err = r.svc.ReadRegistryResult(f.ctx, r.other, run.RunID)
	forbidden(t, err)
	if n := f.str(`SELECT count(*)::text FROM audit_log WHERE action = 'job_run.result_view' AND outcome = 'denied'`); n != "1" {
		t.Errorf("%s denied reads recorded", n)
	}
	_, err = r.svc.ReadRegistryResult(f.ctx, r.reader, run.RunID)
	forbidden(t, err)
	// The input follows the same rules, through the arguments endpoint.
	args, err := r.svc.ReadArguments(f.ctx, r.tech, run.JobID)
	if err != nil || !strings.Contains(string(args.Input), `"op"`) {
		t.Errorf("the asker reads the input: %+v %v", args, err)
	}
	_, err = r.svc.ReadArguments(f.ctx, r.other, run.JobID)
	forbidden(t, err)

	// A result for another path is not kept, and fails the run.
	wrong := r.ask(RegistryQueryInput{Op: "list", Hive: "HKLM", Path: []string{"SOFTWARE", "A"}})
	r.deliver()
	r.answer(wrong.RunID, agentproto.RunSucceeded, listLines([]string{"SOFTWARE", "B"}), nil)
	if s := f.str(`SELECT status||' '||(result_stored_at IS NULL)::text FROM job_runs WHERE id = $1`, wrong.RunID); s != "failed true" {
		t.Errorf("a result for another path: %s", s)
	}
	v, err := r.svc.ReadRegistryResult(f.ctx, r.tech, wrong.RunID)
	if err != nil || v.State != "unknown" || !strings.Contains(v.Reason, "did not match") {
		t.Errorf("view of a mismatch: %+v %v", v, err)
	}

	// A result with a NUL escape is not kept.
	bad := r.ask(RegistryQueryInput{Op: "list", Hive: "HKLM", Path: []string{"X"}})
	r.deliver()
	nul := line(agentproto.RegValue{T: "value", Name: "n", Type: 1, Size: 2, Text: ptr("a")})
	nul = strings.Replace(nul, `"a"`, `"a\u0000b"`, 1)
	r.answer(bad.RunID, agentproto.RunSucceeded, listLines([]string{"X"}, nul), nil)
	v, err = r.svc.ReadRegistryResult(f.ctx, r.tech, bad.RunID)
	if err != nil || v.State != "unknown" {
		t.Errorf("a NUL escape: %+v %v", v, err)
	}

	// A result without its end line is partial, and says so.
	part := r.ask(RegistryQueryInput{Op: "list", Hive: "HKLM", Path: []string{"P"}})
	r.deliver()
	ls := listLines([]string{"P"})
	r.answer(part.RunID, agentproto.RunTimedOut, ls[:len(ls)-1], nil)
	v, err = r.svc.ReadRegistryResult(f.ctx, r.tech, part.RunID)
	if err != nil || v.State != "unknown" || v.Complete || len(v.Subkeys) != 1 {
		t.Errorf("a partial result: %+v %v", v, err)
	}

	// A run reported without a result (an older build's journal) is Unknown.
	none := r.ask(RegistryQueryInput{Op: "list", Hive: "HKLM", Path: []string{"N"}})
	r.deliver()
	r.answer(none.RunID, agentproto.RunSucceeded, nil, nil)
	v, err = r.svc.ReadRegistryResult(f.ctx, r.tech, none.RunID)
	if err != nil || v.State != "unknown" || !strings.Contains(v.Reason, "no result") {
		t.Errorf("no result: %+v %v", v, err)
	}

	// A result that holds a refused path fails the run and is recorded.
	ref := r.ask(RegistryQueryInput{Op: "search", Hive: "HKLM", Path: []string{}, Term: "sam"})
	r.deliver()
	begin := line(agentproto.RegBegin{T: "begin", V: 1, Op: "search", Hive: "HKLM", View: "64", Path: []string{}, Rules: 1, AgentVersion: "1.5.0"})
	hit := line(agentproto.RegMatch{T: "match", Kind: "key", Path: []string{"SECURITY", "SAM"}})
	end := line(agentproto.RegEnd{T: "end", Complete: true})
	r.answer(ref.RunID, agentproto.RunSucceeded, []string{begin, hit, end}, nil)
	if s := f.str(`SELECT status||' '||(result_stored_at IS NULL)::text FROM job_runs WHERE id = $1`, ref.RunID); s != "failed true" {
		t.Errorf("a result with a refused path: %s", s)
	}
	if d := f.str(`SELECT actor_type||' '||(details->>'path')||' '||(details->>'askedBy') FROM audit_log WHERE action = 'registry.refused_on_device'`); !strings.HasPrefix(d, `system SECURITY\SAM tech@example.com`) {
		t.Errorf("registry.refused_on_device: %q", d)
	}

	// The purge empties input and result together, an hour after the last run ended, and not before.
	if _, err := r.svc.Purge(f.ctx); err != nil {
		t.Fatal(err)
	}
	if n := f.str(`SELECT (result_stored_at IS NOT NULL)::text FROM job_runs WHERE id = $1`, run.RunID); n != "true" {
		t.Error("a result emptied before its hour")
	}
	f.exec(`UPDATE job_runs SET finished_at = now() - interval '61 minutes', started_at = now() - interval '62 minutes' WHERE job_id = $1`, run.JobID)
	if _, err := r.svc.Purge(f.ctx); err != nil {
		t.Fatal(err)
	}
	if n := f.str(`SELECT (result_stored_at IS NULL AND result_removed_at IS NOT NULL)::text FROM job_runs WHERE id = $1`, run.RunID); n != "true" {
		t.Error("the result was not emptied after an hour")
	}
	if n := f.str(`SELECT (removed_at IS NOT NULL)::text FROM job_inputs WHERE job_id = $1`, run.JobID); n != "true" {
		t.Error("the input was not emptied with its result")
	}
	_, err = r.svc.ReadRegistryResult(f.ctx, r.tech, run.RunID)
	if e, ok := apperr.As(err); !ok || e.Code != "result_removed" {
		t.Errorf("a removed result: %v", err)
	}
	_, err = r.svc.ReadArguments(f.ctx, r.tech, run.JobID)
	if e, ok := apperr.As(err); !ok || e.Code != "result_removed" {
		t.Errorf("a removed input: %v", err)
	}
	// Reads are kept a week as jobs.
	f.asOwner(`UPDATE jobs SET created_at = now() - interval '8 days' WHERE id = $1`, run.JobID)
	if _, err := r.svc.Purge(f.ctx); err != nil {
		t.Fatal(err)
	}
	if n := f.str(`SELECT count(*)::text FROM jobs WHERE id = $1`, run.JobID); n != "0" {
		t.Error("a read is kept more than 7 days")
	}
}

// TestRegistryClaimOrderSizeAndLimit: quick runs first, an answer by size and
// count, a run sent again alone, and a run that was delivered 5 times
// without starting fails.
func TestRegistryClaimOrderSizeAndLimit(t *testing.T) {
	r := newRegistryFixture(t)
	f := r.fixture
	// Quick first: a script queued before a read is delivered after it.
	sc, _ := r.svc.CreateScript(f.ctx, r.sys, ScriptInput{Name: "S", Shell: "powershell", Body: "Get-Date"})
	script, err := r.svc.CreateJob(f.ctx, r.tech, JobInput{ScriptID: sc.ID, DeviceIDs: []uuid.UUID{r.pc}})
	if err != nil {
		t.Fatal(err)
	}
	read := r.ask(RegistryQueryInput{Op: "list", Hive: "HKLM"})
	got := r.deliver()
	if len(got) != 2 || got[0].RunID != read.RunID.String() || got[1].RunID != script.Runs[0].ID.String() {
		ids := []string{}
		for _, p := range got {
			ids = append(ids, p.RunID)
		}
		t.Fatalf("delivered %v, want the read first", ids)
	}
	// The script's payload is the one before F2: no new fields.
	if got[1].V != agentproto.JobPayloadVersion || got[1].Executor != "" || len(got[1].Input) != 0 {
		t.Errorf("a script's payload: %+v", got[1])
	}

	// A run being sent again goes in an answer of its own.
	f.exec(`UPDATE job_runs SET sent_at = now() - interval '3 minutes' WHERE id = $1`, read.RunID)
	f.exec(`UPDATE job_runs SET sent_at = now() - interval '3 minutes' WHERE id = $1`, script.Runs[0].ID)
	again := r.ask(RegistryQueryInput{Op: "list", Hive: "HKU"})
	got = r.deliver()
	if len(got) != 1 || got[0].RunID != read.RunID.String() {
		t.Fatalf("the quick run that is sent again goes first and alone: %d jobs", len(got))
	}
	got = r.deliver()
	if len(got) != 1 || got[0].RunID != again.RunID.String() {
		t.Fatalf("a fresh run does not go with one sent again: %d jobs", len(got))
	}
	got = r.deliver()
	if len(got) != 1 || got[0].RunID != script.Runs[0].ID.String() {
		t.Fatalf("the script, sent again, goes alone: %d jobs", len(got))
	}

	// A run delivered 5 times without starting fails.
	f.exec(`UPDATE job_runs SET deliveries = 5, sent_at = now() - interval '3 minutes', status = 'sent' WHERE id = $1`, read.RunID)
	f.exec(`UPDATE job_runs SET status = 'succeeded', finished_at = now() WHERE id = $1`, script.Runs[0].ID)
	r.deliver()
	if s := f.str(`SELECT status||': '||error FROM job_runs WHERE id = $1`, read.RunID); s != "failed: The agent did not take it after 5 deliveries." {
		t.Errorf("the 6th delivery: %s", s)
	}

	// An answer holds at most 6 MiB of signed jobs, and at least one run.
	f.exec(`UPDATE job_runs SET status = 'succeeded', finished_at = now() WHERE device_id = $1 AND status NOT IN ('succeeded', 'failed')`, r.pc)
	var big []uuid.UUID
	for i := range 4 {
		who := f.user("big"+strings.Repeat("x", i)+"@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq})
		run, err := r.svc.CreateRegistryQuery(f.ctx, who, RegistryQueryInput{DeviceID: r.pc, Op: "list", Hive: "HKLM", Path: []string{"A" + strings.Repeat("b", i)}})
		if err != nil {
			t.Fatal(err)
		}
		big = append(big, run.RunID)
	}
	f.asOwner(`UPDATE jobs SET signed_bytes = 2000000 WHERE id IN (SELECT job_id FROM job_runs WHERE id = ANY($1))`, big)
	got = r.deliver()
	if len(got) != 3 {
		t.Errorf("2 MB signed jobs: %d delivered in one answer, want 3 (under 6 MiB)", len(got))
	}
	if got = r.deliver(); len(got) != 1 {
		t.Errorf("the rest follow: %d", len(got))
	}
	// A run larger than an answer still goes, alone: an answer is never empty while a run is due.
	huge := f.user("huge@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq})
	hr, err := r.svc.CreateRegistryQuery(f.ctx, huge, RegistryQueryInput{DeviceID: r.pc, Op: "list", Hive: "HKU"})
	if err != nil {
		t.Fatal(err)
	}
	f.asOwner(`UPDATE jobs SET signed_bytes = 2097152 WHERE id = (SELECT job_id FROM job_runs WHERE id = $1)`, hr.RunID)
	if got = r.deliver(); len(got) != 1 {
		t.Error("an answer is never empty while a run is due")
	}
}

// TestRegistryOverTheChannelClaim: the claim the agent channel pushes is
// the poll's claim, with the same checks.
func TestRegistryOverTheChannelClaim(t *testing.T) {
	r := newRegistryFixture(t)
	run := r.ask(RegistryQueryInput{Op: "list", Hive: "HKLM"})
	resp, err := r.svc.ClaimFor(r.ctx, r.pc, 8<<20)
	if err != nil || len(resp.Jobs) != 1 {
		t.Fatalf("channel claim: %+v %v", resp, err)
	}
	p, err := agentproto.VerifyJob(r.key, resp.Jobs[0], r.pc.String(), time.Now())
	if err != nil || p.RunID != run.RunID.String() || p.Builtin != "registry" {
		t.Errorf("%+v %v", p, err)
	}
	// An agent that stops listing the editor is not pushed one.
	other := r.device(r.hq, "PC-13", "windows")
	if _, err := r.svc.Poll(r.ctx, other, registryAccepts); err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.CreateRegistryQuery(r.ctx, r.tech, RegistryQueryInput{DeviceID: other, Op: "list", Hive: "HKLM"}); err != nil {
		t.Fatal(err)
	}
	r.exec(`UPDATE devices SET agent_accepts = '{job.params}' WHERE id = $1`, other)
	resp, err = r.svc.ClaimFor(r.ctx, other, 8<<20)
	if err != nil || len(resp.Jobs) != 0 {
		t.Errorf("a claim for an agent without the editor: %+v %v", resp, err)
	}
}

// TestRegistryExport: an export read becomes a .reg or JSON file for the
// person who asked, and is recorded.
func TestRegistryExport(t *testing.T) {
	r := newRegistryFixture(t)
	run := r.ask(RegistryQueryInput{Op: "export", Hive: "HKLM", Path: []string{"SOFTWARE", "Vendor"}})
	r.deliver()
	begin := line(agentproto.RegBegin{T: "begin", V: 1, Op: "export", Hive: "HKLM", View: "64", Path: []string{"SOFTWARE", "Vendor"}, Rules: 1, AgentVersion: "1.5.0"})
	u16 := func(s string) string {
		var b []byte
		for _, c := range utf16.Encode([]rune(s + "\x00")) {
			b = append(b, byte(c), byte(c>>8))
		}
		return base64.StdEncoding.EncodeToString(b)
	}
	k1 := line(agentproto.RegXKey{T: "xkey", Path: []string{"SOFTWARE", "Vendor"}, Values: []agentproto.RegValue{
		{T: "value", Name: "", Type: 1, Size: 6, Text: ptr("dflt")},
		{T: "value", Name: `Path "x"`, Type: 1, Size: 12, Text: ptr(`C:\Program Files`), Raw: u16(`C:\Program Files`)},
		{T: "value", Name: "Count", Type: 4, Size: 4, Number: ptr32(255)},
		{T: "value", Name: "Secret", Type: 1, Size: 8, Masked: true},
		{T: "value", Name: "Blob", Type: 3, Size: 3, Base64: base64.StdEncoding.EncodeToString([]byte{1, 2, 0xff}), Raw: base64.StdEncoding.EncodeToString([]byte{1, 2, 0xff})},
	}})
	k2 := line(agentproto.RegXKey{T: "xkey", Path: []string{"SOFTWARE", "Vendor", "Hidden"}, State: "refused", Rule: "x"})
	k3 := line(agentproto.RegXKey{T: "xkey", Path: []string{"SOFTWARE", "Vendor", "Lnk"}, State: "link", Target: `\Registry\Machine\SAM`})
	end := line(agentproto.RegEnd{T: "end", Complete: true})
	r.answer(run.RunID, agentproto.RunSucceeded, []string{begin, k1, k2, k3, end}, nil)

	f, err := r.svc.ExportRegistry(r.ctx, r.tech, run.RunID, ExportReg)
	if err != nil {
		t.Fatal(err)
	}
	if f.Data[0] != 0xFF || f.Data[1] != 0xFE {
		t.Fatal("a .reg file is UTF-16LE with a byte order mark")
	}
	var u []uint16
	for i := 2; i+1 < len(f.Data); i += 2 {
		u = append(u, uint16(f.Data[i])|uint16(f.Data[i+1])<<8)
	}
	text := string(utf16.Decode(u))
	for _, want := range []string{"Windows Registry Editor Version 5.00\r\n", "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Vendor]\r\n", `"Path \"x\""="C:\\Program Files"`,
		`"Count"=dword:000000ff`, "; value left out, masked: Secret", `"Blob"=hex:01,02,ff`, "; key refused by EasyRMM and not exported", `-> \Registry\Machine\SAM`} {
		if !strings.Contains(text, want) {
			t.Errorf("the .reg file lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "SymbolicLinkValue") || strings.Contains(strings.ToLower(text), "hex(6)") {
		t.Error("a link is never written")
	}
	js, err := r.svc.ExportRegistry(r.ctx, r.tech, run.RunID, ExportJSON)
	if err != nil || !strings.Contains(string(js.Data), `"device": "PC-12"`) || strings.Contains(string(js.Data), "hunter") {
		t.Errorf("json: %v %s", err, js.Data)
	}
	if n := r.str(`SELECT count(*)::text FROM audit_log WHERE action = 'registry.export'`); n != "2" {
		t.Errorf("%s registry.export records", n)
	}
	if d := r.str(`SELECT details->>'format'||' '||(details->>'keys')||' '||(details->>'values') FROM audit_log WHERE action = 'registry.export' ORDER BY occurred_at LIMIT 1`); d != "reg 1 4" {
		t.Errorf("the record: %s", d)
	}
	// Only the person who asked.
	_, err = r.svc.ExportRegistry(r.ctx, r.other, run.RunID, ExportReg)
	forbidden(t, err)
	if _, err := r.svc.ExportRegistry(r.ctx, r.tech, run.RunID, "xml"); err == nil {
		t.Error("an unknown format")
	}
}

func ptr32(n uint32) *uint32 { return &n }
