//go:build integration

package recovery

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/jobkeys"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

type fixture struct {
	t         *testing.T
	ctx       context.Context
	db        *database.DB
	svc       *Service
	pub       ed25519.PublicKey
	start     time.Time
	connected bool
	acme, hq  uuid.UUID
	globex    uuid.UUID
	super     access.Caller
	tech      access.Caller
	reader    access.Caller
	stranger  access.Caller
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	inst := testdb.New(t)
	f := &fixture{t: t, ctx: context.Background(), db: inst.DB, start: time.Now(), connected: true}
	f.svc = New(inst.DB, audit.New(inst.DB, nil), true, slog.New(slog.NewTextHandler(io.Discard, nil)))
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	f.pub = pub
	f.svc.SetKey(jobkeys.Static(priv))
	f.svc.FollowMesh(func() (bool, time.Time) { return f.connected, f.start.Add(-time.Hour) })
	f.svc.now = func() time.Time { return f.start }
	f.acme = f.id(`INSERT INTO organizations (name) VALUES ('Acme') RETURNING id`)
	f.hq = f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'HQ') RETURNING id`, f.acme)
	f.globex = f.id(`INSERT INTO organizations (name) VALUES ('Globex') RETURNING id`)
	f.super = f.user("super@example.com", rbac.Assignment{Role: rbac.RoleSuperAdmin})
	f.tech = f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme})
	f.reader = f.user("reader@example.com", rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: f.acme})
	f.stranger = f.user("stranger@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.globex})
	return f
}

func (f *fixture) id(sql string, args ...any) uuid.UUID {
	f.t.Helper()
	var id uuid.UUID
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error { return tx.QueryRow(f.ctx, sql, args...).Scan(&id) }); err != nil {
		f.t.Fatal(err)
	}
	return id
}

func (f *fixture) exec(sql string, args ...any) {
	f.t.Helper()
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error { _, err := tx.Exec(f.ctx, sql, args...); return err }); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) count(sql string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error { return tx.QueryRow(f.ctx, sql, args...).Scan(&n) }); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func (f *fixture) user(email string, as ...rbac.Assignment) access.Caller {
	f.t.Helper()
	id := f.id(`INSERT INTO users (email, display_name) VALUES ($1, $1) RETURNING id`, email)
	p, err := rbac.NewPrincipal(id, as)
	if err != nil {
		f.t.Fatal(err)
	}
	return access.User(p, auth.DataScope(p), audit.Actor{Type: audit.ActorUser, ID: id, Label: email})
}

// device enrolls a device whose agent checked in just now, MeshAgent not
// connected for ten minutes.
func (f *fixture) device(name string) uuid.UUID {
	f.t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return f.id(`INSERT INTO devices (organization_id, site_id, name, hostname, platform, agent_public_key, enrolled_at, agent_last_seen_at)
		VALUES ($1, $2, $3, $3, 'linux', $4, now() - interval '1 day', now()) RETURNING id`, f.acme, f.hq, name, key)
}

func (f *fixture) connect(device uuid.UUID, online bool, at time.Time) {
	f.t.Helper()
	f.exec(`UPDATE devices SET remote_online = $2 WHERE id = $1`, device, online)
	f.exec(`UPDATE devices SET remote_changed_at = $2 WHERE id = $1`, device, at)
}

func (f *fixture) request(c access.Caller, device uuid.UUID) (*Repair, error) {
	return f.svc.Request(f.ctx, c, device, agentproto.TargetMeshAgent)
}

func (f *fixture) must(c access.Caller, device uuid.UUID) *Repair {
	f.t.Helper()
	r, err := f.request(c, device)
	if err != nil {
		f.t.Fatal(err)
	}
	return r
}

// beat is a heartbeat of the device's agent: it reports rep and returns the
// instruction it gets, verified.
func (f *fixture) beat(device uuid.UUID, rep *agentproto.RepairReport) *agentproto.RepairPayload {
	f.t.Helper()
	sr := f.svc.AgentHeartbeat(f.ctx, device, rep)
	if sr == nil {
		return nil
	}
	p, err := agentproto.VerifyRepair(f.pub, *sr, device.String(), f.start)
	if err != nil {
		f.t.Fatalf("the instruction does not verify: %v", err)
	}
	return &p
}

func (f *fixture) advance(d time.Duration) {
	f.t.Helper()
	f.svc.now = func() time.Time { return f.start.Add(d) }
	if err := f.svc.Advance(f.ctx); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) latest(device uuid.UUID) *Repair {
	f.t.Helper()
	list, err := f.svc.List(f.ctx, f.super, device)
	if err != nil || len(list) == 0 {
		f.t.Fatalf("list: %v %v", list, err)
	}
	return list[0]
}

func code(err error) string {
	if e, ok := apperr.As(err); ok {
		return e.Code
	}
	return ""
}

func TestRequestNeedsPermissionAndAnEnrolledOnlineDevice(t *testing.T) {
	f := newFixture(t)
	d := f.device("pc")
	if _, err := f.request(f.reader, d); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("read-only user: %v", err)
	}
	if _, err := f.request(f.stranger, d); !errors.Is(err, apperr.ErrNotFound) {
		t.Errorf("another organization's administrator: %v", err)
	}
	if _, err := f.svc.Request(f.ctx, f.tech, d, "easyrmm-agent"); code(err) == "" {
		t.Errorf("a target nothing repairs: %v", err)
	}
	if f.count(`SELECT count(*) FROM agent_repairs`) != 0 {
		t.Fatal("a refused request left a repair")
	}

	r, err := f.request(f.tech, d)
	if err != nil {
		t.Fatal(err)
	}
	if r.Target != "meshagent" || r.CarriedBy != "easyrmm-agent" || r.Trigger != TriggerManual || r.State != Running || len(r.Steps) != 2 ||
		r.Steps[0].Step != "restart" || r.Steps[1].Step != "repair" || r.Steps[0].State != StepPending {
		t.Errorf("repair = %+v", r)
	}
	if f.count(`SELECT count(*) FROM audit_log WHERE action = 'device.repair_request' AND device_id = $1`, d) != 1 {
		t.Error("the request was not audited")
	}
	// One at a time.
	if _, err := f.request(f.tech, d); code(err) != "repair_running" {
		t.Errorf("second request: %v", err)
	}

	// No agent to carry it out, or not checking in.
	discovered := f.id(`INSERT INTO devices (organization_id, site_id, name, hostname, platform) VALUES ($1, $2, 'found', 'found', 'linux') RETURNING id`, f.acme, f.hq)
	if _, err := f.request(f.tech, discovered); code(err) != "no_agent" {
		t.Errorf("device without an agent: %v", err)
	}
	asleep := f.device("asleep")
	f.exec(`UPDATE devices SET agent_last_seen_at = now() - interval '1 hour' WHERE id = $1`, asleep)
	if _, err := f.request(f.tech, asleep); code(err) != "device_offline" {
		t.Errorf("offline device: %v", err)
	}
}

func TestRequestRefusedWithoutRemoteAccessOrAKey(t *testing.T) {
	f := newFixture(t)
	d := f.device("pc")
	f.svc.remote = false
	if _, err := f.request(f.tech, d); code(err) != "no_remote_access" {
		t.Errorf("without remote access: %v", err)
	}
	f.svc.remote, f.svc.key = true, nil
	if _, err := f.request(f.tech, d); code(err) != "no_job_key" {
		t.Errorf("without a key: %v", err)
	}
	if f.svc.AgentHeartbeat(f.ctx, d, nil) != nil {
		t.Error("an instruction without a key")
	}
}

func TestRequestRefusedForADeviceThatIsLeaving(t *testing.T) {
	for name, leave := range map[string]string{
		"removal":   `INSERT INTO device_removals (device_id, id) VALUES ($1, gen_random_uuid())`,
		"opted out": `INSERT INTO easypatch_opt_outs (device_id) VALUES ($1)`,
		"easypatch": `INSERT INTO easypatch_removals (endpoint_id, device_id, reason) VALUES (gen_random_uuid(), $1, 'deleted')`,
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			d := f.device("pc")
			f.exec(leave, d)
			if _, err := f.request(f.tech, d); code(err) != "device_leaving" {
				t.Errorf("%v", err)
			}
		})
	}
}

// The whole way: restart, wait, repair, wait, connected.
func TestARepairEscalatesFromRestartToRepairAndSucceeds(t *testing.T) {
	f := newFixture(t)
	d := f.device("pc")
	f.connect(d, false, f.start.Add(-10*time.Minute))
	r := f.must(f.tech, d)

	// The instruction repeats until the agent reports it.
	p := f.beat(d, nil)
	if p == nil || p.Target != "meshagent" || p.Step != "restart" || p.ID != r.Steps[0].ID {
		t.Fatalf("instruction = %+v", p)
	}
	if again := f.beat(d, nil); again == nil || again.ID != p.ID {
		t.Fatalf("repeated instruction = %+v", again)
	}
	if got := f.latest(d); got.Steps[0].State != StepSent || got.Steps[0].SentAt == nil {
		t.Errorf("step = %+v", got.Steps[0])
	}

	// A report for another step changes nothing.
	f.beat(d, &agentproto.RepairReport{ID: "other", OK: true})
	if got := f.latest(d); got.Steps[0].State != StepSent {
		t.Errorf("step = %+v", got.Steps[0])
	}

	// Reported done: nothing more is handed out while the target gets its
	// time, and the repair waits.
	if q := f.beat(d, &agentproto.RepairReport{ID: p.ID, OK: true}); q != nil {
		t.Fatalf("instruction right after the step was done: %+v", q)
	}
	if got := f.latest(d); got.Steps[0].State != StepDone || got.State != Running {
		t.Fatalf("repair = %+v", got)
	}
	f.advance(ManualWait - time.Second)
	if got := f.latest(d); got.State != Running || got.Steps[1].State != StepPending {
		t.Fatalf("before the wait is over: %+v", got)
	}
	// Still not connected after the wait: the next step.
	f.advance(ManualWait)
	if f.latest(d).State != Running {
		t.Fatalf("ended: %+v", f.latest(d))
	}
	q := f.beat(d, &agentproto.RepairReport{ID: p.ID, OK: true}) // repeated, settled already
	if q == nil || q.Step != "repair" || q.ID != r.Steps[1].ID {
		t.Fatalf("second instruction = %+v", q)
	}
	f.beat(d, &agentproto.RepairReport{ID: q.ID, OK: true})
	// MeshCentral sees it connected after the step.
	f.connect(d, true, f.start.Add(ManualWait+30*time.Second))
	f.advance(ManualWait + time.Minute)
	got := f.latest(d)
	if got.State != Succeeded || got.EndedAt == nil || got.Error != "" {
		t.Fatalf("repair = %+v", got)
	}
	if f.count(`SELECT count(*) FROM audit_log WHERE action = 'device.repair_end' AND outcome = 'success'`) != 1 {
		t.Error("the end was not audited")
	}
	// Over: nothing more to hand out, and a new one may start.
	if f.beat(d, nil) != nil {
		t.Error("an instruction after the end")
	}
	f.must(f.tech, d)
}

func TestARepairEndsAtOnceWhenTheTargetComesBack(t *testing.T) {
	f := newFixture(t)
	d := f.device("pc")
	f.connect(d, false, f.start.Add(-time.Hour))
	f.must(f.tech, d)
	p := f.beat(d, nil)
	f.beat(d, &agentproto.RepairReport{ID: p.ID, OK: true})
	f.connect(d, true, f.start.Add(10*time.Second))
	f.advance(15 * time.Second)
	if got := f.latest(d); got.State != Succeeded || got.Steps[1].State != StepPending {
		t.Fatalf("repair = %+v", got)
	}
}

func TestAFailedStepGoesStraightToTheNextAndTheLastFailureEndsTheRepair(t *testing.T) {
	f := newFixture(t)
	d := f.device("pc")
	f.connect(d, false, f.start.Add(-time.Hour))
	f.must(f.tech, d)
	p := f.beat(d, nil)
	q := f.beat(d, &agentproto.RepairReport{ID: p.ID, OK: false, Error: "the unit does not exist"})
	if q == nil || q.Step != "repair" {
		t.Fatalf("after a failed restart: %+v", q)
	}
	if got := f.latest(d); got.Steps[0].State != StepFailed || got.Steps[0].Error != "the unit does not exist" || got.State != Running {
		t.Fatalf("repair = %+v", got)
	}
	if r := f.beat(d, &agentproto.RepairReport{ID: q.ID, OK: false, Error: "download failed"}); r != nil {
		t.Fatalf("after the last step failed: %+v", r)
	}
	got := f.latest(d)
	if got.State != Failed || got.Error != "The last step failed: download failed" || got.EndedAt == nil {
		t.Fatalf("repair = %+v", got)
	}
	if f.count(`SELECT count(*) FROM audit_log WHERE action = 'device.repair_end' AND outcome = 'failure'`) != 1 {
		t.Error("the end was not audited")
	}
}

func TestARepairThatNeverBringsTheTargetBackFails(t *testing.T) {
	f := newFixture(t)
	d := f.device("pc")
	f.connect(d, false, f.start.Add(-time.Hour))
	f.must(f.tech, d)
	for i := range 2 {
		p := f.beat(d, nil)
		if p == nil {
			t.Fatalf("no instruction for step %d", i)
		}
		f.beat(d, &agentproto.RepairReport{ID: p.ID, OK: true})
		f.advance(time.Duration(i+1) * (ManualWait + time.Second))
	}
	got := f.latest(d)
	if got.State != Failed || got.Error != "MeshAgent did not connect to MeshCentral after the last step." {
		t.Fatalf("repair = %+v", got)
	}
}

func TestAStepThatNeverReachesTheAgentFailsTheRepair(t *testing.T) {
	f := newFixture(t)
	d := f.device("pc")
	f.must(f.tech, d)
	f.advance(StepValid - time.Second)
	if f.latest(d).State != Running {
		t.Fatal("ended early")
	}
	f.advance(StepValid)
	got := f.latest(d)
	if got.State != Failed || got.Steps[0].State != StepFailed {
		t.Fatalf("repair = %+v", got)
	}
}

func TestNothingIsJudgedWhileMeshCentralCannotBeSeen(t *testing.T) {
	f := newFixture(t)
	d := f.device("pc")
	f.connect(d, false, f.start.Add(-time.Hour))
	f.must(f.tech, d)
	p := f.beat(d, nil)
	f.beat(d, &agentproto.RepairReport{ID: p.ID, OK: true})
	f.connected = false
	f.advance(10 * time.Minute)
	if got := f.latest(d); got.State != Running || f.beat(d, nil) != nil {
		t.Fatalf("while MeshCentral cannot be seen: %+v", got)
	}
	f.connected = true
	f.advance(10 * time.Minute)
	if q := f.beat(d, nil); q == nil || q.Step != "repair" {
		t.Fatalf("after MeshCentral is back: %+v", q)
	}
}

func TestADeviceThatStartsToLeaveEndsItsRepair(t *testing.T) {
	f := newFixture(t)
	d := f.device("pc")
	f.must(f.tech, d)
	f.exec(`INSERT INTO device_removals (device_id, id) VALUES ($1, gen_random_uuid())`, d)
	if f.beat(d, nil) != nil {
		t.Error("an instruction for a device that is leaving")
	}
	f.advance(time.Second)
	if got := f.latest(d); got.State != Failed || got.Error != "The device is being removed." {
		t.Fatalf("repair = %+v", got)
	}
}

func TestARepairIsKeptShortAndOldOnesGo(t *testing.T) {
	f := newFixture(t)
	d := f.device("pc")
	f.connect(d, false, f.start.Add(-time.Hour))
	f.must(f.tech, d)
	f.advance(MaxRunning)
	if got := f.latest(d); got.State != Failed {
		t.Fatalf("repair = %+v", got)
	}
	f.svc.now = func() time.Time { return f.start.Add(MaxRunning + Keep + time.Hour) }
	if err := f.svc.purge(f.ctx); err != nil {
		t.Fatal(err)
	}
	if f.count(`SELECT count(*) FROM agent_repairs`) != 0 {
		t.Error("an old repair was kept")
	}
}

func TestListIsForDevicesTheCallerSees(t *testing.T) {
	f := newFixture(t)
	d := f.device("pc")
	f.must(f.tech, d)
	if list, err := f.svc.List(f.ctx, f.reader, d); err != nil || len(list) != 1 {
		t.Errorf("read-only user: %v %v", list, err)
	}
	if _, err := f.svc.List(f.ctx, f.stranger, d); !errors.Is(err, apperr.ErrNotFound) {
		t.Errorf("another organization: %v", err)
	}
}

func TestRunAdvancesRepairsAndStopsWithItsContext(t *testing.T) {
	f := newFixture(t)
	d := f.device("pc")
	f.must(f.tech, d)
	// The loop is woken by a request and looks at the repair at once; this
	// one is past the time the carrying agent has to take its step.
	f.svc.now = func() time.Time { return f.start.Add(StepValid) }
	ctx, cancel := context.WithCancel(f.ctx)
	done := make(chan struct{})
	go func() { f.svc.Run(ctx); close(done) }()
	deadline := time.Now().Add(20 * time.Second)
	for f.latest(d).State != Failed {
		if time.Now().After(deadline) {
			t.Fatal("the loop did not end the repair")
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not stop")
	}
}

func TestADamagedRecordEndsItsRepairAndLongErrorsAreCut(t *testing.T) {
	f := newFixture(t)
	d := f.device("pc")
	f.must(f.tech, d)
	f.exec(`UPDATE agent_repairs SET step = 9 WHERE device_id = $1`, d)
	f.advance(time.Second)
	if got := f.latest(d); got.State != Failed || got.Error != "The repair's record is damaged." {
		t.Fatalf("repair = %+v", got)
	}

	f.must(f.tech, d)
	p := f.beat(d, nil)
	long := make([]rune, 2000)
	for i := range long {
		long[i] = 'é'
	}
	f.beat(d, &agentproto.RepairReport{ID: p.ID, OK: false, Error: string(long)})
	if got := f.latest(d); len([]rune(got.Steps[0].Error)) != agentproto.MaxRepairError {
		t.Errorf("step error is %d characters", len([]rune(got.Steps[0].Error)))
	}
}
