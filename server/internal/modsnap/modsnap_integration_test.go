//go:build integration

package modsnap_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"slices"
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
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/jobkeys"
	"github.com/paulmataruso/easyrmm/server/internal/jobs"
	"github.com/paulmataruso/easyrmm/server/internal/modsnap"
	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
	"github.com/paulmataruso/easyrmm/server/internal/winmod"
	"github.com/paulmataruso/easyrmm/server/internal/winmod/defender"
	"github.com/paulmataruso/easyrmm/server/internal/winmod/dhcp"
)

type fx struct {
	t            *testing.T
	ctx          context.Context
	db           *database.DB
	svc          *modsnap.Service
	jobs         *jobs.Service
	acme, hq     uuid.UUID
	globex, main uuid.UUID
	tech, viewer access.Caller
}

func newFx(t *testing.T) *fx {
	t.Helper()
	inst := testdb.New(t)
	f := &fx{t: t, ctx: context.Background(), db: inst.DB}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	au := audit.New(inst.DB, nil)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mods := modules.New(inst.DB, au, log)
	cat, err := winmod.NewCatalog(slices.Concat(defender.Actions(), dhcp.Actions())...)
	if err != nil {
		t.Fatal(err)
	}
	f.jobs = jobs.New(inst.DB, au, jobkeys.Static(key), 30*24*time.Hour, 7*24*time.Hour, log)
	f.jobs.SetWinmod(cat, mods, nil)
	f.svc = modsnap.New(inst.DB, cat, mods, mods, f.jobs, log)
	f.acme = f.id(`INSERT INTO organizations (name) VALUES ('Acme') RETURNING id`)
	f.hq = f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'HQ') RETURNING id`, f.acme)
	f.globex = f.id(`INSERT INTO organizations (name) VALUES ('Globex') RETURNING id`)
	f.main = f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'Main') RETURNING id`, f.globex)
	f.tech = f.user("t@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme})
	// Read-Only holds no module permission: the module is not found for it.
	f.viewer = f.user("ro@example.com", rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: f.acme})
	return f
}

func (f *fx) user(email string, as ...rbac.Assignment) access.Caller {
	f.t.Helper()
	id := f.id(`INSERT INTO users (email, display_name) VALUES ($1, $1) RETURNING id`, email)
	p, err := rbac.NewPrincipal(id, as)
	if err != nil {
		f.t.Fatal(err)
	}
	return access.User(p, auth.DataScope(p), audit.Actor{Type: audit.ActorUser, ID: id, Label: email})
}

func (f *fx) id(sql string, args ...any) uuid.UUID {
	f.t.Helper()
	var id uuid.UUID
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error { return tx.QueryRow(f.ctx, sql, args...).Scan(&id) }); err != nil {
		f.t.Fatal(err)
	}
	return id
}

func (f *fx) exec(sql string, args ...any) {
	f.t.Helper()
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error { _, err := tx.Exec(f.ctx, sql, args...); return err }); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fx) count(sql string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error { return tx.QueryRow(f.ctx, sql, args...).Scan(&n) }); err != nil {
		f.t.Fatal(err)
	}
	return n
}

// device enrolls a Windows device with Defender, last seen agoMinutes ago,
// whose agent takes job params.
func (f *fx) device(org, site uuid.UUID, name string, agoMinutes int) uuid.UUID {
	f.t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	d := f.id(`INSERT INTO devices (organization_id, site_id, name, hostname, platform, agent_public_key, enrolled_at, agent_last_seen_at, roles, roles_at)
		VALUES ($1, $2, $3, $3, 'windows', $4, now() - interval '1 day', now() - make_interval(mins => $5), '[{"name":"defender","state":"present"}]', now())
		RETURNING id`, org, site, name, key, agoMinutes)
	f.exec(`UPDATE devices SET agent_accepts = $2, agent_accepts_build = coalesce(agent_sha256, agent_version) WHERE id = $1`,
		d, []string{agentproto.CapJobPwsh, agentproto.CapJobParams})
	return d
}

func (f *fx) snapshot(dev uuid.UUID, agoMinutes int, sensitive bool) {
	f.exec(`INSERT INTO windows_module_snapshots (device_id, module, action, params_hash, taken_at, sensitive, data)
		VALUES ($1, 'defender', 'defender.status', '', now() - make_interval(mins => $2), $3, '{"runningMode":"Normal"}')
		ON CONFLICT (device_id, action, params_hash) DO UPDATE SET taken_at = excluded.taken_at, sensitive = excluded.sensitive`, dev, agoMinutes, sensitive)
}

func (f *fx) reads(dev uuid.UUID) int {
	return f.count(`SELECT count(*) FROM job_runs r JOIN jobs j ON j.id = r.job_id WHERE r.device_id = $1 AND j.kind = 'winmod'`, dev)
}

func TestSnapshotFreshnessAndRefreshOnDemand(t *testing.T) {
	f := newFx(t)
	dev := f.device(f.acme, f.hq, "dc1", 0)
	const action = "defender.status"

	// Never read: nothing to show, a read is started.
	got, err := f.svc.Get(f.ctx, f.tech, dev, action, nil)
	if err != nil || got.TakenAt != nil || !got.Stale || !got.Refreshing || f.reads(dev) != 1 {
		t.Fatalf("first open: %+v, %v, %d reads", got, err, f.reads(dev))
	}
	// A read on its way is not started twice.
	if got, err = f.svc.Get(f.ctx, f.tech, dev, action, nil); err != nil || !got.Refreshing || f.reads(dev) != 1 {
		t.Fatalf("second open: %+v, %v, %d reads", got, err, f.reads(dev))
	}
	if got, err = f.svc.Refresh(f.ctx, f.tech, dev, action, nil); err != nil || !got.Refreshing || f.reads(dev) != 1 {
		t.Fatalf("refresh while reading: %+v, %v, %d reads", got, err, f.reads(dev))
	}

	// A fresh snapshot is returned at once with no read.
	f.exec(`DELETE FROM jobs`)
	f.snapshot(dev, 1, false)
	got, err = f.svc.Get(f.ctx, f.tech, dev, action, nil)
	if err != nil || got.Stale || got.Refreshing || got.TakenAt == nil || f.reads(dev) != 0 {
		t.Fatalf("fresh: %+v, %v, %d reads", got, err, f.reads(dev))
	}
	var data map[string]string
	if json.Unmarshal(got.Data, &data) != nil || data["runningMode"] != "Normal" {
		t.Errorf("data %s", got.Data)
	}
	// A stale one is returned and refreshed.
	f.snapshot(dev, 10, false)
	got, err = f.svc.Get(f.ctx, f.tech, dev, action, nil)
	if err != nil || !got.Stale || !got.Refreshing || got.TakenAt == nil || f.reads(dev) != 1 {
		t.Fatalf("stale: %+v, %v, %d reads", got, err, f.reads(dev))
	}
	// The button reads even a fresh snapshot, when none is on its way.
	f.exec(`DELETE FROM jobs`)
	f.snapshot(dev, 0, false)
	if got, err = f.svc.Refresh(f.ctx, f.tech, dev, action, nil); err != nil || !got.Refreshing || f.reads(dev) != 1 {
		t.Fatalf("refresh: %+v, %v, %d reads", got, err, f.reads(dev))
	}

	// An offline computer shows its snapshot and gets no job.
	off := f.device(f.acme, f.hq, "dc-off", 60)
	f.snapshot(off, 30, false)
	got, err = f.svc.Get(f.ctx, f.tech, off, action, nil)
	if err != nil || !got.Stale || !got.Offline || got.Refreshing || f.reads(off) != 0 {
		t.Fatalf("offline: %+v, %v, %d reads", got, err, f.reads(off))
	}

	// The 404 rule: no permission, a module that is off, an unknown action,
	// a parameter the action does not take.
	if _, err := f.svc.Get(f.ctx, f.viewer, dev, action, nil); !errors.Is(err, apperr.NotFound()) {
		t.Errorf("without the permission: %v", err)
	}
	if _, err := f.svc.Get(f.ctx, f.tech, dev, "defender.nope", nil); !errors.Is(err, apperr.NotFound()) {
		t.Errorf("unknown action: %v", err)
	}
	if _, err := f.svc.Get(f.ctx, f.tech, dev, action, json.RawMessage(`{"x":1}`)); err == nil {
		t.Error("an undeclared parameter was accepted")
	}
	f.exec(`INSERT INTO windows_module_settings (organization_id, module, enabled) VALUES ($1, 'defender', false)`, f.acme)
	if _, err := f.svc.Get(f.ctx, f.tech, dev, action, nil); !errors.Is(err, apperr.NotFound()) {
		t.Errorf("module off: %v", err)
	}
}

func TestScheduledReads(t *testing.T) {
	f := newFx(t)
	restore := devscope.Set(f.acme)
	t.Cleanup(restore)
	due := f.device(f.acme, f.hq, "due", 0)
	fresh := f.device(f.acme, f.hq, "fresh", 0)
	f.snapshot(fresh, 30, false)
	old := f.device(f.acme, f.hq, "old-snapshot", 0)
	f.snapshot(old, 90, false)
	offline := f.device(f.acme, f.hq, "offline", 30)
	noRole := f.device(f.acme, f.hq, "no-role", 0)
	f.exec(`UPDATE devices SET roles = '[]' WHERE id = $1`, noRole)
	outside := f.device(f.globex, f.main, "outside", 0)

	n, err := f.svc.Sweep(f.ctx)
	if err != nil || n != 2 {
		t.Fatalf("sweep started %d reads, %v", n, err)
	}
	for name, d := range map[string]uuid.UUID{"due": due, "old": old} {
		if f.reads(d) != 1 {
			t.Errorf("%s: %d reads", name, f.reads(d))
		}
	}
	for name, d := range map[string]uuid.UUID{"fresh": fresh, "offline": offline, "no role": noRole, "outside the scope": outside} {
		if f.reads(d) != 0 {
			t.Errorf("%s: %d reads", name, f.reads(d))
		}
	}
	// Nothing is started twice while a read is on its way.
	if n, err := f.svc.Sweep(f.ctx); err != nil || n != 0 {
		t.Errorf("second sweep started %d reads, %v", n, err)
	}

	// A module that is off for the site is not read.
	f.exec(`DELETE FROM jobs`)
	f.exec(`INSERT INTO windows_module_settings (organization_id, site_id, module, enabled) VALUES ($1, $2, 'defender', false)`, f.acme, f.hq)
	if n, err := f.svc.Sweep(f.ctx); err != nil || n != 0 {
		t.Errorf("sweep with the module off started %d reads, %v", n, err)
	}
}

func TestRetention(t *testing.T) {
	f := newFx(t)
	week := f.device(f.acme, f.hq, "week", 0)
	f.snapshot(week, 8*24*60, false)
	recent := f.device(f.acme, f.hq, "recent", 0)
	f.snapshot(recent, 6*24*60, false)
	secretOld := f.device(f.acme, f.hq, "secret-old", 0)
	f.snapshot(secretOld, 20, true)
	secretNew := f.device(f.acme, f.hq, "secret-new", 0)
	f.snapshot(secretNew, 5, true)

	n, err := f.svc.Purge(f.ctx)
	if err != nil || n != 2 {
		t.Fatalf("purged %d, %v", n, err)
	}
	for name, want := range map[string]struct {
		dev  uuid.UUID
		kept int
	}{"week": {week, 0}, "recent": {recent, 1}, "secret-old": {secretOld, 0}, "secret-new": {secretNew, 1}} {
		if got := f.count(`SELECT count(*) FROM windows_module_snapshots WHERE device_id = $1`, want.dev); got != want.kept {
			t.Errorf("%s: %d snapshots kept, want %d", name, got, want.kept)
		}
	}
	// Deleting a device deletes its snapshots.
	f.exec(`DELETE FROM devices WHERE id = $1`, recent)
	if got := f.count(`SELECT count(*) FROM windows_module_snapshots WHERE device_id = $1`, recent); got != 0 {
		t.Errorf("%d snapshots of a deleted device", got)
	}
}

func TestRunSweepsUntilItsContextEnds(t *testing.T) {
	f := newFx(t)
	dev := f.device(f.acme, f.hq, "dc1", 0)
	ctx, cancel := context.WithCancel(f.ctx)
	done := make(chan struct{})
	go func() { f.svc.Run(ctx); close(done) }()
	deadline := time.Now().Add(20 * time.Second)
	for f.reads(dev) == 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	<-done
	if f.reads(dev) != 1 {
		t.Errorf("the first sweep started %d reads", f.reads(dev))
	}
}

// A tab's read is audited as automatic; a read of an action that keeps no snapshot (a sensitive page of leases) starts
// a run each time, one in flight per device, action and parameters; and a result older than two minutes is read again
// although the action's own freshness is five.
func TestAutomaticReadsAreMarkedAndBounded(t *testing.T) {
	f := newFx(t)
	dev := f.device(f.acme, f.hq, "dc1", 0)
	mgr := f.user("m@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.acme})
	f.exec(`UPDATE devices SET roles = '[{"name":"defender","state":"present"},{"name":"dhcp","state":"present"}]' WHERE id = $1`, dev)

	got, err := f.svc.Get(f.ctx, f.tech, dev, "defender.status", nil)
	if err != nil || got.RunID == nil || !got.Refreshing {
		t.Fatalf("first read: %+v, %v", got, err)
	}
	if n := f.count(`SELECT count(*) FROM audit_log WHERE device_id = $1 AND action = 'winmod.defender.status' AND details->>'automatic' = 'true'`, dev); n != 1 {
		t.Errorf("%d audit rows marked automatic", n)
	}
	// The run named is the one in flight, and a second tab gets the same one.
	again, err := f.svc.Get(f.ctx, f.tech, dev, "defender.status", nil)
	if err != nil || again.RunID == nil || *again.RunID != *got.RunID || f.reads(dev) != 1 {
		t.Fatalf("second tab: %+v, %v, %d reads", again, err, f.reads(dev))
	}

	// Two minutes and a bit is stale although the action is fresh for five.
	f.exec(`DELETE FROM jobs`)
	f.snapshot(dev, 3, false)
	if got, err = f.svc.Get(f.ctx, f.tech, dev, "defender.status", nil); err != nil || !got.Stale || !got.Refreshing || got.TakenAt == nil {
		t.Fatalf("three minutes old: %+v, %v", got, err)
	}
	f.exec(`DELETE FROM jobs`)
	f.snapshot(dev, 1, false)
	if got, err = f.svc.Get(f.ctx, f.tech, dev, "defender.status", nil); err != nil || got.Stale || got.RunID != nil {
		t.Fatalf("one minute old: %+v, %v", got, err)
	}
	// A running operation can ask for a younger result.
	f.snapshot(dev, 0, false)
	if got, err = f.svc.GetWithin(f.ctx, f.tech, dev, "defender.status", nil, 30*time.Second); err != nil || got.Stale {
		t.Fatalf("just read, asked within 30 seconds: %+v, %v", got, err)
	}
	f.exec(`UPDATE windows_module_snapshots SET taken_at = now() - interval '45 seconds'`)
	if got, err = f.svc.GetWithin(f.ctx, f.tech, dev, "defender.status", nil, 30*time.Second); err != nil || !got.Stale || !got.Refreshing {
		t.Fatalf("45 seconds old, asked within 30: %+v, %v", got, err)
	}

	// Leases keep no snapshot: every read starts a run, one per scope in flight.
	f.exec(`DELETE FROM jobs`)
	a, err := f.svc.Get(f.ctx, mgr, dev, "dhcp.lease_list", json.RawMessage(`{"scopeId":"192.168.1.0"}`))
	if err != nil || a.RunID == nil || a.Data != nil {
		t.Fatalf("leases: %+v, %v", a, err)
	}
	b, err := f.svc.Get(f.ctx, mgr, dev, "dhcp.lease_list", json.RawMessage(`{"scopeId":"192.168.2.0"}`))
	if err != nil || b.RunID == nil || *b.RunID == *a.RunID {
		t.Fatalf("another scope shares the first one's run: %+v, %v", b, err)
	}
	a2, err := f.svc.Get(f.ctx, mgr, dev, "dhcp.lease_list", json.RawMessage(`{"scopeId":"192.168.1.0"}`))
	if err != nil || a2.RunID == nil || *a2.RunID != *a.RunID {
		t.Fatalf("same scope: %+v, %v", a2, err)
	}
	// A change is never read on its own.
	if _, err := f.svc.Get(f.ctx, mgr, dev, "dhcp.scope_range_set", json.RawMessage(`{"scopeId":"192.168.1.0","startRange":"192.168.1.1","endRange":"192.168.1.9"}`)); !errors.Is(err, apperr.NotFound()) {
		t.Errorf("a change was read on its own: %v", err)
	}
}

// A computer outside the development scope is never read automatically.
func TestAutomaticReadStaysInTheDevelopmentScope(t *testing.T) {
	f := newFx(t)
	dev := f.device(f.globex, f.main, "gx", 0)
	gx := f.user("g@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.globex})
	t.Cleanup(devscope.Set(f.acme))
	if _, err := f.svc.Get(f.ctx, gx, dev, "defender.status", nil); !errors.Is(err, apperr.NotFound()) {
		t.Errorf("outside the scope: %v", err)
	}
	if f.reads(dev) != 0 {
		t.Error("a read was started outside the scope")
	}
}

// The measured path of one read, against the real database: the job is made, the agent takes it and reports, and
// the console's next look finds the result. Run with -v to see the times.
func TestReadPathTimings(t *testing.T) {
	f := newFx(t)
	dev := f.device(f.acme, f.hq, "dc1", 0)
	t0 := time.Now()
	got, err := f.svc.Get(f.ctx, f.tech, dev, "defender.status", nil)
	if err != nil || got.RunID == nil {
		t.Fatal(got, err)
	}
	created := time.Since(t0)
	t1 := time.Now()
	if _, err := f.jobs.Poll(f.ctx, dev, []string{agentproto.CapJobParams, agentproto.CapJobPwsh}); err != nil {
		t.Fatal(err)
	}
	if st, err := f.jobs.Start(f.ctx, dev, *got.RunID); err != nil || !st.Proceed {
		t.Fatal(st, err)
	}
	claimed := time.Since(t1)
	t2 := time.Now()
	if err := f.jobs.Result(f.ctx, dev, *got.RunID, agentproto.ResultRequest{Status: jobs.StatusSucceeded, ExitCode: new(int), Stdout: timingStatus}); err != nil {
		t.Fatal(err)
	}
	stored := time.Since(t2)
	t3 := time.Now()
	res, err := f.jobs.ReadWinmodResult(f.ctx, f.tech, *got.RunID)
	if err != nil || res.OK == nil || !*res.OK {
		t.Fatal(res, err)
	}
	seen := time.Since(t3)
	t4 := time.Now()
	after, err := f.svc.Get(f.ctx, f.tech, dev, "defender.status", nil)
	if err != nil || after.Stale || after.Data == nil {
		t.Fatalf("the next open: %+v, %v", after, err)
	}
	t.Logf("job created and audited %v; claimed (poll and start) %v; result stored %v; console reads the run %v; next tab open from the stored result %v",
		created, claimed, stored, seen, time.Since(t4))
}

const timingStatus = `EASYRMM-WINMOD-RESULT-V1 {"ok":true,"version":1,"data":{"antivirusEnabled":true,"antispywareEnabled":true,` +
	`"realTimeProtectionEnabled":true,"behaviorMonitorEnabled":true,"ioavProtectionEnabled":true,"onAccessProtectionEnabled":true,` +
	`"nisEnabled":true,"tamperProtected":false,"runningMode":"Normal","computerState":0,"engineVersion":"1.1.24090.11",` +
	`"productVersion":"4.18.24090.11","serviceVersion":"4.18.24090.11","signatureVersion":"1.421.1.0",` +
	`"signatureUpdatedAt":"2026-11-26T08:00:00Z","signatureAgeDays":0,"quickScanAgeDays":1,"fullScanAgeDays":null},"error":null}` + "\n"
