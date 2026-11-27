//go:build integration

package jobkeys

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// guardErr is a guard whose answer a test changes.
type guardErr struct {
	mu  sync.Mutex
	err error
}

func (g *guardErr) set(err error) { g.mu.Lock(); g.err = err; g.mu.Unlock() }
func (g *guardErr) get() error    { g.mu.Lock(); defer g.mu.Unlock(); return g.err }

func (f *fixture) auditCount(action string) int {
	f.t.Helper()
	return f.count(`SELECT count(*) FROM audit_log WHERE action = $1`, action)
}

func (f *fixture) offer(dev uuid.UUID) Statements {
	f.t.Helper()
	var s Statements
	f.tx(func(tx pgx.Tx) (err error) { s, err = f.ring.Offer(f.ctx, tx, dev); return err })
	return s
}

func (f *fixture) install(dev uuid.UUID) (ed25519.PublicKey, string) {
	f.t.Helper()
	var pub []byte
	f.tx(func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT agent_public_key FROM devices WHERE id = $1`, dev).Scan(&pub)
	})
	return pub, agentproto.InstallID(pub)
}

// report stores a device's report, a minute after the last one.
func (f *fixture) report(dev uuid.UUID, keys ...Key) {
	f.t.Helper()
	f.advance(time.Minute)
	f.observe(dev, f.now(), sha("a"), reportOf(keys...))
}

func TestStartPlannedMakesAKeyThatIsNotTheFloorAndRefusesASecond(t *testing.T) {
	f := newFixture(t)
	k1 := f.ring.Newest()
	var floors []int64
	f.ring.OnFloorChange(func(from, to int64) { floors = append(floors, to) })

	s, err := f.ring.Start(f.ctx, ReasonPlanned, HostBy())
	if err != nil {
		t.Fatal(err)
	}
	if s.Key.Generation <= k1.Generation || s.Key.CutOverAt != nil || s.Follows != k1.Generation {
		t.Fatalf("started: %+v", s)
	}
	if f.ring.Newest().Generation != s.Key.Generation || f.ring.Floor().Generation != k1.Generation {
		t.Fatalf("newest %d floor %d", f.ring.Newest().Generation, f.ring.Floor().Generation)
	}
	if !f.ring.Newest().Held() {
		t.Fatal("the new key's seed is not held")
	}
	if _, open := f.ring.Progress(); !open {
		t.Fatal("no rotation in progress")
	}
	if len(floors) != 0 {
		t.Fatalf("the floor did not move: %v", floors)
	}
	if n := f.auditCount("job_key.rotate"); n != 1 {
		t.Fatalf("audit rows: %d", n)
	}
	if _, err := f.ring.Start(f.ctx, ReasonPlanned, HostBy()); !errors.Is(err, ErrInProgress) {
		t.Fatalf("a second planned rotation: %v", err)
	}
	if _, err := f.ring.Start(f.ctx, ReasonMoving, HostBy()); !errors.Is(err, ErrInProgress) {
		t.Fatalf("a moving rotation during one: %v", err)
	}
	if _, err := f.ring.Start(f.ctx, "bogus", HostBy()); err == nil {
		t.Fatal("a bad reason was accepted")
	}
}

func TestStartCompromisedMarksEveryOlderKeyEndsAPlannedRotationAndMovesTheFloor(t *testing.T) {
	f := newFixture(t)
	k1 := f.ring.Newest()
	var floors []int64
	f.ring.OnFloorChange(func(from, to int64) { floors = append(floors, to) })
	planned, err := f.ring.Start(f.ctx, ReasonPlanned, HostBy())
	if err != nil {
		t.Fatal(err)
	}
	s, err := f.ring.Start(f.ctx, ReasonCompromised, HostBy())
	if err != nil {
		t.Fatal(err)
	}
	if s.Ended != planned.Key.Generation || len(s.Compromised) != 2 {
		t.Fatalf("started: %+v", s)
	}
	if f.ring.Floor().Generation != s.Key.Generation {
		t.Fatalf("floor %d, new %d", f.ring.Floor().Generation, s.Key.Generation)
	}
	for _, k := range f.ring.Keys() {
		if (k.Generation != s.Key.Generation) != (k.CompromisedAt != nil) {
			t.Errorf("key %d compromised %v", k.Generation, k.CompromisedAt)
		}
		if k.Generation == planned.Key.Generation && k.CutOverAt != nil {
			t.Error("the planned key was cut over to")
		}
	}
	if _, open := f.ring.Progress(); open {
		t.Fatal("a rotation is still in progress")
	}
	if len(floors) != 1 || floors[0] != s.Key.Generation {
		t.Fatalf("floor events: %v (from %d)", floors, k1.Generation)
	}
	// The compromised key's seed is kept until no device may trust it.
	if !f.ring.Keys()[0].Held() {
		t.Error("the compromised key's seed was deleted at once")
	}
}

func TestFinishNeedsTheBackupTheDayAndAPlannedRotation(t *testing.T) {
	f := newFixture(t)
	if _, err := f.ring.Finish(f.ctx, FinishInput{BackupTaken: true, By: HostBy()}); !errors.Is(err, ErrNoRotation) {
		t.Fatalf("nothing to finish: %v", err)
	}
	s, err := f.ring.Start(f.ctx, ReasonMoving, HostBy())
	if err != nil {
		t.Fatal(err)
	}
	var floors []int64
	f.ring.OnFloorChange(func(from, to int64) { floors = append(floors, to) })
	if _, err := f.ring.Finish(f.ctx, FinishInput{By: HostBy()}); !errors.Is(err, ErrBackup) {
		t.Fatalf("without the backup: %v", err)
	}
	if _, err := f.ring.Finish(f.ctx, FinishInput{BackupTaken: true, By: HostBy()}); !errors.Is(err, ErrTooEarly) {
		t.Fatalf("too early: %v", err)
	}
	f.advance(MinOverlap - time.Minute)
	if _, err := f.ring.Finish(f.ctx, FinishInput{BackupTaken: true, By: HostBy()}); !errors.Is(err, ErrTooEarly) {
		t.Fatalf("a minute early: %v", err)
	}
	f.advance(time.Minute)
	dev := f.device("pc")
	f.report(dev, f.ring.Keys()[0], s.Key)
	moved := f.device("moved")
	f.report(moved, s.Key)
	fin, err := f.ring.Finish(f.ctx, FinishInput{BackupTaken: true, By: HostBy()})
	if err != nil {
		t.Fatal(err)
	}
	if fin.Moved != 2 || fin.NotMoved != 0 || f.ring.Floor().Generation != s.Key.Generation {
		t.Fatalf("finished: %+v floor %d", fin, f.ring.Floor().Generation)
	}
	if len(floors) != 1 || floors[0] != s.Key.Generation {
		t.Fatalf("floor events: %v", floors)
	}
	if n := f.auditCount("job_key.finish"); n != 1 {
		t.Fatalf("audit rows: %d", n)
	}
	if _, err := f.ring.Finish(f.ctx, FinishInput{BackupTaken: true, By: HostBy()}); !errors.Is(err, ErrNoRotation) {
		t.Fatalf("finished twice: %v", err)
	}

	// --now skips the day, and the record says so.
	if _, err := f.ring.Start(f.ctx, ReasonPlanned, HostBy()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.ring.Finish(f.ctx, FinishInput{BackupTaken: true, Now: true, By: HostBy()}); err != nil {
		t.Fatal(err)
	}
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'job_key.finish' AND details->>'skippedMinimum' = 'true'`); n != 1 {
		t.Fatalf("skipped records: %d", n)
	}
}

func TestChangesAreRefusedWhileHeldUpgradingOrAnOlderServerIsSeen(t *testing.T) {
	f := newFixture(t)
	var guard guardErr
	f.ring.SetGuard(guard.get)

	guard.set(errors.New("updater: the updater holds the server"))
	if _, err := f.ring.Start(f.ctx, ReasonPlanned, HostBy()); !errors.Is(err, ErrHeld) {
		t.Fatalf("held: %v", err)
	}
	guard.set(errors.New("updater: an upgrade is under way"))
	if _, err := f.ring.Start(f.ctx, ReasonPlanned, HostBy()); !errors.Is(err, ErrUpgrading) {
		t.Fatalf("upgrading: %v", err)
	}
	if _, err := f.ring.Forget(f.ctx, 1, HostBy()); !errors.Is(err, ErrUpgrading) {
		t.Fatalf("forget while upgrading: %v", err)
	}
	if _, err := f.ring.Recover(f.ctx, 1, HostBy()); !errors.Is(err, ErrUpgrading) {
		t.Fatalf("recover while upgrading: %v", err)
	}
	if _, _, err := f.ring.ReplaceLost(f.ctx, HostBy()); !errors.Is(err, ErrUpgrading) {
		t.Fatalf("replace-lost while upgrading: %v", err)
	}
	guard.set(nil)
	if n := f.count(`SELECT count(*) FROM job_keys`); n != 1 {
		t.Fatalf("a refused change made a key: %d", n)
	}

	// An instance of an older version, seen recently.
	f.exec(`INSERT INTO server_instances (id, version) VALUES ('old', '1.0.9')`)
	if _, err := f.ring.Start(f.ctx, ReasonPlanned, HostBy()); !errors.Is(err, ErrOlderSrv) {
		t.Fatalf("older server: %v", err)
	}
	// Not an older one when it was last seen long ago, is the same version, a
	// development build, or newer.
	for _, v := range []string{"1.2.3", "dev", "v1.3.0", "garbage"} {
		f.exec(`UPDATE server_instances SET version = $1 WHERE id = 'old'`, v)
		if err := f.ring.checkOlderForTest(f.ctx); err != nil {
			t.Fatalf("version %q: %v", v, err)
		}
	}
	f.exec(`UPDATE server_instances SET version = '1.0.9', seen_at = now() - interval '3 minutes' WHERE id = 'old'`)
	if err := f.ring.checkOlderForTest(f.ctx); err != nil {
		t.Fatalf("an instance not seen for 3 minutes: %v", err)
	}
	f.exec(`DELETE FROM server_instances WHERE id = 'old'`)

	// A connection named plain easyrmm-server: a build from before the ring.
	cfg, err := pgx.ParseConfig(f.inst.SuperDSN)
	if err != nil {
		t.Fatal(err)
	}
	cfg.RuntimeParams["application_name"] = "easyrmm-server"
	conn, err := pgx.ConnectConfig(f.ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	if _, err := f.ring.Start(f.ctx, ReasonPlanned, HostBy()); !errors.Is(err, ErrOlderSrv) {
		t.Fatalf("an old build's connection: %v", err)
	}
	// Finishing is refused the same way; forgetting is not.
	if _, err := f.ring.Finish(f.ctx, FinishInput{BackupTaken: true, Now: true, By: HostBy()}); !errors.Is(err, ErrOlderSrv) && !errors.Is(err, ErrNoRotation) {
		t.Fatalf("finish beside an old build: %v", err)
	}
	conn.Close(f.ctx)
	if _, err := f.ring.Start(f.ctx, ReasonPlanned, HostBy()); err != nil {
		t.Fatalf("after the old build is gone: %v", err)
	}
}

func (r *Ring) checkOlderForTest(ctx context.Context) error {
	return r.db.InTx(ctx, database.System, func(tx pgx.Tx) error { return r.checkOlder(ctx, tx) })
}

func TestTheHoldIsCheckedAgainInsideTheLock(t *testing.T) {
	f := newFixture(t)
	// The guard's answer changes between the caller's look and the lock: the
	// change reads it inside the lock, so the later answer is the one that counts.
	calls := 0
	f.ring.SetGuard(func() error {
		calls++
		if calls >= 1 {
			return errors.New("updater: the updater holds the server")
		}
		return nil
	})
	if _, err := f.ring.Start(f.ctx, ReasonPlanned, HostBy()); !errors.Is(err, ErrHeld) || calls != 1 {
		t.Fatalf("err %v after %d looks", err, calls)
	}
	if n := f.count(`SELECT count(*) FROM job_keys`); n != 1 {
		t.Fatalf("keys: %d", n)
	}
}

func TestForgetNeverTheNewestAndCountsWhatItLeavesNeedingRepinning(t *testing.T) {
	f := newFixture(t)
	k1 := f.ring.Newest()
	s, err := f.ring.Start(f.ctx, ReasonPlanned, HostBy())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.ring.Forget(f.ctx, s.Key.Generation, HostBy()); !errors.Is(err, ErrNewestKey) {
		t.Fatalf("the newest: %v", err)
	}
	if _, err := f.ring.Forget(f.ctx, 999, HostBy()); !errors.Is(err, ErrNoSuchKey) {
		t.Fatalf("no such key: %v", err)
	}
	stuck, fine := f.device("stuck"), f.device("fine")
	f.report(stuck, k1)
	f.report(fine, k1, s.Key)
	n, err := f.ring.Forget(f.ctx, k1.Generation, HostBy())
	if err != nil || n != 1 {
		t.Fatalf("forget: %d, %v", n, err)
	}
	if k, _ := f.ring.ByGeneration(k1.Generation); k.Held() || k.SeedDeletedAt == nil {
		t.Fatalf("the seed is still held: %+v", k)
	}
	if _, err := f.ring.Forget(f.ctx, k1.Generation, HostBy()); !errors.Is(err, ErrNoSeed) {
		t.Fatalf("forgotten twice: %v", err)
	}
	// The device that trusts only it is now one that needs re-pinning.
	if c := f.choice(stuck); !c.NeedsRepinning {
		t.Fatalf("stuck: %+v", c)
	}
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'job_key.forget' AND details->>'by' = 'person' AND details->>'devicesNeedingRepinning' = '1'`); n != 1 {
		t.Fatalf("audit rows: %d", n)
	}
}

func TestSweepSeedsDeletesOnlyWhatNoDeviceMayTrust(t *testing.T) {
	f := newFixture(t)
	k1 := f.ring.Newest()
	s, err := f.ring.Start(f.ctx, ReasonPlanned, HostBy())
	if err != nil {
		t.Fatal(err)
	}
	dev := f.device("pc")
	f.report(dev, k1, s.Key)
	if _, err := f.ring.Finish(f.ctx, FinishInput{BackupTaken: true, Now: true, By: HostBy()}); err != nil {
		t.Fatal(err)
	}
	if n, err := f.ring.SweepSeeds(f.ctx); err != nil || n != 0 {
		t.Fatalf("a device still reports the old key: %d, %v", n, err)
	}
	f.report(dev, s.Key)
	// A removed device that was last given the old key keeps it alive.
	f.exec(`INSERT INTO retired_devices (device_id, organization_id, site_id, name, expires_at, job_key_given_generation)
		VALUES ($1, $2, $3, 'gone', now() + interval '90 days', 1)`, uuid.New(), f.org, f.site)
	if n, err := f.ring.SweepSeeds(f.ctx); err != nil || n != 0 {
		t.Fatalf("a removed device may still trust it: %d, %v", n, err)
	}
	f.exec(`DELETE FROM retired_devices`)
	if n, err := f.ring.SweepSeeds(f.ctx); err != nil || n != 1 {
		t.Fatalf("nothing needs it: %d, %v", n, err)
	}
	if k, _ := f.ring.ByGeneration(k1.Generation); k.Held() {
		t.Fatal("the seed is still held")
	}
	if f.ring.Floor().Held() == false {
		t.Fatal("the floor's seed was deleted")
	}
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'job_key.forget' AND details->>'by' = 'server'`); n != 1 {
		t.Fatalf("audit rows: %d", n)
	}
	if n, err := f.ring.SweepSeeds(f.ctx); err != nil || n != 0 {
		t.Fatalf("again: %d, %v", n, err)
	}
}

func TestReplaceLostAndRecover(t *testing.T) {
	f := newFixture(t)
	if _, _, err := f.ring.ReplaceLost(f.ctx, HostBy()); !errors.Is(err, ErrNothing) {
		t.Fatalf("nothing lost: %v", err)
	}
	k1 := f.ring.Newest()
	// The seed is sealed with a key this server does not have.
	other := newSealer(t, "other")
	sealed, err := other.Seal(k1.Private.Seed(), aad(1))
	if err != nil {
		t.Fatal(err)
	}
	right := f.sealerString(1)
	f.exec(`UPDATE job_keys SET sealed_seed = $2 WHERE generation = $1`, int64(1), sealed)
	if err := f.ring.Reload(f.ctx); err == nil {
		t.Fatal("the ring loaded a seed it cannot open")
	}

	// .env does not match this database: another sealed value does not open.
	foreign, err := other.Seal([]byte(`{}`), []byte("easyrmm:tls.internal_ca"))
	if err != nil {
		t.Fatal(err)
	}
	f.exec(`INSERT INTO settings (key, value) VALUES ('tls.internal_ca', jsonb_build_object('sealed', $1::text))`, foreign)
	host := NewHost(f.db, f.sealer, audit.New(f.db, nil), quiet(), "1.2.3", nil)
	if _, _, err := host.ReplaceLost(f.ctx, HostBy()); !errors.Is(err, ErrEnvDiffers) {
		t.Fatalf("a mismatched .env: %v", err)
	}
	if n := f.count(`SELECT count(*) FROM job_keys WHERE lost_at IS NOT NULL`); n != 0 {
		t.Fatalf("a refusal marked a key lost: %d", n)
	}
	f.exec(`DELETE FROM settings WHERE key = 'tls.internal_ca'`)

	lost, nk, err := host.ReplaceLost(f.ctx, HostBy())
	if err != nil || len(lost) != 1 || lost[0] != 1 || nk.Reason != ReasonLostReplacement || nk.CutOverAt == nil {
		t.Fatalf("replace-lost: %v %+v %v", lost, nk, err)
	}
	if err := f.ring.Reload(f.ctx); err != nil {
		t.Fatalf("the ring does not load after replace-lost: %v", err)
	}
	if f.ring.Floor().Generation != nk.Generation || f.ring.Newest().Generation != nk.Generation {
		t.Fatalf("floor %d", f.ring.Floor().Generation)
	}
	if k, _ := f.ring.ByGeneration(1); k.LostAt == nil || k.Held() {
		t.Fatalf("the lost key: %+v", k)
	}
	if n := f.auditCount("job_key.replace_lost"); n != 1 {
		t.Fatalf("audit rows: %d", n)
	}
	// A key that is not lost cannot be recovered; the lost one cannot while
	// its seed still does not open.
	if _, err := host.Recover(f.ctx, nk.Generation, HostBy()); !errors.Is(err, ErrNotLost) {
		t.Fatalf("recover a held key: %v", err)
	}
	if _, err := host.Recover(f.ctx, 1, HostBy()); !errors.Is(err, ErrOpens) {
		t.Fatalf("recover with the wrong key: %v", err)
	}
	// With the right encryption key listed as a previous one, it opens.
	f.exec(`UPDATE job_keys SET sealed_seed = $1 WHERE generation = 1`, right)
	dev := f.device("pc")
	f.report(dev, k1)
	n, err := host.Recover(f.ctx, 1, HostBy())
	if err != nil || n != 1 {
		t.Fatalf("recover: %d, %v", n, err)
	}
	if err := f.ring.Reload(f.ctx); err != nil {
		t.Fatal(err)
	}
	if k, _ := f.ring.ByGeneration(1); !k.Held() || k.LostAt != nil {
		t.Fatalf("recovered: %+v", k)
	}
	if c := f.choice(dev); c.NeedsRepinning || c.Key.Generation != 1 {
		t.Fatalf("the device after recovery: %+v", c)
	}
	if n := f.auditCount("job_key.recover"); n != 1 {
		t.Fatalf("audit rows: %d", n)
	}
}

// sealerString is the seed of a generation sealed with the fixture's own key.
func (f *fixture) sealerString(gen int64) string {
	f.t.Helper()
	k, ok := f.ring.ByGeneration(gen)
	if !ok {
		f.t.Fatal("no such key")
	}
	s, err := f.sealer.Seal(k.Private.Seed(), aad(gen))
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}

func TestOfferWalksADeviceThroughAPlannedRotation(t *testing.T) {
	f := newFixture(t)
	k1 := f.ring.Newest()
	dev := f.device("pc")
	devPub, install := f.install(dev)

	// Never reported: nothing.
	if s := f.offer(dev); s.Handover != nil || s.Cutover != nil {
		t.Fatalf("never reported: %+v", s)
	}
	// One key and no newer key: nothing.
	f.report(dev, k1)
	if s := f.offer(dev); s.Handover != nil || s.Cutover != nil {
		t.Fatalf("nothing to move to: %+v", s)
	}

	r, err := f.ring.Start(f.ctx, ReasonPlanned, HostBy())
	if err != nil {
		t.Fatal(err)
	}
	k2 := r.Key
	k2, _ = f.ring.ByGeneration(k2.Generation)

	// Rule 4: the hand-over to the newest, signed with the key it trusts.
	s := f.offer(dev)
	if s.Handover == nil || s.Cutover != nil {
		t.Fatalf("handover: %+v", s)
	}
	st, err := agentproto.VerifyHandover(k1.Public, *s.Handover, dev.String(), install, f.now())
	if err != nil || st.Key != k2.Encoded() || st.Generation != k2.Generation {
		t.Fatalf("verify: %+v %v", st, err)
	}
	if _, err := agentproto.VerifyHandover(k2.Public, *s.Handover, dev.String(), install, f.now()); err == nil {
		t.Fatal("the hand-over verified under the key it introduces")
	}
	_ = devPub
	if n := f.count(`SELECT count(*) FROM issued_instructions WHERE kind = 'handover' AND instruction_id = $1 AND generation = 1`, k2.Fingerprint()); n != 1 {
		t.Fatalf("issued rows: %d", n)
	}

	// Both keys, during the overlap: nothing, the target is the floor and it
	// lacks the floor's cut-over reason... it trusts the floor and the newest.
	f.report(dev, k1, k2)
	if s := f.offer(dev); s.Handover != nil || s.Cutover != nil {
		t.Fatalf("during the overlap: %+v", s)
	}
	if c := f.choice(dev); c.Key.Generation != k2.Generation {
		t.Fatalf("signed for %d", c.Key.Generation)
	}

	// Finished: the floor is the new key; a device that trusts both is cut over.
	if _, err := f.ring.Finish(f.ctx, FinishInput{BackupTaken: true, Now: true, By: HostBy()}); err != nil {
		t.Fatal(err)
	}
	s = f.offer(dev)
	if s.Cutover == nil || s.Handover != nil {
		t.Fatalf("cutover: %+v", s)
	}
	cs, err := agentproto.VerifyCutover(k2.Public, *s.Cutover, dev.String(), install, f.now())
	if err != nil || cs.Key != k2.Encoded() {
		t.Fatalf("verify cutover: %+v %v", cs, err)
	}
	var gen *int64
	f.tx(func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT job_key_cutover_generation FROM devices WHERE id = $1`, dev).Scan(&gen)
	})
	if gen == nil || *gen != k2.Generation {
		t.Fatalf("the cut-over was not recorded: %v", gen)
	}
	// It confirms with a report of one key: nothing more.
	f.report(dev, k2)
	if s := f.offer(dev); s.Handover != nil || s.Cutover != nil {
		t.Fatalf("after confirming: %+v", s)
	}
}

func TestOfferFollowsADeviceThatTrustsAKeyTheServerNeverHeld(t *testing.T) {
	f := newFixture(t)
	k1 := f.ring.Newest()
	dev := f.device("pc")
	_, install := f.install(dev)
	r, err := f.ring.Start(f.ctx, ReasonPlanned, HostBy())
	if err != nil {
		t.Fatal(err)
	}
	k2, _ := f.ring.ByGeneration(r.Key.Generation)
	// It trusts k1 and a key of a lower generation than the target that the
	// ring never saw (rule 3, second branch): the hand-over, signed with k1.
	_, unk, _ := ed25519.GenerateKey(nil)
	unknown := Key{Generation: k1.Generation + 1, Public: unk.Public().(ed25519.PublicKey)}
	f.advance(time.Minute)
	f.observe(dev, f.now(), sha("a"), reportOf(k1, unknown))
	s := f.offer(dev)
	if s.Handover == nil {
		t.Fatalf("no hand-over: %+v", s)
	}
	if st, err := agentproto.VerifyHandover(k1.Public, *s.Handover, dev.String(), install, f.now()); err != nil || st.Generation != k2.Generation {
		t.Fatalf("verify: %+v %v", st, err)
	}
}
