//go:build integration

package jobkeys

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

type fixture struct {
	t      *testing.T
	ctx    context.Context
	db     *database.DB
	sealer *secrets.Sealer
	ring   *Ring
	org    uuid.UUID
	site   uuid.UUID
	clock  *time.Time
	mu     sync.Mutex
}

func newSealer(t *testing.T, id string) *secrets.Sealer {
	t.Helper()
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	s, err := secrets.NewSealer(secrets.Key{ID: id, Raw: raw})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// newFixture is a migrated database with a ring opened over it, as a first
// start of a fresh install does.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	inst := testdb.New(t)
	f := &fixture{t: t, ctx: context.Background(), db: inst.DB, sealer: newSealer(t, "k1")}
	now := time.Now().UTC().Truncate(time.Millisecond)
	f.clock = &now
	f.openRing()
	f.org = f.uuid(`INSERT INTO organizations (name) VALUES ('Acme') RETURNING id`)
	f.site = f.uuid(`INSERT INTO sites (organization_id, name) VALUES ($1, 'HQ') RETURNING id`, f.org)
	return f
}

func (f *fixture) openRing() {
	f.t.Helper()
	r, err := Open(f.ctx, f.db, f.sealer, quiet(), Options{Version: "1.2.3", Audit: audit.New(f.db, nil), Now: f.now})
	if err != nil {
		f.t.Fatal(err)
	}
	f.ring = r
}

func (f *fixture) now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return *f.clock
}

func (f *fixture) advance(d time.Duration) {
	f.mu.Lock()
	*f.clock = f.clock.Add(d)
	f.mu.Unlock()
}

func (f *fixture) exec(sql string, args ...any) {
	f.t.Helper()
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(f.ctx, sql, args...)
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) uuid(sql string, args ...any) uuid.UUID {
	f.t.Helper()
	var id uuid.UUID
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error { return tx.QueryRow(f.ctx, sql, args...).Scan(&id) }); err != nil {
		f.t.Fatal(err)
	}
	return id
}

func (f *fixture) count(sql string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error { return tx.QueryRow(f.ctx, sql, args...).Scan(&n) }); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func (f *fixture) device(name string) uuid.UUID {
	f.t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	return f.uuid(`INSERT INTO devices (organization_id, site_id, name, hostname, os_description, platform, agent_public_key, enrolled_at)
		VALUES ($1, $2, $3, $3, 'Linux', 'linux', $4, now()) RETURNING id`, f.org, f.site, name, []byte(pub))
}

func (f *fixture) tx(fn func(pgx.Tx) error) {
	f.t.Helper()
	if err := f.db.InTx(f.ctx, database.System, fn); err != nil {
		f.t.Fatal(err)
	}
}

// addKey puts a second key into the ring, as a rotation will, and reloads.
func (f *fixture) addKey(gen int64, held bool) (ed25519.PrivateKey, ed25519.PublicKey) {
	f.t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	var sealed *string
	var deleted *time.Time
	if held {
		s, err := f.sealer.Seal(priv.Seed(), aad(gen))
		if err != nil {
			f.t.Fatal(err)
		}
		sealed = &s
	} else {
		now := time.Now()
		deleted = &now
	}
	f.exec(`INSERT INTO job_keys (generation, public_key, sealed_seed, reason, seed_deleted_at) VALUES ($1, $2, $3, 'planned', $4)`,
		gen, []byte(priv.Public().(ed25519.PublicKey)), sealed, deleted)
	if err := f.ring.Reload(f.ctx); err != nil {
		f.t.Fatal(err)
	}
	return priv, priv.Public().(ed25519.PublicKey)
}

func TestFreshInstallMakesGenerationOneAndTheTombstone(t *testing.T) {
	f := newFixture(t)
	keys := f.ring.Keys()
	if len(keys) != 1 || keys[0].Generation != 1 || keys[0].CutOverAt == nil || keys[0].Reason != ReasonInitial || !keys[0].Held() {
		t.Fatalf("ring %+v", keys)
	}
	if f.ring.Newest().Generation != 1 || f.ring.Floor().Generation != 1 {
		t.Error("newest and floor are not generation 1")
	}
	var value string
	f.tx(func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT value::text FROM settings WHERE key = 'jobs.signing_key'`).Scan(&value)
	})
	if !strings.HasPrefix(value, `"moved to the job_keys table`) {
		t.Errorf("settings row %s", value)
	}
	// What an older server's LoadKey reads the row into: a string does not fit.
	var old struct {
		Sealed string `json:"sealed"`
	}
	if err := json.Unmarshal([]byte(value), &old); err == nil {
		t.Error("an older server could read the tombstone")
	}
	// The seed is sealed under the generation's additional data and nothing else.
	var sealed string
	f.tx(func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT sealed_seed FROM job_keys WHERE generation = 1`).Scan(&sealed)
	})
	if _, err := f.sealer.Open(sealed, aad(1)); err != nil {
		t.Errorf("opening with the generation's additional data: %v", err)
	}
	if _, err := f.sealer.Open(sealed, []byte(settingAAD)); err == nil {
		t.Error("the seed opens with the old additional data")
	}
	if strings.Contains(sealed, keys[0].Encoded()) {
		t.Error("the seed is not sealed")
	}
	// A second server on the same database finds the same key and moves nothing.
	again, err := Open(f.ctx, f.db, f.sealer, quiet(), Options{Version: "1.2.3"})
	if err != nil || !again.Newest().Public.Equal(keys[0].Public) {
		t.Fatalf("second server: %v", err)
	}
	if f.count(`SELECT count(*) FROM job_keys`) != 1 {
		t.Error("a second server made a key")
	}
	if f.count(`SELECT count(*) FROM server_instances`) != 2 {
		t.Error("two servers are not both recorded")
	}
}

// The move from settings: the same seed and public key, sealed again under
// the new additional data, recorded as cut over to, the tombstone written.
func TestMoveFromSettingsKeepsTheKey(t *testing.T) {
	inst := testdb.New(t)
	ctx := context.Background()
	sealer := newSealer(t, "k1")
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	sealed, err := sealer.Seal(priv.Seed(), []byte(settingAAD))
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := json.Marshal(map[string]string{"sealed": sealed})
	if err := inst.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO settings (key, value) VALUES ('jobs.signing_key', $1)`, doc)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	r, err := Open(ctx, inst.DB, sealer, quiet(), Options{Version: "1.2.3"})
	if err != nil {
		t.Fatal(err)
	}
	k := r.Newest()
	if !k.Public.Equal(priv.Public()) || k.Generation != 1 || k.CutOverAt == nil || !k.Held() {
		t.Fatalf("moved key %+v", k)
	}
	var now string
	_ = inst.DB.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT sealed_seed FROM job_keys WHERE generation = 1`).Scan(&now)
	})
	if now == sealed {
		t.Error("the sealed value did not change with the additional data")
	}
	if seed, err := sealer.Open(now, aad(1)); err != nil || string(seed) != string(priv.Seed()) {
		t.Errorf("the seed changed: %v", err)
	}
	var value string
	_ = inst.DB.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT value::text FROM settings WHERE key = 'jobs.signing_key'`).Scan(&value)
	})
	if strings.Contains(value, "sealed") {
		t.Errorf("the settings row still holds the key: %s", value)
	}
}

func TestOpenRefusesWhenTheSeedCannotBeOpened(t *testing.T) {
	f := newFixture(t)
	wrong := newSealer(t, "k1")
	if _, err := Open(f.ctx, f.db, wrong, quiet(), Options{}); err == nil || !strings.Contains(err.Error(), "EASYRMM_SECRET_KEY") {
		t.Fatalf("opened with another secret key: %v", err)
	}
	// A tombstone with an empty ring is refused, not answered with a new key.
	g := newFixture(t)
	g.exec(`DELETE FROM job_keys`)
	if _, err := Open(g.ctx, g.db, g.sealer, quiet(), Options{}); err == nil || !strings.Contains(err.Error(), "tombstone") {
		t.Fatalf("an empty ring behind a tombstone: %v", err)
	}
}

func TestKeysAreSealedAgainAfterTheEncryptionKeyChanges(t *testing.T) {
	f := newFixture(t)
	pub := f.ring.Newest().Public
	var before string
	f.tx(func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT sealed_seed FROM job_keys WHERE generation = 1`).Scan(&before)
	})
	// The old key is kept in the ring and a new primary added, as
	// EASYRMM_SECRET_KEYS_PREVIOUS does.
	oldRaw := make([]byte, 32)
	_, _ = rand.Read(oldRaw)
	oldSealer, _ := secrets.NewSealer(secrets.Key{ID: "k0", Raw: oldRaw})
	seed := f.ring.Newest().Private.Seed()
	sealedOld, _ := oldSealer.Seal(seed, aad(1))
	f.exec(`UPDATE job_keys SET sealed_seed = $1 WHERE generation = 1`, sealedOld)
	newRaw := make([]byte, 32)
	_, _ = rand.Read(newRaw)
	both, err := secrets.NewSealer(secrets.Key{ID: "k1", Raw: newRaw}, secrets.Key{ID: "k0", Raw: oldRaw})
	if err != nil {
		t.Fatal(err)
	}
	r, err := Open(f.ctx, f.db, both, quiet(), Options{})
	if err != nil || !r.Newest().Public.Equal(pub) {
		t.Fatalf("open: %v", err)
	}
	var after string
	f.tx(func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT sealed_seed FROM job_keys WHERE generation = 1`).Scan(&after)
	})
	if after == sealedOld || !strings.HasPrefix(after, "v1.k1.") {
		t.Errorf("not sealed again under the primary key: %q", after)
	}
	if opened, err := both.Open(after, aad(1)); err != nil || string(opened) != string(seed) {
		t.Errorf("the reseal changed the seed: %v", err)
	}
}

func TestTwoServersStartingTogetherMakeOneKey(t *testing.T) {
	inst := testdb.New(t)
	ctx := context.Background()
	sealer := newSealer(t, "k1")
	var wg sync.WaitGroup
	rings := make([]*Ring, 4)
	errs := make([]error, 4)
	for i := range rings {
		wg.Go(func() { rings[i], errs[i] = Open(ctx, inst.DB, sealer, quiet(), Options{Version: "1"}) })
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
		if !rings[i].Newest().Public.Equal(rings[0].Newest().Public) {
			t.Fatal("two servers hold different keys")
		}
	}
	var n int
	_ = inst.DB.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM job_keys`).Scan(&n)
	})
	if n != 1 {
		t.Errorf("%d keys", n)
	}
}

func TestServerInstancesAreRecordedHeldAndRemoved(t *testing.T) {
	f := newFixture(t)
	var held atomic.Bool
	f.ring.SetHeld(held.Load)
	list, err := f.ring.Instances(f.ctx)
	if err != nil || len(list) != 1 || list[0].Version != "1.2.3" || list[0].Held || list[0].ID != f.ring.ID() {
		t.Fatalf("instances %+v %v", list, err)
	}
	// Run writes a hold the moment it changes, and removes the row at the end.
	ctx, cancel := context.WithCancel(f.ctx)
	done := make(chan struct{})
	go func() { f.ring.Run(ctx); close(done) }()
	held.Store(true)
	deadline := time.Now().Add(10 * time.Second)
	for {
		list, _ = f.ring.Instances(f.ctx)
		if len(list) == 1 && list[0].Held {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the hold was not recorded")
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	<-done
	if n := f.count(`SELECT count(*) FROM server_instances`); n != 0 {
		t.Errorf("the row stayed after the server stopped: %d", n)
	}
	// A server that died without removing its row is not counted after two
	// minutes, and is purged after a day.
	f.exec(`INSERT INTO server_instances (id, version, seen_at) VALUES ('dead', '0.9', now() - interval '3 minutes')`)
	if list, _ := f.ring.Instances(f.ctx); len(list) != 0 {
		t.Errorf("a stale instance is counted: %+v", list)
	}
	f.exec(`UPDATE server_instances SET seen_at = now() - interval '2 days' WHERE id = 'dead'`)
	if err := f.ring.Purge(f.ctx); err != nil {
		t.Fatal(err)
	}
	if f.count(`SELECT count(*) FROM server_instances`) != 0 {
		t.Error("the dead server's row was not purged")
	}
}

// reportOf builds a report of keys at generations.
func reportOf(keys ...Key) []agentproto.TrustedKey {
	out := make([]agentproto.TrustedKey, len(keys))
	for i, k := range keys {
		out[i] = agentproto.TrustedKey{Key: k.Encoded(), Generation: k.Generation}
	}
	return out
}

func (f *fixture) observe(dev uuid.UUID, at time.Time, build string, keys []agentproto.TrustedKey) {
	f.t.Helper()
	f.tx(func(tx pgx.Tx) error {
		return f.ring.Observe(f.ctx, tx, Observation{Device: dev, Org: f.org, Site: f.site, Label: "pc", Keys: keys, SignedAt: at, Build: build})
	})
}

func (f *fixture) choice(dev uuid.UUID) Choice {
	f.t.Helper()
	var c Choice
	f.tx(func(tx pgx.Tx) (err error) { c, err = f.ring.For(f.ctx, tx, dev); return err })
	return c
}

func TestObserveStoresTheReportOnlyWhenItChangesAndIsNewer(t *testing.T) {
	f := newFixture(t)
	dev := f.device("pc-1")
	k1 := f.ring.Newest()
	t0 := f.now()
	f.observe(dev, t0, sha("a"), reportOf(k1))
	var first, at time.Time
	f.tx(func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT job_keys_first_reported_at, job_keys_report_at FROM devices WHERE id = $1`, dev).Scan(&first, &at)
	})
	if !at.Equal(t0) || !first.Equal(t0) {
		t.Fatalf("stored at %v first %v", at, first)
	}
	// The same report again: nothing is written.
	f.observe(dev, t0.Add(time.Minute), sha("a"), reportOf(k1))
	var at2 time.Time
	f.tx(func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT job_keys_report_at FROM devices WHERE id = $1`, dev).Scan(&at2)
	})
	if !at2.Equal(t0) {
		t.Errorf("an unchanged report was written again: %v", at2)
	}
	// A new build with the same report is a change.
	f.observe(dev, t0.Add(2*time.Minute), sha("b"), reportOf(k1))
	var built string
	f.tx(func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT job_keys_report_sha FROM devices WHERE id = $1`, dev).Scan(&built)
	})
	if built != sha("b") {
		t.Errorf("build %q", built)
	}
	// Two keys; then an older request (a poll held open) with the old report
	// never writes over the newer one.
	_, pub2 := f.addKey(f.now().UnixMilli(), true)
	k2, _ := f.ring.ByPublic(pub2)
	f.observe(dev, t0.Add(10*time.Minute), sha("b"), reportOf(k1, k2))
	f.observe(dev, t0.Add(5*time.Minute), sha("b"), reportOf(k1))
	var raw []byte
	f.tx(func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT job_keys_report FROM devices WHERE id = $1`, dev).Scan(&raw)
	})
	var stored []reported
	_ = json.Unmarshal(raw, &stored)
	if len(stored) != 2 {
		t.Errorf("an older report overwrote the newer: %s", raw)
	}
	// Reports that are not believed are not stored.
	bad := [][]agentproto.TrustedKey{
		{{Key: "nope", Generation: 1}},
		{{Key: k1.Encoded(), Generation: 1}, {Key: k1.Encoded(), Generation: 2}},
		{{Key: k1.Encoded(), Generation: -1}},
		make([]agentproto.TrustedKey, MaxReported+1),
	}
	for i := range bad[3] {
		p, _, _ := ed25519.GenerateKey(rand.Reader)
		bad[3][i] = agentproto.TrustedKey{Key: agentproto.EncodeKey(p), Generation: 1}
	}
	for i, rep := range bad {
		f.observe(dev, t0.Add(time.Hour+time.Duration(i)*time.Minute), sha("b"), rep)
	}
	f.tx(func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT job_keys_report FROM devices WHERE id = $1`, dev).Scan(&raw)
	})
	_ = json.Unmarshal(raw, &stored)
	if len(stored) != 2 {
		t.Errorf("a report that is not valid was stored: %s", raw)
	}
}

func TestUnknownKeysAreFlaggedAuditedOnceAndCleared(t *testing.T) {
	f := newFixture(t)
	dev := f.device("pc-1")
	k1 := f.ring.Newest()
	rogue, _, _ := ed25519.GenerateKey(rand.Reader)
	unknown := Key{Public: rogue, Generation: f.now().Add(4 * time.Minute).UnixMilli()}
	t0 := f.now()
	f.observe(dev, t0, sha("s"), reportOf(k1, unknown))
	if n := f.count(`SELECT count(*) FROM device_unknown_keys WHERE device_id = $1 AND fingerprint = $2`, dev, unknown.Fingerprint()); n != 1 {
		t.Fatalf("flagged %d", n)
	}
	// Reported again (changed generation field aside) it is audited once.
	f.observe(dev, t0.Add(time.Minute), sha("s"), reportOf(k1, unknown))
	f.observe(dev, t0.Add(2*time.Minute), sha("s"), reportOf(unknown, k1))
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'device.job_key_unknown' AND device_id = $1`, dev); n != 1 {
		t.Errorf("audited %d times", n)
	}
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'device.job_key_unknown' AND details->>'fingerprint' = $1`, unknown.Fingerprint()); n != 1 {
		t.Errorf("the record does not carry the fingerprint")
	}
	// The key the ring held is never flagged.
	if n := f.count(`SELECT count(*) FROM device_unknown_keys WHERE fingerprint = $1`, k1.Fingerprint()); n != 0 {
		t.Error("a key of the ring was flagged")
	}
	// The flag clears when the device no longer reports the key.
	f.observe(dev, t0.Add(3*time.Minute), sha("s"), reportOf(k1))
	if n := f.count(`SELECT count(*) FROM device_unknown_keys WHERE device_id = $1`, dev); n != 0 {
		t.Error("the flag stayed")
	}
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'device.job_key_unknown_cleared' AND device_id = $1`, dev); n != 1 {
		t.Errorf("clearing audited %d times", n)
	}
	// A key the ring did not hold when reported, loaded later (the next
	// periodic reload), stops being unknown.
	pub2, priv2, _ := ed25519.GenerateKey(rand.Reader)
	later := Key{Public: pub2, Generation: 5}
	f.observe(dev, t0.Add(4*time.Minute), sha("s"), reportOf(k1, later))
	if f.count(`SELECT count(*) FROM device_unknown_keys WHERE device_id = $1`, dev) != 1 {
		t.Fatal("not flagged")
	}
	sealed, _ := f.sealer.Seal(priv2.Seed(), aad(5))
	f.exec(`INSERT INTO job_keys (generation, public_key, sealed_seed, reason) VALUES (5, $1, $2, 'planned')`, []byte(pub2), sealed)
	if err := f.ring.Reload(f.ctx); err != nil {
		t.Fatal(err)
	}
	f.observe(dev, t0.Add(5*time.Minute), sha("s"), reportOf(k1, later, Key{Public: rogue, Generation: 9}))
	if n := f.count(`SELECT count(*) FROM device_unknown_keys WHERE device_id = $1`, dev); n != 1 {
		t.Errorf("flags %d, want only the rogue key's", n)
	}
}

func TestReloadsForUnknownKeysAreLimited(t *testing.T) {
	f := newFixture(t)
	rogue, _, _ := ed25519.GenerateKey(rand.Reader)
	reloadedAt := func() time.Time {
		f.ring.mu.RLock()
		defer f.ring.mu.RUnlock()
		return f.ring.lastReload
	}
	f.advance(ReloadOnUnknown)
	before := reloadedAt()
	if _, ok := f.ring.lookup(f.ctx, rogue); ok {
		t.Fatal("found a key it never held")
	}
	if !reloadedAt().After(before) {
		t.Fatal("a report of an unknown key did not reload the ring")
	}
	after := reloadedAt()
	// Remembered as unknown: repeated reports cause no more reloads, even a
	// moment later.
	f.advance(ReloadOnUnknown + time.Second)
	for i := 0; i < 5; i++ {
		f.ring.lookup(f.ctx, rogue)
	}
	if !reloadedAt().Equal(after) {
		t.Error("a key remembered as unknown caused another reload")
	}
	// Another unknown key within 5 seconds of the last reload does not reload.
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	f.ring.mu.Lock()
	f.ring.lastReload = f.now()
	f.ring.mu.Unlock()
	last := reloadedAt()
	f.ring.lookup(f.ctx, other)
	if !reloadedAt().Equal(last) {
		t.Error("two reloads within five seconds")
	}
	// The periodic reload forgets what was unknown.
	if err := f.ring.Reload(f.ctx); err != nil {
		t.Fatal(err)
	}
	f.ring.mu.RLock()
	n := len(f.ring.unknown)
	f.ring.mu.RUnlock()
	if n != 0 {
		t.Error("unknown keys survived a periodic reload")
	}
}

func TestTheKeyForADeviceFollowsItsReport(t *testing.T) {
	f := newFixture(t)
	k1 := f.ring.Newest()
	priv2, pub2 := f.addKey(f.now().UnixMilli(), true)
	k2, _ := f.ring.ByPublic(pub2)
	_ = priv2
	t0 := f.now()

	// A device that never reported: the key it was given, generation 1 for
	// devices enrolled before the ring.
	old := f.device("old")
	if c := f.choice(old); c.Key.Generation != 1 || c.NeedsRepinning {
		t.Fatalf("never reported: %+v", c)
	}
	f.exec(`UPDATE devices SET job_key_given_generation = $2 WHERE id = $1`, old, k2.Generation)
	if c := f.choice(old); c.Key.Generation != k2.Generation {
		t.Fatalf("given the newer key at enrollment: %d", c.Key.Generation)
	}

	// Trusting both: the newest of the report; trusting one: that one.
	both, one := f.device("both"), f.device("one")
	f.observe(both, t0, sha("a"), reportOf(k1, k2))
	f.observe(one, t0, sha("a"), reportOf(k1))
	if c := f.choice(both); c.Key.Generation != k2.Generation {
		t.Errorf("both: %d", c.Key.Generation)
	}
	if c := f.choice(one); c.Key.Generation != 1 {
		t.Errorf("one: %d", c.Key.Generation)
	}

	// The build changed since the report (an update or its rollback) and the
	// request carries none: the oldest key of the stored report.
	f.exec(`UPDATE devices SET agent_sha256 = $2 WHERE id = $1`, both, sha("b"))
	if c := f.choice(both); c.Key.Generation != 1 {
		t.Errorf("a build changed since the report: %d", c.Key.Generation)
	}
	// Until it reports again.
	f.observe(both, t0.Add(time.Minute), sha("b"), reportOf(k1, k2))
	if c := f.choice(both); c.Key.Generation != k2.Generation {
		t.Errorf("after reporting again: %d", c.Key.Generation)
	}

	// A cut-over sent to the new key: signed with it, until a later report
	// lacks it. When the build also changed since and the request carries no
	// report, the cut-over rule wins.
	moved := f.device("moved")
	f.observe(moved, t0, sha("a"), reportOf(k1, k2))
	f.exec(`UPDATE devices SET job_key_cutover_generation = $2, job_key_cutover_at = $3, agent_sha256 = $4 WHERE id = $1`,
		moved, k2.Generation, t0.Add(time.Minute), sha("new build"))
	if c := f.choice(moved); c.Key.Generation != k2.Generation {
		t.Errorf("cut-over and a changed build: %d", c.Key.Generation)
	}
	// A report before the cut-over was sent does not undo it (a poll opened earlier).
	f.observe(moved, t0.Add(30*time.Second), sha("a"), reportOf(k1))
	if c := f.choice(moved); c.Key.Generation != k2.Generation {
		t.Errorf("an older report undid the cut-over: %d", c.Key.Generation)
	}
	// A later report that lacks the key does.
	f.observe(moved, t0.Add(2*time.Minute), sha("new build"), reportOf(k1))
	if c := f.choice(moved); c.Key.Generation != 1 {
		t.Errorf("a later report lacking the key: %d", c.Key.Generation)
	}

	// A device that trusts no key the ring holds needs re-pinning.
	lost, _, _ := ed25519.GenerateKey(rand.Reader)
	stranded := f.device("stranded")
	f.observe(stranded, t0, sha("a"), reportOf(Key{Public: lost, Generation: 77}))
	if c := f.choice(stranded); !c.NeedsRepinning || c.Key.Generation != f.ring.Floor().Generation {
		t.Errorf("stranded: %+v", c)
	}
	// A key whose seed the ring deleted is not one it can sign with.
	_, gone := f.addKey(f.now().UnixMilli()+10, false)
	goneKey, _ := f.ring.ByPublic(gone)
	forgot := f.device("forgot")
	f.observe(forgot, t0, sha("a"), reportOf(goneKey))
	if c := f.choice(forgot); !c.NeedsRepinning {
		t.Errorf("a forgotten key: %+v", c)
	}
	// Mixed: a held key and a forgotten one: the held one.
	mixed := f.device("mixed")
	f.observe(mixed, t0, sha("a"), reportOf(k1, goneKey))
	if c := f.choice(mixed); c.NeedsRepinning || c.Key.Generation != 1 {
		t.Errorf("mixed: %+v", c)
	}
	// A device the server does not know is signed for like one that never reported.
	if c := f.choice(uuid.New()); c.Key.Generation != 1 {
		t.Errorf("unknown device: %+v", c)
	}
}

func TestRemovedDevicesAreSignedForByTheirLastReport(t *testing.T) {
	f := newFixture(t)
	k1 := f.ring.Newest()
	_, pub2 := f.addKey(f.now().UnixMilli(), true)
	k2, _ := f.ring.ByPublic(pub2)
	dev := f.device("gone")
	f.observe(dev, f.now(), sha("a"), reportOf(k1, k2))
	f.exec(`INSERT INTO retired_devices (device_id, organization_id, site_id, name, agent_public_key, expires_at)
		SELECT id, organization_id, site_id, name, agent_public_key, now() + interval '1 day' FROM devices WHERE id = $1`, dev)
	f.exec(`UPDATE retired_devices r SET job_keys_report = d.job_keys_report, job_keys_report_at = d.job_keys_report_at,
		job_keys_report_sha = d.job_keys_report_sha FROM devices d WHERE d.id = r.device_id AND r.device_id = $1`, dev)
	f.exec(`DELETE FROM devices WHERE id = $1`, dev)
	if c := f.choice(dev); c.Key.Generation != k2.Generation {
		t.Errorf("a removed device: %d", c.Key.Generation)
	}
}

func TestIssueRecordsWhatIsSignedAndOnlyOncePerKey(t *testing.T) {
	f := newFixture(t)
	dev := f.device("pc")
	k1 := f.ring.Newest()
	var key ed25519.PrivateKey
	f.tx(func(tx pgx.Tx) (err error) {
		key, _, err = f.ring.Issue(f.ctx, tx, dev, agentproto.InstructionJob, "run-1")
		return err
	})
	if !key.Public().(ed25519.PublicKey).Equal(k1.Public) {
		t.Fatal("signed with another key")
	}
	f.tx(func(tx pgx.Tx) error {
		_, _, err := f.ring.Issue(f.ctx, tx, dev, agentproto.InstructionJob, "run-1")
		return err
	})
	if n := f.count(`SELECT count(*) FROM issued_instructions WHERE device_id = $1 AND kind = 'job' AND instruction_id = 'run-1' AND generation = 1`, dev); n != 1 {
		t.Errorf("a redelivery with the same key recorded %d rows", n)
	}
	// A redelivery signed with another key adds a row.
	_, pub2 := f.addKey(f.now().UnixMilli(), true)
	k2, _ := f.ring.ByPublic(pub2)
	f.observe(dev, f.now(), sha("a"), reportOf(k1, k2))
	f.tx(func(tx pgx.Tx) error {
		_, _, err := f.ring.Issue(f.ctx, tx, dev, agentproto.InstructionJob, "run-1")
		return err
	})
	if n := f.count(`SELECT count(*) FROM issued_instructions WHERE device_id = $1 AND instruction_id = 'run-1'`, dev); n != 2 {
		t.Errorf("rows %d", n)
	}
	// Rolled back with the transaction that signs: nothing leaves unrecorded
	// and nothing is recorded that did not leave.
	err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
		if _, _, err := f.ring.Issue(f.ctx, tx, dev, agentproto.InstructionJob, "run-2"); err != nil {
			return err
		}
		return context.Canceled
	})
	if err == nil || f.count(`SELECT count(*) FROM issued_instructions WHERE instruction_id = 'run-2'`) != 0 {
		t.Error("a rolled back signing left a row")
	}
	// A long ID is bounded.
	f.tx(func(tx pgx.Tx) error {
		_, _, err := f.ring.Issue(f.ctx, tx, dev, agentproto.InstructionDownload, strings.Repeat("n", 500))
		return err
	})
	// Purge keeps 90 days.
	f.exec(`INSERT INTO issued_instructions (kind, instruction_id, device_id, generation, issued_at) VALUES ('job', 'old-run', $1, 1, now() - interval '91 days')`, dev)
	if err := f.ring.Purge(f.ctx); err != nil {
		t.Fatal(err)
	}
	if n := f.count(`SELECT count(*) FROM issued_instructions WHERE instruction_id = 'old-run'`); n != 0 {
		t.Errorf("a row older than 90 days survived the purge: %d", n)
	}
	if n := f.count(`SELECT count(*) FROM issued_instructions WHERE instruction_id = 'run-1'`); n != 2 {
		t.Errorf("after the purge: %d", n)
	}
	// The ring signs for no device with a key it does not hold.
	f.exec(`UPDATE job_keys SET sealed_seed = NULL, seed_deleted_at = now()`)
	if err := f.ring.Reload(f.ctx); err != nil {
		t.Fatal(err)
	}
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
		_, _, err := f.ring.Issue(f.ctx, tx, dev, agentproto.InstructionJob, "run-3")
		return err
	}); err == nil {
		t.Error("signed with no seed")
	}
}

func TestNextGenerationIsAboveTheRingAndWhatDevicesReportWithinTheBound(t *testing.T) {
	f := newFixture(t)
	now := f.now()
	next := func() int64 {
		var g int64
		f.tx(func(tx pgx.Tx) (err error) { g, err = f.ring.NextGeneration(f.ctx, tx, now); return err })
		return g
	}
	if g := next(); g != now.UnixMilli() {
		t.Errorf("the time in milliseconds: %d", g)
	}
	// The ring's highest plus one beats a clock that went backwards.
	f.addKey(now.UnixMilli()+100, true)
	if g := next(); g != now.UnixMilli()+101 {
		t.Errorf("the ring's term: %d", g)
	}
	// A device reports a key the ring never held, four minutes ahead: flagged,
	// and the next generation is above it.
	dev := f.device("pc")
	rogue, _, _ := ed25519.GenerateKey(rand.Reader)
	ahead := now.Add(4 * time.Minute).UnixMilli()
	f.observe(dev, now, sha("a"), reportOf(f.ring.Newest(), Key{Public: rogue, Generation: ahead}))
	if f.count(`SELECT count(*) FROM device_unknown_keys WHERE device_id = $1`, dev) != 1 {
		t.Fatal("not flagged")
	}
	if g := next(); g != ahead+1 {
		t.Errorf("above the reported key: %d, want %d", g, ahead+1)
	}
	// A report an hour ahead is flagged too and lies outside the bound.
	dev2 := f.device("pc2")
	rogue2, _, _ := ed25519.GenerateKey(rand.Reader)
	f.observe(dev2, now, sha("a"), reportOf(f.ring.Newest(), Key{Public: rogue2, Generation: now.Add(time.Hour).UnixMilli()}))
	if f.count(`SELECT count(*) FROM device_unknown_keys WHERE device_id = $1`, dev2) != 1 {
		t.Fatal("an hour ahead is not flagged")
	}
	if g := next(); g != ahead+1 {
		t.Errorf("a report outside the bound moved the next generation: %d", g)
	}
	// Removed devices count too.
	removed := ahead + 30_000
	f.exec(`INSERT INTO retired_devices (device_id, organization_id, site_id, name, expires_at, job_keys_report)
		VALUES (gen_random_uuid(), $1, $2, 'r', now() + interval '1 day', $3)`, f.org, f.site,
		[]byte(`[{"key":"AAAA","generation":`+itoa(removed)+`}]`))
	if g := next(); g != removed+1 {
		t.Errorf("a removed device's report: %d", g)
	}
}

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func TestRefusedStatementsAreAuditedOncePerDeviceAndID(t *testing.T) {
	f := newFixture(t)
	dev := f.device("pc")
	o := Observation{Device: dev, Org: f.org, Site: f.site, Label: "pc"}
	ref := agentproto.KeyRefusal{Statement: agentproto.InstructionHandover, ID: "s-1", Reason: strings.Repeat("r", 500)}
	for i := 0; i < 3; i++ {
		f.tx(func(tx pgx.Tx) error { return f.ring.RefusedStatement(f.ctx, tx, o, ref) })
	}
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'device.job_key_refused' AND device_id = $1`, dev); n != 1 {
		t.Fatalf("audited %d times", n)
	}
	var reason string
	f.tx(func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT details->>'reason' FROM audit_log WHERE action = 'device.job_key_refused'`).Scan(&reason)
	})
	if len(reason) != agentproto.MaxKeyRefusal {
		t.Errorf("reason length %d", len(reason))
	}
	// Another statement is another record; junk is not recorded.
	f.tx(func(tx pgx.Tx) error {
		if err := f.ring.RefusedStatement(f.ctx, tx, o, agentproto.KeyRefusal{Statement: agentproto.InstructionCutover, ID: "s-2", Reason: "r"}); err != nil {
			return err
		}
		if err := f.ring.RefusedStatement(f.ctx, tx, o, agentproto.KeyRefusal{Statement: "job", ID: "s-3"}); err != nil {
			return err
		}
		return f.ring.RefusedStatement(f.ctx, tx, o, agentproto.KeyRefusal{Statement: agentproto.InstructionCutover, ID: strings.Repeat("x", 80)})
	})
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'device.job_key_refused'`); n != 2 {
		t.Errorf("records %d", n)
	}
}

func TestObserveStoresTheAuthoritiesSortedBoundedAndOnlyWhenTheyChange(t *testing.T) {
	f := newFixture(t)
	dev := f.device("pc")
	obs := func(at time.Time, auth []string) {
		f.tx(func(tx pgx.Tx) error {
			return f.ring.Observe(f.ctx, tx, Observation{Device: dev, Org: f.org, Site: f.site, Authorities: auth, SignedAt: at})
		})
	}
	t0 := f.now()
	obs(t0, []string{"b", "a", "b"})
	var got []string
	var at time.Time
	f.tx(func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT agent_authorities, agent_authorities_at FROM devices WHERE id = $1`, dev).Scan(&got, &at)
	})
	if len(got) != 2 || got[0] != "a" || got[1] != "b" || !at.Equal(t0) {
		t.Fatalf("authorities %v at %v", got, at)
	}
	obs(t0.Add(time.Minute), []string{"a", "b"})
	f.tx(func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT agent_authorities_at FROM devices WHERE id = $1`, dev).Scan(&at)
	})
	if !at.Equal(t0) {
		t.Errorf("an unchanged list was written again: %v", at)
	}
	many := make([]string, agentproto.MaxKeyReportAuthorities+5)
	for i := range many {
		many[i] = sha(string(rune('A' + i)))
	}
	obs(t0.Add(2*time.Minute), many)
	var n int
	f.tx(func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT cardinality(agent_authorities) FROM devices WHERE id = $1`, dev).Scan(&n)
	})
	if n != agentproto.MaxKeyReportAuthorities {
		t.Errorf("%d authorities kept", n)
	}
}

func TestRingAccessorsAndFloor(t *testing.T) {
	f := newFixture(t)
	k1 := f.ring.Newest()
	if k, ok := f.ring.ByGeneration(1); !ok || !k.Public.Equal(k1.Public) {
		t.Error("ByGeneration")
	}
	if _, ok := f.ring.ByGeneration(99); ok {
		t.Error("found a generation that does not exist")
	}
	if _, ok := f.ring.ByFingerprint(k1.Fingerprint()); !ok {
		t.Error("ByFingerprint")
	}
	if _, ok := f.ring.ByFingerprint("0000"); ok {
		t.Error("found a fingerprint that does not exist")
	}
	// The floor is the newest key cut over to; the newest key is not
	// necessarily the floor.
	_, pub2 := f.addKey(f.now().UnixMilli(), true)
	k2, _ := f.ring.ByPublic(pub2)
	if f.ring.Newest().Generation != k2.Generation || f.ring.Floor().Generation != 1 {
		t.Errorf("newest %d floor %d", f.ring.Newest().Generation, f.ring.Floor().Generation)
	}
	f.exec(`UPDATE job_keys SET cut_over_at = now() WHERE generation = $1`, k2.Generation)
	if err := f.ring.Reload(f.ctx); err != nil {
		t.Fatal(err)
	}
	if f.ring.Floor().Generation != k2.Generation {
		t.Errorf("floor %d", f.ring.Floor().Generation)
	}
	// A seed that does not match its public key is not loaded.
	f.exec(`UPDATE job_keys SET public_key = decode(repeat('ab', 32), 'hex') WHERE generation = 1`)
	if err := f.ring.Reload(f.ctx); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Errorf("a seed that does not match: %v", err)
	}
	// A seed that is not a seed.
	g := newFixture(t)
	bad, _ := g.sealer.Seal([]byte("short"), aad(1))
	g.exec(`UPDATE job_keys SET sealed_seed = $1 WHERE generation = 1`, bad)
	if err := g.ring.Reload(g.ctx); err == nil || !strings.Contains(err.Error(), "not an Ed25519 seed") {
		t.Errorf("a short seed: %v", err)
	}
	// A lost key's seed is kept sealed and not opened: the ring starts with it.
	h := newFixture(t)
	h.exec(`UPDATE job_keys SET lost_at = now(), sealed_seed = 'not a sealed value' WHERE generation = 1`)
	if err := h.ring.Reload(h.ctx); err != nil {
		t.Errorf("a lost key's seed was opened: %v", err)
	}
	if h.ring.Newest().Held() {
		t.Error("a lost key is held")
	}
}

func TestRingWithoutAuditStillRecords(t *testing.T) {
	f := newFixture(t)
	r, err := Open(f.ctx, f.db, f.sealer, quiet(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	dev := f.device("pc")
	rogue, _, _ := ed25519.GenerateKey(rand.Reader)
	f.tx(func(tx pgx.Tx) error {
		return r.Observe(f.ctx, tx, Observation{Device: dev, Keys: reportOf(r.Newest(), Key{Public: rogue, Generation: 5}), SignedAt: f.now()})
	})
	if f.count(`SELECT count(*) FROM device_unknown_keys WHERE device_id = $1`, dev) != 1 {
		t.Error("not flagged")
	}
	if f.count(`SELECT count(*) FROM audit_log WHERE action = 'device.job_key_unknown'`) != 0 {
		t.Error("audited with no audit log")
	}
}
