//go:build integration

package tlsmove_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/jobkeys"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
	"github.com/paulmataruso/easyrmm/server/internal/tlsmove"
	"github.com/paulmataruso/easyrmm/server/internal/tlstrust"
)

const name = "rmm.example.com"

// certs is a Certs whose target chain and mesh delay a test sets.
type certs struct {
	mu     sync.Mutex
	chain  [][]byte
	delay  time.Duration
	swaps  []string
	failed error
}

func (c *certs) Prepare(_ context.Context, _, _ string) (tlsmove.Prepared, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return tlsmove.Prepared{Chain: c.chain, Notes: []string{"trial skipped"}}, c.failed
}
func (c *certs) Swap(_ context.Context, n, t string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.swaps = append(c.swaps, n+">"+t)
	return nil
}
func (c *certs) SwapDelay(context.Context, string) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.delay
}

type fixture struct {
	t     *testing.T
	ctx   context.Context
	db    *database.DB
	trust *tlstrust.Service
	svc   *tlsmove.Service
	certs *certs
	pub   ed25519.PublicKey
	org   uuid.UUID
	site  uuid.UUID
	actor audit.Actor
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	inst := testdb.New(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	au := audit.New(inst.DB, nil)
	f := &fixture{t: t, ctx: context.Background(), db: inst.DB, pub: pub, certs: &certs{}}
	f.trust = tlstrust.New(inst.DB, au, jobkeys.Static(priv), log)
	f.svc = tlsmove.New(tlsmove.Deps{DB: inst.DB, Audit: au, Certs: f.certs, Trust: f.trust, Log: log})
	f.org = f.id(`INSERT INTO organizations (name) VALUES ('Acme') RETURNING id`)
	f.site = f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'HQ') RETURNING id`, f.org)
	uid := f.id(`INSERT INTO users (email, display_name) VALUES ('s@example.com', 's') RETURNING id`)
	f.actor = audit.Actor{Type: audit.ActorUser, ID: uid, Label: "s@example.com"}
	f.certs.chain = [][]byte{cert(t)}
	return f
}

func cert(t *testing.T) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func (f *fixture) id(sql string, args ...any) uuid.UUID {
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

// device makes an enrolled device whose agent announced the name as its
// origin, seen seenAgo ago.
func (f *fixture) device(host string, seenAgo time.Duration, org uuid.UUID) tlstrust.Device {
	f.t.Helper()
	site := f.site
	if org != f.org {
		site = f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'HQ') RETURNING id`, org)
	}
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	id := f.id(`INSERT INTO devices (organization_id, site_id, name, hostname, platform, agent_public_key, enrolled_at, agent_last_seen_at)
		VALUES ($1, $2, $3, $3, 'linux', $4, now() - interval '90 days', now() - $5::interval) RETURNING id`, org, site, host, key, seenAgo.String())
	d := tlstrust.Device{ID: id, Org: org, Site: site, Hostname: host, Platform: "linux"}
	f.beat(d, nil)
	return d
}

func (f *fixture) beat(d tlstrust.Device, report func(*agentproto.TrustPayload) *agentproto.TrustReport) {
	f.t.Helper()
	b := tlstrust.Beat{Origin: name, IP: netip.MustParseAddr("192.0.2.10"), Caps: []string{agentproto.CapTrust}, AgentSHA256: "aaa"}
	s := f.trust.Heartbeat(f.ctx, d, b)
	if s == nil || report == nil {
		return
	}
	p, err := agentproto.VerifyTrust(f.pub, *s, d.ID.String(), name, time.Now())
	if err != nil {
		f.t.Fatal(err)
	}
	b.Report = report(&p)
	f.trust.Heartbeat(f.ctx, d, b)
}

func answer(ok bool, msg string) func(*agentproto.TrustPayload) *agentproto.TrustReport {
	return func(p *agentproto.TrustPayload) *agentproto.TrustReport {
		r := &agentproto.TrustReport{ID: p.ID, Trusts: "system"}
		for _, c := range p.Chains {
			r.Results = append(r.Results, agentproto.TrustResult{Chain: c.ID, Scope: agentproto.TrustScopeAgent, OK: ok, Error: msg})
		}
		return r
	}
}

func (f *fixture) source() string {
	f.t.Helper()
	s, err := f.svc.Source(f.ctx, name)
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}

func TestAMoveWaitsForEveryDeviceThenSwaps(t *testing.T) {
	f := newFixture(t)
	a := f.device("pc-a", time.Minute, f.org)
	b := f.device("pc-b", time.Minute, f.org)
	if err := f.svc.Start(f.ctx, f.actor, name, tlsmove.SourceACME); err != nil {
		t.Fatal(err)
	}
	if f.source() != tlsmove.SourceEnv {
		t.Fatal("the source changed before any device verified")
	}
	if err := f.svc.Start(f.ctx, f.actor, name, tlsmove.SourceAuthority); !errors.Is(err, tlsmove.ErrMoveActive) {
		t.Fatalf("a second move = %v", err)
	}
	p, err := f.svc.Progress(f.ctx, name)
	if err != nil || p.Waiting != 2 || len(p.Devices) != 2 || p.Target != tlsmove.SourceACME {
		t.Fatalf("progress = %+v, %v", p, err)
	}
	f.beat(a, answer(true, ""))
	f.svc.Tick(f.ctx)
	if f.source() != tlsmove.SourceEnv {
		t.Fatal("swapped with one device not reported")
	}
	f.beat(b, answer(true, ""))
	f.svc.Tick(f.ctx)
	if f.source() != tlsmove.SourceACME || f.svc.Served(name) != tlsmove.SourceACME {
		t.Fatalf("source = %s, served = %s", f.source(), f.svc.Served(name))
	}
	if len(f.certs.swaps) != 1 {
		t.Errorf("swaps = %v", f.certs.swaps)
	}
	if _, err := f.svc.Progress(f.ctx, name); !errors.Is(err, tlsmove.ErrNoMove) {
		t.Errorf("progress after the swap = %v", err)
	}
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'tls.source_change'`); n != 2 {
		t.Errorf("%d audit rows, want requested and completed", n)
	}
	// And back, with the same flow.
	if err := f.svc.Start(f.ctx, f.actor, name, tlsmove.SourceEnv); err != nil {
		t.Fatal(err)
	}
	f.beat(a, answer(true, ""))
	f.beat(b, answer(true, ""))
	f.svc.Tick(f.ctx)
	if f.source() != tlsmove.SourceEnv {
		t.Errorf("moving back left source = %s", f.source())
	}
}

func TestAFailedDeviceBlocksAndShowsItsError(t *testing.T) {
	f := newFixture(t)
	a := f.device("pc-a", time.Minute, f.org)
	if err := f.svc.Start(f.ctx, f.actor, name, tlsmove.SourceACME); err != nil {
		t.Fatal(err)
	}
	f.beat(a, answer(false, "x509: certificate signed by unknown authority"))
	f.svc.Tick(f.ctx)
	p, _ := f.svc.Progress(f.ctx, name)
	if f.source() != tlsmove.SourceEnv || p.Waiting != 1 || p.Devices[0].State != "failed" || p.Devices[0].Error == "" {
		t.Fatalf("source = %s, progress = %+v", f.source(), p)
	}
}

func TestADeviceNotSeenForThirtyDaysDoesNotBlock(t *testing.T) {
	f := newFixture(t)
	a := f.device("pc-a", time.Minute, f.org)
	f.device("pc-old", 40*24*time.Hour, f.org)
	if err := f.svc.Start(f.ctx, f.actor, name, tlsmove.SourceAuthority); err != nil {
		t.Fatal(err)
	}
	p, _ := f.svc.Progress(f.ctx, name)
	stale := 0
	for _, d := range p.Devices {
		if d.State == "stale" {
			stale++
		}
	}
	if stale != 1 || p.Waiting != 1 {
		t.Fatalf("progress = %+v", p)
	}
	f.beat(a, answer(true, ""))
	f.svc.Tick(f.ctx)
	if f.source() != tlsmove.SourceAuthority {
		t.Fatal("a stale device blocked the move")
	}
}

func TestCancelChangesNothing(t *testing.T) {
	f := newFixture(t)
	f.device("pc-a", time.Minute, f.org)
	if err := f.svc.Cancel(f.ctx, f.actor, name); !errors.Is(err, tlsmove.ErrNoMove) {
		t.Fatalf("cancel with no move = %v", err)
	}
	if err := f.svc.Start(f.ctx, f.actor, name, tlsmove.SourceACME); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Cancel(f.ctx, f.actor, name); err != nil {
		t.Fatal(err)
	}
	f.svc.Tick(f.ctx)
	if f.source() != tlsmove.SourceEnv || len(f.certs.swaps) != 0 {
		t.Fatalf("source = %s, swaps = %v", f.source(), f.certs.swaps)
	}
	if n := f.count(`SELECT count(*) FROM device_tls_trust WHERE purpose = 'target'`); n != 0 {
		t.Errorf("%d target rows left", n)
	}
	if err := f.svc.Start(f.ctx, f.actor, name, tlsmove.SourceEnv); !errors.Is(err, tlsmove.ErrSameSource) {
		t.Errorf("a move to the current source = %v", err)
	}
	if err := f.svc.Start(f.ctx, f.actor, name, "nowhere"); !errors.Is(err, tlsmove.ErrBadSource) {
		t.Errorf("a bad source = %v", err)
	}
}

func TestAMeshNameWaitsForMeshCentralsRead(t *testing.T) {
	f := newFixture(t)
	a := f.device("pc-a", time.Minute, f.org)
	if err := f.svc.Start(f.ctx, f.actor, name, tlsmove.SourceACME); err != nil {
		t.Fatal(err)
	}
	f.beat(a, answer(true, ""))
	f.certs.mu.Lock()
	f.certs.delay = 2 * time.Minute
	f.certs.mu.Unlock()
	f.svc.Tick(f.ctx)
	if f.source() != tlsmove.SourceEnv {
		t.Fatal("swapped inside MeshCentral's wait")
	}
	f.certs.mu.Lock()
	f.certs.delay = 0
	f.certs.mu.Unlock()
	f.svc.Tick(f.ctx)
	if f.source() != tlsmove.SourceACME {
		t.Fatal("did not swap after the wait")
	}
}

func TestADeviceOutsideTheDevScopeBlocksAndIsNotAsked(t *testing.T) {
	f := newFixture(t)
	other := f.id(`INSERT INTO organizations (name) VALUES ('Globex') RETURNING id`)
	t.Cleanup(devscope.Set(f.org))
	d := f.device("pc-other", time.Minute, other)
	if err := f.svc.Start(f.ctx, f.actor, name, tlsmove.SourceACME); err != nil {
		t.Fatal(err)
	}
	if n := f.count(`SELECT count(*) FROM device_tls_trust WHERE device_id = $1`, d.ID); n != 0 {
		t.Errorf("a device outside the scope was asked (%d rows)", n)
	}
	p, _ := f.svc.Progress(f.ctx, name)
	if p.Waiting != 1 || p.Devices[0].State != "outside_scope" {
		t.Fatalf("progress = %+v", p)
	}
	f.svc.Tick(f.ctx)
	if f.source() != tlsmove.SourceEnv {
		t.Fatal("swapped with a device outside the scope unverified")
	}
}

func TestAFailedPrepareLeavesNoMove(t *testing.T) {
	f := newFixture(t)
	f.certs.failed = errors.New("CAA forbids it")
	if err := f.svc.Start(f.ctx, f.actor, name, tlsmove.SourceACME); err == nil {
		t.Fatal("start succeeded")
	}
	if n := f.count(`SELECT count(*) FROM tls_names`); n != 0 {
		t.Errorf("%d rows after a refused move", n)
	}
}
