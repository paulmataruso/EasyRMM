//go:build integration

package tlsaddname_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/pki"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
	"github.com/paulmataruso/easyrmm/server/internal/tlsaddname"
	"github.com/paulmataruso/easyrmm/server/internal/tlscert"
	"github.com/paulmataruso/easyrmm/server/internal/tlsmove"
	"github.com/paulmataruso/easyrmm/server/internal/tlstrust"
)

const (
	console = "rmm.example.com"
	mesh    = "mesh.rmm.example.com"
)

type certs struct{}

func (certs) Prepare(context.Context, string, string) (tlsmove.Prepared, error) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: console}, DNSNames: []string{console},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	return tlsmove.Prepared{Chain: [][]byte{der}}, err
}
func (certs) Swap(context.Context, string, string) error      { return nil }
func (certs) SwapDelay(context.Context, string) time.Duration { return 0 }

type asker struct {
	mu    sync.Mutex
	asked []tlstrust.Target
	ids   [][]uuid.UUID
}

func (a *asker) Ask(_ context.Context, ids []uuid.UUID, t tlstrust.Target, _ bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.asked, a.ids = append(a.asked, t), append(a.ids, ids)
	return nil
}

type notices struct {
	mu     sync.Mutex
	events []tlscert.Event
}

func (n *notices) Publish(_ context.Context, e tlscert.Event) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.events = append(n.events, e)
	return nil
}
func (n *notices) last() tlscert.Event {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.events[len(n.events)-1]
}

type resolver map[string][]string

func (r resolver) LookupIPAddr(_ context.Context, h string) ([]net.IPAddr, error) {
	ips, ok := r[h]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: h, IsNotFound: true}
	}
	var out []net.IPAddr
	for _, s := range ips {
		out = append(out, net.IPAddr{IP: net.ParseIP(s)})
	}
	return out, nil
}

type fixture struct {
	t       *testing.T
	ctx     context.Context
	db      *database.DB
	svc     *tlsaddname.Service
	moves   *tlsmove.Service
	ca      *pki.Authority
	asker   *asker
	notices *notices
	actor   audit.Actor
	now     time.Time
	dns     resolver
	fetchOK bool
	held    bool
	ipInst  bool
	trusts  []bool
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	inst := testdb.New(t)
	ca, err := pki.New()
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	au := audit.New(inst.DB, nil)
	f := &fixture{t: t, ctx: context.Background(), db: inst.DB, ca: ca, asker: &asker{}, notices: &notices{}, now: time.Now(),
		dns: resolver{console: {"203.0.113.10"}, mesh: {"203.0.113.10"}}, fetchOK: true, ipInst: true}
	f.moves = tlsmove.New(tlsmove.Deps{DB: inst.DB, Audit: au, Certs: certs{}, Trust: f.asker, Log: log})
	var svc *tlsaddname.Service
	svc = tlsaddname.New(tlsaddname.Deps{
		DB: inst.DB, Audit: au, Moves: f.moves, Trust: f.asker, Auth: ca, Notices: f.notices, Log: log,
		IPInstall: func() bool { return f.ipInst },
		ServerIPs: func(context.Context) []net.IP { return []net.IP{net.ParseIP("203.0.113.10")} },
		Held:      func(context.Context, string) bool { return f.held },
		Resolver:  f.dns,
		Fetch: func(context.Context, string) (string, error) {
			if !f.fetchOK {
				return "", errors.New("connection timed out")
			}
			return svc.Token(), nil
		},
		OnTrust: func(_, _ string, trusted bool) { f.trusts = append(f.trusts, trusted) },
		Now:     func() time.Time { return f.now },
	})
	f.svc = svc
	uid := f.id(`INSERT INTO users (email, display_name) VALUES ('s@example.com', 's') RETURNING id`)
	f.actor = audit.Actor{Type: audit.ActorUser, ID: uid, Label: "s@example.com"}
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

func (f *fixture) device(org uuid.UUID, seenAgo time.Duration) uuid.UUID {
	f.t.Helper()
	site := f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, gen_random_uuid()::text) RETURNING id`, org)
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	id := f.id(`INSERT INTO devices (organization_id, site_id, name, hostname, platform, agent_public_key, enrolled_at, agent_last_seen_at)
		VALUES ($1, $2, 'pc', 'pc', 'linux', $3, now() - interval '90 days', now() - $4::interval) RETURNING id`, org, site, key, seenAgo.String())
	// Enrolled through the IP address, which is the origin it reports: the
	// added name's own move has no device to wait for.
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
		_, e := tx.Exec(f.ctx, `INSERT INTO device_tls_state (device_id, origin) VALUES ($1, '203.0.113.10')`, id)
		return e
	}); err != nil {
		f.t.Fatal(err)
	}
	return id
}

func (f *fixture) org(name string) uuid.UUID {
	return f.id(`INSERT INTO organizations (name) VALUES ($1) RETURNING id`, name)
}

func (f *fixture) count(sql string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error { return tx.QueryRow(f.ctx, sql, args...).Scan(&n) }); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func TestAddNameFlow(t *testing.T) {
	f := newFixture(t)
	org := f.org("Acme")
	dev := f.device(org, time.Hour)
	f.device(org, 60*24*time.Hour) // not seen in 30 days: not asked

	if !f.svc.Eligible(f.ctx) {
		t.Fatal("an IP install without a pair is eligible")
	}
	// A name that does not point here is refused, and nothing is recorded.
	f.dns[mesh] = []string{"198.51.100.1"}
	if err := f.svc.Add(f.ctx, f.actor, console, mesh); !errors.Is(err, tlsaddname.ErrNotReachable) {
		t.Fatalf("a name pointing elsewhere: %v", err)
	}
	if n := f.count(`SELECT count(*) FROM tls_added_names`); n != 0 {
		t.Fatalf("%d rows after a refused add", n)
	}
	f.dns[mesh] = []string{"203.0.113.10"}

	if err := f.svc.Add(f.ctx, f.actor, console, ""); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Add(f.ctx, f.actor, "other.example.com", ""); !errors.Is(err, tlsaddname.ErrExists) {
		t.Fatalf("a second pair: %v", err)
	}
	// Both names were moved to Let's Encrypt (waiting for devices: none here).
	f.moves.Tick(f.ctx)
	for _, n := range []string{console, mesh} {
		if got := f.moves.Served(n); got != tlsmove.SourceACME {
			t.Errorf("%s served from %q, want acme", n, got)
		}
	}
	// Agents inside the scope, seen recently, were asked to verify the
	// authority's second certificate for each name.
	if len(f.asker.asked) != 2 {
		t.Fatalf("asked %d times", len(f.asker.asked))
	}
	for i, ids := range f.asker.ids {
		if len(ids) != 1 || ids[0] != dev {
			t.Errorf("ask %d went to %v", i, ids)
		}
	}
	ch := f.asker.asked[0].Chains[0].DER
	leaf, err := x509.ParseCertificate(ch[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.IPAddresses) != 0 || len(leaf.DNSNames) != 2 {
		t.Errorf("the second certificate must carry the added names only: %v %v", leaf.DNSNames, leaf.IPAddresses)
	}
	if !f.svc.IsAdded(mesh) || f.svc.Trusted(console) {
		t.Error("an added name is known and not trusted yet")
	}

	// Not held, reachable: still pending.
	f.svc.Tick(f.ctx)
	p, err := f.svc.Status(f.ctx)
	if err != nil || p.State != tlsaddname.StatePending || !p.Reachable {
		t.Fatalf("%+v %v", p, err)
	}
	// Held and reachable: trusted, once.
	f.held = true
	f.now = f.now.Add(2 * time.Hour)
	f.svc.Tick(f.ctx)
	p, _ = f.svc.Status(f.ctx)
	if p.State != tlsaddname.StateTrusted || p.TrustedAt == nil || !f.svc.Trusted(console) {
		t.Fatalf("%+v", p)
	}
	if len(f.trusts) != 1 || !f.trusts[0] {
		t.Fatalf("OnTrust calls: %v", f.trusts)
	}
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action IN ('tls.name_added', 'tls.name_trusted')`); n != 2 {
		t.Errorf("%d audit rows", n)
	}

	// The fetch fails and no browser has confirmed: a warning opens, and the
	// pair stays trusted through the grace period.
	f.fetchOK = false
	f.now = f.now.Add(2 * time.Hour)
	f.svc.Tick(f.ctx)
	if e := f.notices.last(); !e.Open || e.Severity != "warning" || e.Key != "tls:"+console {
		t.Fatalf("notice: %+v", e)
	}
	if p, _ = f.svc.Status(f.ctx); p.State != tlsaddname.StateTrusted {
		t.Fatalf("a failure inside the grace period must not end trust: %+v", p)
	}
	// A browser through the name counts as proof and clears the warning.
	if err := f.svc.BrowserConfirm(f.ctx, console+":443"); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(2 * time.Hour)
	f.svc.Tick(f.ctx)
	if e := f.notices.last(); e.Open {
		t.Fatalf("a browser confirmation resolves the warning: %+v", e)
	}
	// Past the grace period with neither proof, trust ends and the name
	// keeps only its agent route.
	f.now = f.now.Add(8 * 24 * time.Hour)
	f.svc.Tick(f.ctx)
	p, _ = f.svc.Status(f.ctx)
	if p.State != tlsaddname.StateUntrusted || f.svc.Trusted(console) || !f.svc.IsAdded(console) {
		t.Fatalf("%+v", p)
	}
	if _, err := f.svc.SecondCertificate(); err != nil {
		t.Fatalf("the agent route keeps the second certificate: %v", err)
	}
	if len(f.trusts) != 2 || f.trusts[1] {
		t.Fatalf("OnTrust calls: %v", f.trusts)
	}

	// Remove drops the pair and moves the names back.
	if err := f.svc.Remove(f.ctx, f.actor); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Status(f.ctx); !errors.Is(err, tlsaddname.ErrNone) || f.svc.IsAdded(console) {
		t.Fatalf("status after remove: %v", err)
	}
	if !f.svc.Eligible(f.ctx) {
		t.Error("eligible again after remove")
	}
}

func TestAddNameDevScopeAndGuards(t *testing.T) {
	f := newFixture(t)
	in, out := f.org("In"), f.org("Out")
	dev := f.device(in, time.Hour)
	f.device(out, time.Hour)
	defer devscope.Set(in)()

	f.ipInst = false
	if err := f.svc.Add(f.ctx, f.actor, console, ""); !errors.Is(err, tlsaddname.ErrNotIPInstall) {
		t.Fatalf("a DNS install: %v", err)
	}
	f.ipInst = true
	if err := f.svc.Add(f.ctx, f.actor, "rmm.example.com", "mesh.other.org"); !errors.Is(err, tlsaddname.ErrNotSameSite) {
		t.Fatalf("another site: %v", err)
	}
	if err := f.svc.Add(f.ctx, f.actor, console, mesh); err != nil {
		t.Fatal(err)
	}
	for i, ids := range f.asker.ids {
		if len(ids) != 1 || ids[0] != dev {
			t.Errorf("ask %d reached devices outside the development scope: %v", i, ids)
		}
	}
}

func TestResolverFailureIsNotReachable(t *testing.T) {
	f := newFixture(t)
	delete(f.dns, console)
	if err := f.svc.Add(f.ctx, f.actor, console, mesh); !errors.Is(err, tlsaddname.ErrNotReachable) {
		t.Fatalf("%v", err)
	}
}
