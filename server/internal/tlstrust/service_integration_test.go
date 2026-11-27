//go:build integration

package tlstrust_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"log/slog"
	"math/big"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/jobkeys"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
	"github.com/paulmataruso/easyrmm/server/internal/tlstrust"
)

const origin = "rmm.example.com"

type source struct {
	mu     sync.Mutex
	chains map[string][]tlstrust.Chain
}

func (s *source) Chains(host string) []tlstrust.Chain {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.chains[host]
}

func (s *source) set(host string, c ...tlstrust.Chain) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.chains == nil {
		s.chains = map[string][]tlstrust.Chain{}
	}
	s.chains[host] = c
}

type fixture struct {
	t     *testing.T
	ctx   context.Context
	db    *database.DB
	svc   *tlstrust.Service
	src   *source
	pub   ed25519.PublicKey
	org   uuid.UUID
	site  uuid.UUID
	other uuid.UUID
	super access.Caller
	dev   tlstrust.Device
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	inst := testdb.New(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	f := &fixture{t: t, ctx: context.Background(), db: inst.DB, pub: pub, src: &source{}}
	f.svc = tlstrust.New(inst.DB, audit.New(inst.DB, nil), jobkeys.Static(priv), slog.New(slog.NewTextHandler(io.Discard, nil)))
	f.svc.SetSource(f.src)
	f.org = f.id(`INSERT INTO organizations (name) VALUES ('Acme') RETURNING id`)
	f.site = f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'HQ') RETURNING id`, f.org)
	f.other = f.id(`INSERT INTO organizations (name) VALUES ('Globex') RETURNING id`)
	f.super = f.user("super@example.com", rbac.Assignment{Role: rbac.RoleSuperAdmin})
	f.dev = f.device("pc-1", "linux", true)
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

func (f *fixture) device(name, platform string, online bool) tlstrust.Device {
	f.t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	seen := "now()"
	if !online {
		seen = "now() - interval '40 days'"
	}
	id := f.id(`INSERT INTO devices (organization_id, site_id, name, hostname, platform, agent_public_key, enrolled_at, agent_last_seen_at)
		VALUES ($1, $2, $3, $3, $4, $5, now() - interval '60 days', `+seen+`) RETURNING id`, f.org, f.site, name, platform, key)
	return tlstrust.Device{ID: id, Org: f.org, Site: f.site, Hostname: name, Platform: platform}
}

// chain makes a certificate chain of one certificate for a host, from a new authority.
func chain(t *testing.T, purpose, host string) tlstrust.Chain {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tlstrust.Chain{Purpose: purpose, DER: [][]byte{der}}
}

func caChain(t *testing.T) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "Authority"}, IsCA: true, BasicConstraintsValid: true,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func (f *fixture) beat(d tlstrust.Device, mod func(*tlstrust.Beat)) *agentproto.TrustPayload {
	f.t.Helper()
	b := tlstrust.Beat{Origin: origin, IP: netip.MustParseAddr("192.0.2.10"), Caps: []string{agentproto.CapTrust}, AgentSHA256: "aaa"}
	if mod != nil {
		mod(&b)
	}
	s := f.svc.Heartbeat(f.ctx, d, b)
	if s == nil {
		return nil
	}
	p, err := agentproto.VerifyTrust(f.pub, *s, d.ID.String(), origin, time.Now())
	if err != nil {
		f.t.Fatalf("the instruction does not verify with the job key: %v", err)
	}
	return &p
}

func report(p *agentproto.TrustPayload, ok bool, errText string) *agentproto.TrustReport {
	r := &agentproto.TrustReport{ID: p.ID, Trusts: "system"}
	for _, c := range p.Chains {
		r.Results = append(r.Results, agentproto.TrustResult{Chain: c.ID, Scope: agentproto.TrustScopeAgent, OK: ok, Error: errText})
	}
	for _, c := range p.EasyPatchChains {
		r.Results = append(r.Results, agentproto.TrustResult{Chain: c.ID, Scope: agentproto.TrustScopeEasyPatch, OK: ok, Error: errText})
	}
	return r
}

func TestAnInstructionOnlyToAnAgentThatAnnouncedTrust(t *testing.T) {
	f := newFixture(t)
	f.src.set(origin, chain(t, agentproto.TrustServed, origin))
	if p := f.beat(f.dev, func(b *tlstrust.Beat) { b.Caps = nil }); p != nil {
		t.Fatalf("an agent that announced nothing got %+v", p)
	}
	if n := f.count(`SELECT count(*) FROM device_tls_trust`); n != 0 {
		t.Errorf("%d rows for an agent that announced nothing", n)
	}
	p := f.beat(f.dev, nil)
	if p == nil || len(p.Chains) != 1 || p.Chains[0].Purpose != agentproto.TrustServed || p.Origin != origin || p.DeviceID != f.dev.ID.String() {
		t.Fatalf("instruction = %+v", p)
	}
	if got := p.ExpiresAt.Sub(p.IssuedAt); got != agentproto.TrustValid {
		t.Errorf("validity = %v", got)
	}
}

func TestNoInstructionForAnIPAddressOrAnUnservedHost(t *testing.T) {
	f := newFixture(t)
	f.src.set(origin, chain(t, agentproto.TrustServed, origin))
	if p := f.beat(f.dev, func(b *tlstrust.Beat) { b.Origin = "203.0.113.10" }); p != nil {
		t.Errorf("an IP origin got %+v", p)
	}
	if p := f.beat(f.dev, func(b *tlstrust.Beat) { b.Origin = "other.example.com" }); p != nil {
		t.Errorf("a host with no chain got %+v", p)
	}
	if p := f.beat(f.dev, func(b *tlstrust.Beat) { b.Origin = "RMM.Example.com" }); p != nil {
		t.Errorf("an origin not in lower case got %+v", p)
	}
}

func TestInstructionIsGatedByTheDevScope(t *testing.T) {
	f := newFixture(t)
	f.src.set(origin, chain(t, agentproto.TrustServed, origin))
	restore := devscope.Set(f.other)
	defer restore()
	if p := f.beat(f.dev, nil); p != nil {
		t.Fatalf("an organization outside the development scope got %+v", p)
	}
	if n := f.count(`SELECT count(*) FROM device_tls_state`); n != 0 {
		t.Errorf("%d state rows outside the scope", n)
	}
}

func TestResultsAreRecordedAndAuditedOnce(t *testing.T) {
	f := newFixture(t)
	f.src.set(origin, chain(t, agentproto.TrustServed, origin))
	p := f.beat(f.dev, nil)
	rep := report(p, true, "")
	rep.Widened = false
	if again := f.beat(f.dev, func(b *tlstrust.Beat) { b.Report = rep }); again != nil {
		t.Fatalf("an answered question is asked again: %+v", again)
	}
	if n := f.count(`SELECT count(*) FROM device_tls_trust WHERE state = 'passed' AND checked_at IS NOT NULL`); n != 1 {
		t.Errorf("%d passed rows", n)
	}
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'device.tls_trust' AND device_id = $1 AND actor_type = 'agent'`, f.dev.ID); n != 1 {
		t.Errorf("%d audit rows", n)
	}
	// The agent sends the report again until an answer drops it: no second row.
	f.beat(f.dev, func(b *tlstrust.Beat) { b.Report = rep })
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'device.tls_trust' AND device_id = $1`, f.dev.ID); n != 1 {
		t.Errorf("%d audit rows after a repeat", n)
	}
	v, err := f.svc.Device(f.ctx, f.super, f.dev.ID)
	if err != nil || !v.Capable || v.Trusts != "system" || len(v.Checks) != 1 || v.Checks[0].State != "passed" || v.Unprotected || v.Reinstall != nil {
		t.Fatalf("view = %+v, %v", v, err)
	}
}

func TestAFailedChainKeepsItsError(t *testing.T) {
	f := newFixture(t)
	f.src.set(origin, chain(t, agentproto.TrustServed, origin))
	p := f.beat(f.dev, nil)
	f.beat(f.dev, func(b *tlstrust.Beat) {
		b.Report = report(p, false, "x509: certificate signed by unknown authority "+strings.Repeat("y", 500))
	})
	v, _ := f.svc.Device(f.ctx, f.super, f.dev.ID)
	if len(v.Checks) != 1 || v.Checks[0].State != "failed" || !strings.Contains(v.Checks[0].Error, "unknown authority") || len(v.Checks[0].Error) > agentproto.MaxTrustError {
		t.Fatalf("checks = %+v", v.Checks)
	}
}

func TestAReportForAQuestionNotAskedChangesNothing(t *testing.T) {
	f := newFixture(t)
	f.src.set(origin, chain(t, agentproto.TrustServed, origin))
	p := f.beat(f.dev, nil)
	forged := report(p, true, "")
	forged.ID = strings.Repeat("0", 32)
	f.beat(f.dev, func(b *tlstrust.Beat) { b.Report = forged })
	// A chain id that does not exist, under the right request.
	other := report(p, true, "")
	other.Results[0].Chain = "agent-served-ffffffffffff"
	f.beat(f.dev, func(b *tlstrust.Beat) { b.Report = other })
	// A result in the wrong scope.
	wrong := report(p, true, "")
	wrong.Results[0].Scope = agentproto.TrustScopeEasyPatch
	f.beat(f.dev, func(b *tlstrust.Beat) { b.Report = wrong })
	if n := f.count(`SELECT count(*) FROM device_tls_trust WHERE state = 'pending'`); n != 1 {
		t.Errorf("%d pending rows; a report for something not asked answered one", n)
	}
	// Another device's request cannot be answered by this device.
	other2 := f.device("pc-2", "linux", true)
	f.beat(other2, func(b *tlstrust.Beat) { b.Report = report(p, true, "") })
	if n := f.count(`SELECT count(*) FROM device_tls_trust WHERE state = 'passed'`); n != 0 {
		t.Errorf("%d passed rows", n)
	}
}

func TestAReplayedReportAfterTheChainChangedIsIgnored(t *testing.T) {
	f := newFixture(t)
	f.src.set(origin, chain(t, agentproto.TrustServed, origin))
	first := f.beat(f.dev, nil)
	// The chain changes (a renewal): the device is asked again.
	f.src.set(origin, chain(t, agentproto.TrustServed, origin))
	second := f.beat(f.dev, nil)
	if second == nil || second.ID == first.ID || second.Chains[0].ID == first.Chains[0].ID {
		t.Fatalf("a changed chain was not asked again: %+v then %+v", first, second)
	}
	// The old answer arrives late (or is replayed): it answers nothing.
	f.beat(f.dev, func(b *tlstrust.Beat) { b.Report = report(first, true, "") })
	if n := f.count(`SELECT count(*) FROM device_tls_trust WHERE state = 'passed'`); n != 0 {
		t.Errorf("%d passed rows after an old answer", n)
	}
	f.beat(f.dev, func(b *tlstrust.Beat) { b.Report = report(second, true, "") })
	if n := f.count(`SELECT count(*) FROM device_tls_trust WHERE state = 'passed'`); n != 1 {
		t.Errorf("%d passed rows after the right answer", n)
	}
}

func TestSameQuestionKeepsItsIDAndIsAnsweredOnce(t *testing.T) {
	f := newFixture(t)
	f.src.set(origin, chain(t, agentproto.TrustServed, origin))
	a, b := f.beat(f.dev, nil), f.beat(f.dev, nil)
	if a == nil || b == nil || a.ID != b.ID || a.Chains[0].ID != b.Chains[0].ID {
		t.Fatalf("a question not answered changes its ID: %+v %+v", a, b)
	}
	if n := f.count(`SELECT count(*) FROM device_tls_trust`); n != 1 {
		t.Errorf("%d rows", n)
	}
}

func TestRecheckWhenTheBuildChanges(t *testing.T) {
	f := newFixture(t)
	f.src.set(origin, chain(t, agentproto.TrustServed, origin))
	p := f.beat(f.dev, nil)
	f.beat(f.dev, func(b *tlstrust.Beat) { b.Report = report(p, true, "") })
	if again := f.beat(f.dev, nil); again != nil {
		t.Fatalf("asked again for no reason: %+v", again)
	}
	// An update, or a rollback: a build with another hash.
	if again := f.beat(f.dev, func(b *tlstrust.Beat) { b.AgentSHA256 = "bbb" }); again == nil {
		t.Fatal("not asked again after the build changed")
	}
}

func TestARollbackToAnOlderBuildStopsInstructions(t *testing.T) {
	f := newFixture(t)
	f.src.set(origin, chain(t, agentproto.TrustServed, origin))
	f.beat(f.dev, nil)
	if p := f.beat(f.dev, func(b *tlstrust.Beat) { b.Caps = nil; b.AgentSHA256 = "old" }); p != nil {
		t.Fatalf("an older build got %+v", p)
	}
	if n := f.count(`SELECT count(*) FROM device_tls_state WHERE capable`); n != 0 {
		t.Error("the device is still capable")
	}
	// The newer build comes back, and is asked again, as a first time.
	if p := f.beat(f.dev, func(b *tlstrust.Beat) { b.AgentSHA256 = "new" }); p == nil {
		t.Error("not asked after it announced the capability again")
	}
}

func TestAFallbackChainThatFailsMarksTheDeviceUnprotected(t *testing.T) {
	f := newFixture(t)
	f.src.set(origin, chain(t, agentproto.TrustServed, origin), chain(t, agentproto.TrustFallback, origin))
	p := f.beat(f.dev, nil)
	if len(p.Chains) != 2 {
		t.Fatalf("chains = %d", len(p.Chains))
	}
	rep := report(p, true, "")
	for i, c := range p.Chains {
		if c.Purpose == agentproto.TrustFallback {
			rep.Results[i].OK, rep.Results[i].Error = false, "x509: certificate signed by unknown authority"
		}
	}
	f.beat(f.dev, func(b *tlstrust.Beat) { b.Report = rep })
	v, _ := f.svc.Device(f.ctx, f.super, f.dev.ID)
	if !v.Unprotected {
		t.Errorf("view = %+v", v)
	}
	// The name loses its fallback: that row goes with it, and so does the mark.
	f.src.set(origin, chain(t, agentproto.TrustServed, origin))
	f.beat(f.dev, func(b *tlstrust.Beat) { b.AgentSHA256 = "bbb" })
	if v, _ = f.svc.Device(f.ctx, f.super, f.dev.ID); v.Unprotected || len(v.Checks) != 1 {
		t.Errorf("after the fallback went: %+v", v)
	}
}

func TestEasyPatchHostChainsAreAskedForAndMarkedAStandInOnLinux(t *testing.T) {
	f := newFixture(t)
	f.src.set(origin, chain(t, agentproto.TrustServed, origin))
	f.src.set("patch.example.com", chain(t, agentproto.TrustServed, "patch.example.com"))
	f.svc.SetEasyPatchHost(func(context.Context, uuid.UUID) string { return "patch.example.com" })
	p := f.beat(f.dev, nil)
	if p == nil || p.EasyPatchHost != "patch.example.com" || len(p.EasyPatchChains) != 1 || len(p.Chains) != 1 {
		t.Fatalf("instruction = %+v", p)
	}
	f.beat(f.dev, func(b *tlstrust.Beat) { b.Report = report(p, true, "") })
	v, _ := f.svc.Device(f.ctx, f.super, f.dev.ID)
	var standIn, agentRow bool
	for _, c := range v.Checks {
		if c.Scope == agentproto.TrustScopeEasyPatch {
			standIn = c.StandIn
		} else {
			agentRow = !c.StandIn
		}
	}
	if !standIn || !agentRow {
		t.Errorf("checks = %+v", v.Checks)
	}
	win := f.device("pc-win", "windows", true)
	pw := f.beat(win, nil)
	f.beat(win, func(b *tlstrust.Beat) { b.Report = report(pw, true, "") })
	vw, _ := f.svc.Device(f.ctx, f.super, win.ID)
	for _, c := range vw.Checks {
		if c.StandIn {
			t.Errorf("a Windows device's EasyPatch result is marked a stand-in: %+v", c)
		}
	}
}

func TestAMoveAsksForTargetAndAuthority(t *testing.T) {
	f := newFixture(t)
	target := chain(t, agentproto.TrustTarget, origin)
	ca := caChain(t)
	if err := f.svc.Ask(f.ctx, []uuid.UUID{f.dev.ID}, tlstrust.Target{Origin: origin, Chains: []tlstrust.Chain{target}, AddCerts: [][]byte{ca}}, false); err != nil {
		t.Fatal(err)
	}
	p := f.beat(f.dev, nil)
	if p == nil || len(p.Chains) != 1 || p.Chains[0].Purpose != agentproto.TrustTarget || len(p.AddCerts) != 1 || p.AddCerts[0] != base64.StdEncoding.EncodeToString(ca) {
		t.Fatalf("instruction = %+v", p)
	}
	rep := report(p, true, "")
	rep.Widened, rep.Trusts = true, "system+ca-file"
	f.beat(f.dev, func(b *tlstrust.Beat) { b.Report = rep })
	v, _ := f.svc.Device(f.ctx, f.super, f.dev.ID)
	if !v.Widened || v.Trusts != "system+ca-file" || v.Checks[0].State != "passed" || v.Checks[0].Purpose != agentproto.TrustTarget {
		t.Fatalf("view = %+v", v)
	}
	// Asked again without force: the answer stands. With force: pending again.
	if err := f.svc.Ask(f.ctx, []uuid.UUID{f.dev.ID}, tlstrust.Target{Origin: origin, Chains: []tlstrust.Chain{target}, AddCerts: [][]byte{ca}}, false); err != nil {
		t.Fatal(err)
	}
	if n := f.count(`SELECT count(*) FROM device_tls_trust WHERE state = 'pending'`); n != 0 {
		t.Errorf("%d pending after an unforced ask", n)
	}
	if err := f.svc.Ask(f.ctx, []uuid.UUID{f.dev.ID}, tlstrust.Target{Origin: origin, Chains: []tlstrust.Chain{target}, AddCerts: [][]byte{ca}}, true); err != nil {
		t.Fatal(err)
	}
	if n := f.count(`SELECT count(*) FROM device_tls_trust WHERE state = 'pending'`); n != 1 {
		t.Errorf("%d pending after a forced ask", n)
	}
	// Nothing to ask is refused, and so is a purpose that does not exist.
	if f.svc.Ask(f.ctx, []uuid.UUID{f.dev.ID}, tlstrust.Target{Origin: origin}, false) == nil {
		t.Error("an empty ask was accepted")
	}
	if f.svc.Ask(f.ctx, []uuid.UUID{f.dev.ID}, tlstrust.Target{Origin: origin, Chains: []tlstrust.Chain{{Purpose: "all", DER: target.DER}}}, false) == nil {
		t.Error("an unknown purpose was accepted")
	}
}

func TestARefusalIsAuditedOncePerInstructionAndKeepsTheQuestionPending(t *testing.T) {
	f := newFixture(t)
	f.src.set(origin, chain(t, agentproto.TrustServed, origin))
	p := f.beat(f.dev, nil)
	refusal := &agentproto.TrustReport{ID: p.ID, Refused: "the trust instruction has expired", Trusts: "system"}
	for range 3 {
		if again := f.beat(f.dev, func(b *tlstrust.Beat) { b.Report = refusal }); again == nil {
			t.Fatal("a refused question was dropped")
		}
	}
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'device.tls_trust' AND outcome = 'failure' AND device_id = $1`, f.dev.ID); n != 1 {
		t.Errorf("%d refusals audited", n)
	}
	v, _ := f.svc.Device(f.ctx, f.super, f.dev.ID)
	if v.Refused == "" || v.Checks[0].State != "pending" {
		t.Errorf("view = %+v", v)
	}
}

func TestReinstallIsOfferedToADeviceThatFailedAndIsGone(t *testing.T) {
	f := newFixture(t)
	gone := f.device("pc-gone", "linux", false)
	f.src.set(origin, chain(t, agentproto.TrustServed, origin))
	p := f.beat(gone, nil)
	f.beat(gone, func(b *tlstrust.Beat) { b.Report = report(p, false, "x509: certificate signed by unknown authority") })
	v, err := f.svc.Device(f.ctx, f.super, gone.ID)
	if err != nil || v.Reinstall == nil || !strings.Contains(v.Reinstall.Fix, "--ca-file") || v.SiteID != f.site.String() {
		t.Fatalf("view = %+v, %v", v, err)
	}
	// Connected and failing is not cut off: the page shows the failure only.
	online := f.device("pc-on", "linux", true)
	po := f.beat(online, nil)
	f.beat(online, func(b *tlstrust.Beat) { b.Report = report(po, false, "x509: certificate signed by unknown authority") })
	if v, _ = f.svc.Device(f.ctx, f.super, online.ID); v.Reinstall != nil || v.Checks[0].State != "failed" {
		t.Errorf("an online device was offered a reinstall: %+v", v)
	}
	// A move that was sent and never answered by a device that is gone.
	stale := f.device("pc-stale", "linux", false)
	if err := f.svc.Ask(f.ctx, []uuid.UUID{stale.ID}, tlstrust.Target{Origin: origin, Chains: []tlstrust.Chain{chain(t, agentproto.TrustTarget, origin)}}, false); err != nil {
		t.Fatal(err)
	}
	f.beat(stale, nil)
	f.exec(`UPDATE device_tls_trust SET sent_at = now() - interval '2 hours' WHERE device_id = $1`, stale.ID)
	if v, _ = f.svc.Device(f.ctx, f.super, stale.ID); v.Reinstall == nil {
		t.Errorf("a long unanswered move was not offered a reinstall: %+v", v)
	}
}

func (f *fixture) exec(sql string, args ...any) {
	f.t.Helper()
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error { _, err := tx.Exec(f.ctx, sql, args...); return err }); err != nil {
		f.t.Fatal(err)
	}
}

// What a person sees follows the device: another organization's administrator
// sees nothing of it, and the tables are under row-level security.
func TestOnlyWhoCanSeeTheDeviceSeesItsTrust(t *testing.T) {
	f := newFixture(t)
	f.src.set(origin, chain(t, agentproto.TrustServed, origin))
	f.beat(f.dev, nil)
	outsider := f.user("globex@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.other})
	if _, err := f.svc.Device(f.ctx, outsider, f.dev.ID); err == nil {
		t.Error("another organization's administrator read the device's trust")
	}
	insider := f.user("acme@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.org})
	if _, err := f.svc.Device(f.ctx, insider, f.dev.ID); err != nil {
		t.Errorf("the device's own organization: %v", err)
	}
	// Directly, under the outsider's row scope: no row at all.
	var n int
	if err := f.db.ReadTx(f.ctx, outsider.Scope, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM device_tls_trust) + (SELECT count(*) FROM device_tls_state)`).Scan(&n)
	}); err != nil || n != 0 {
		t.Errorf("an outsider's scope reads %d rows (%v)", n, err)
	}
	// And a scoped transaction cannot write them.
	err := f.db.InTx(f.ctx, insider.Scope, func(tx pgx.Tx) error {
		_, err := tx.Exec(f.ctx, `UPDATE device_tls_trust SET state = 'passed'`)
		return err
	})
	if err != nil {
		t.Logf("write refused: %v", err)
	}
	if got := f.count(`SELECT count(*) FROM device_tls_trust WHERE state = 'passed'`); got != 0 {
		t.Errorf("a person's scope wrote the table: %d rows passed", got)
	}
}

func TestDeletingTheDeviceDeletesItsTrust(t *testing.T) {
	f := newFixture(t)
	f.src.set(origin, chain(t, agentproto.TrustServed, origin))
	f.beat(f.dev, nil)
	f.exec(`DELETE FROM devices WHERE id = $1`, f.dev.ID)
	if n := f.count(`SELECT (SELECT count(*) FROM device_tls_trust) + (SELECT count(*) FROM device_tls_state)`); n != 0 {
		t.Errorf("%d rows left", n)
	}
}

func TestFixFor(t *testing.T) {
	for in, want := range map[string]string{
		"x509: certificate signed by unknown authority":           "--ca-file",
		"x509: certificate has expired or is not yet valid":       "date and time",
		"x509: certificate is valid for a.example, not b.example": "name this agent connects to",
		"something else": "--ca-file",
	} {
		if got := tlstrust.FixFor(in); !strings.Contains(got, want) {
			t.Errorf("FixFor(%q) = %q", in, got)
		}
	}
}
