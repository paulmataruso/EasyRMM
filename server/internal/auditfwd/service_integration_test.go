//go:build integration

package auditfwd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

type fixture struct {
	t     *testing.T
	ctx   context.Context
	db    *database.DB
	log   *audit.Logger
	svc   *Service
	admin audit.Actor
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	inst := testdb.New(t)
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	sealer, err := secrets.NewSealer(secrets.Key{ID: "k1", Raw: raw})
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, ctx: context.Background(), db: inst.DB, log: audit.New(inst.DB, nil)}
	f.svc = New(inst.DB, f.log, sealer, "rmm.example.com", "1.0.0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	var id uuid.UUID
	if err := inst.DB.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `INSERT INTO users (email, display_name) VALUES ('admin@msp.example', 'Admin') RETURNING id`).Scan(&id)
	}); err != nil {
		t.Fatal(err)
	}
	f.admin = audit.Actor{Type: audit.ActorUser, ID: id, Label: "admin@msp.example"}
	t.Cleanup(f.svc.closeConn)
	return f
}

// record appends n audit records and returns their ids.
func (f *fixture) record(n int) {
	f.t.Helper()
	for i := 0; i < n; i++ {
		if err := f.log.Record(f.ctx, audit.Event{Actor: audit.SystemActor("test"), Action: "test.event", Outcome: audit.Success,
			Details: map[string]any{"n": i}}); err != nil {
			f.t.Fatal(err)
		}
	}
}

func (f *fixture) maxID() int64 {
	f.t.Helper()
	var id int64
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT coalesce(max(id), 0) FROM audit_log`).Scan(&id)
	}); err != nil {
		f.t.Fatal(err)
	}
	return id
}

func (f *fixture) forward() int {
	f.t.Helper()
	n, err := f.svc.Forward(f.ctx)
	if err != nil {
		f.t.Fatalf("forward: %v", err)
	}
	return n
}

func (f *fixture) update(in Input) Settings {
	f.t.Helper()
	s, err := f.svc.Update(f.ctx, f.admin, in)
	if err != nil {
		f.t.Fatalf("update: %v", err)
	}
	return s
}

type received struct {
	pri, msgID string
	rec        map[string]any
}

func receive(t *testing.T, c *collector) received {
	t.Helper()
	p := parse(t, c.next(t))
	var r map[string]any
	if err := json.Unmarshal([]byte(p[8]), &r); err != nil {
		t.Fatalf("MSG %q: %v", p[8], err)
	}
	if p[3] != "rmm.example.com" || p[4] != "easyrmm" || p[7] != `[origin software="EasyRMM" swVersion="1.0.0"]` {
		t.Fatalf("header %q", p)
	}
	return received{pri: p[0], msgID: p[6], rec: r}
}

func TestForwardsEveryRecordInOrder(t *testing.T) {
	f := newFixture(t)
	if n := f.forward(); n != 0 {
		t.Fatalf("forwarded %d without settings", n)
	}
	f.record(3)
	col := newCollector(t, TCP, nil)
	s := f.update(Input{Enabled: true, Transport: "TCP", Host: " 127.0.0.1 ", Port: col.port, StartFrom: "beginning"})
	if !s.Configured || !s.Enabled || s.Transport != TCP || s.Host != "127.0.0.1" || s.Facility != DefaultFacility ||
		s.UpdatedBy != "admin@msp.example" || s.UpdatedAt == nil || s.Status.LastID != 0 {
		t.Fatalf("settings %+v", s)
	}
	// Three records and the settings change itself.
	want := f.maxID()
	if want != 4 || s.Status.Backlog != want || s.Status.Stored != want || s.Status.OldestPendingAt == nil {
		t.Fatalf("backlog %d of %d (oldest %v), want %d", s.Status.Backlog, s.Status.Stored, s.Status.OldestPendingAt, want)
	}
	if n := f.forward(); int64(n) != want {
		t.Fatalf("forwarded %d, want %d", n, want)
	}
	var prev string
	for id := int64(1); id <= want; id++ {
		r := receive(t, col)
		if r.rec["id"] != float64(id) {
			t.Fatalf("record %v, want id %d", r.rec["id"], id)
		}
		// The hash chain arrives whole.
		if id > 1 && r.rec["prevHash"] != prev {
			t.Fatalf("record %d prevHash %v, want %s", id, r.rec["prevHash"], prev)
		}
		prev = r.rec["entryHash"].(string)
		if _, err := hex.DecodeString(prev); err != nil || len(prev) != 64 {
			t.Fatalf("entry hash %q", prev)
		}
		if id == want && (r.msgID != "audit_forwarding.update" || r.pri != "110") {
			t.Fatalf("last record %+v", r)
		}
	}
	s, _ = f.svc.Get(f.ctx)
	if s.Status.LastID != want || s.Status.Backlog != 0 || s.Status.LastSentAt == nil || s.Status.OldestPendingAt != nil {
		t.Fatalf("after forwarding %+v", s.Status)
	}

	// Only new records go next time, over the same connection.
	f.record(2)
	if n := f.forward(); n != 2 {
		t.Fatalf("forwarded %d new records", n)
	}
	receive(t, col)
	receive(t, col)
	if col.accepted.Load() != 1 {
		t.Fatalf("%d connections for two rounds", col.accepted.Load())
	}

	// A collector that restarted is reconnected to before anything is lost.
	col.drop()
	time.Sleep(50 * time.Millisecond)
	f.record(1)
	if n := f.forward(); n != 1 {
		t.Fatalf("forwarded %d after the collector restarted", n)
	}
	if r := receive(t, col); r.rec["action"] != "test.event" || col.accepted.Load() != 2 {
		t.Fatalf("after reconnecting %+v, %d connections", r, col.accepted.Load())
	}

	// Turned off, the record of turning it off still goes, then nothing, and
	// the connection closes.
	in := Input{Enabled: false, Transport: TCP, Host: "127.0.0.1", Port: col.port}
	if s := f.update(in); !s.Status.Stopping || s.Status.Backlog != 1 {
		t.Fatalf("turning off %+v", s.Status)
	}
	f.record(1)
	if n := f.forward(); n != 1 {
		t.Fatalf("forwarded %d after turning off", n)
	}
	if r := receive(t, col); r.msgID != "audit_forwarding.update" || r.rec["details"].(map[string]any)["enabled"] != false {
		t.Fatalf("last record %+v", r)
	}
	if s, _ := f.svc.Get(f.ctx); s.Status.Stopping {
		t.Fatalf("still stopping %+v", s.Status)
	}
	if n := f.forward(); n != 0 || f.svc.conn != nil {
		t.Fatalf("forwarded %d while off", n)
	}
	// Turned on again from now, the records written meanwhile are skipped;
	// the change that turned it on is the first to go.
	in.Enabled, in.StartFrom = true, "now"
	f.update(in)
	f.record(1)
	if n := f.forward(); n != 2 {
		t.Fatalf("forwarded %d starting from now", n)
	}
	if r := receive(t, col); r.msgID != "audit_forwarding.update" || r.rec["details"].(map[string]any)["startFrom"] != "now" {
		t.Fatalf("starting from now %+v", r)
	}
	if r := receive(t, col); r.rec["action"] != "test.event" {
		t.Fatalf("after the change %+v", r)
	}
	col.none(t, 100*time.Millisecond)
}

// Over TCP: a burst of BatchSize datagrams can overflow a UDP receive buffer
// on a busy machine (CI runners allow about 200 KB), and batching does not
// depend on the transport.
func TestForwardsInBatches(t *testing.T) {
	f := newFixture(t)
	col := newCollector(t, TCP, nil)
	f.record(BatchSize + 10)
	f.update(Input{Enabled: true, Transport: TCP, Host: "127.0.0.1", Port: col.port, Facility: 16, StartFrom: "beginning"})
	total := int(f.maxID())
	if n := f.forward(); n != BatchSize {
		t.Fatalf("first batch %d", n)
	}
	if n := f.forward(); n != total-BatchSize {
		t.Fatalf("second batch %d, want %d", n, total-BatchSize)
	}
	for i := 1; i <= total; i++ {
		r := receive(t, col)
		if r.rec["id"] != float64(i) {
			t.Fatalf("datagram %d carries %v", i, r.rec["id"])
		}
		if r.pri != "134" && r.pri != "133" && r.pri != "132" {
			t.Fatalf("PRI %s for local0", r.pri)
		}
	}
}

func TestDeliveryFailuresAreReportedAndRetried(t *testing.T) {
	f := newFixture(t)
	port := closedPort(t, "tcp")
	f.update(Input{Enabled: true, Transport: TCP, Host: "127.0.0.1", Port: port, StartFrom: "beginning"})
	f.record(2)
	n, err := f.svc.Forward(f.ctx)
	if err == nil || n != 0 {
		t.Fatalf("forwarded %d to nothing: %v", n, err)
	}
	s, _ := f.svc.Get(f.ctx)
	if !strings.Contains(s.Status.LastError, "Connection refused") || s.Status.LastErrorAt == nil || s.Status.LastID != 0 || s.Status.Backlog == 0 {
		t.Fatalf("status after a failure %+v", s.Status)
	}

	// The same port, now listening: the backlog goes, and the error stays on
	// record with its time.
	col := newCollectorOn(t, port)
	sent := f.forward()
	if int64(sent) != f.maxID() {
		t.Fatalf("forwarded %d of %d", sent, f.maxID())
	}
	for i := 0; i < sent; i++ {
		receive(t, col)
	}
	s, _ = f.svc.Get(f.ctx)
	if s.Status.LastError == "" || s.Status.LastSentAt == nil || !s.Status.LastSentAt.After(*s.Status.LastErrorAt) || s.Status.Backlog != 0 {
		t.Fatalf("status after recovering %+v", s.Status)
	}
	// Changing the destination clears the old error.
	s = f.update(Input{Enabled: true, Transport: UDP, Host: "127.0.0.1", Port: port})
	if s.Status.LastError != "" || s.Status.LastErrorAt != nil || s.Status.LastID != f.maxID()-1 {
		t.Fatalf("after moving %+v", s.Status)
	}

	// Run keeps going until its context ends, backing off while it fails.
	ctx, cancel := context.WithCancel(f.ctx)
	done := make(chan struct{})
	udp := newCollector(t, UDP, nil)
	f.update(Input{Enabled: true, Transport: UDP, Host: "127.0.0.1", Port: udp.port})
	go func() { f.svc.Run(ctx); close(done) }()
	f.record(1)
	for {
		if r := receive(t, udp); r.rec["action"] == "test.event" {
			break
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
}

// newCollectorOn listens for TCP on a given loopback port.
func newCollectorOn(t *testing.T, port int) *collector {
	t.Helper()
	for i := 0; ; i++ {
		c, err := listenTCP(t, port)
		if err == nil {
			return c
		}
		if i > 50 {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestOneServerForwardsAtATime(t *testing.T) {
	f := newFixture(t)
	col := newCollector(t, TCP, nil)
	f.update(Input{Enabled: true, Transport: TCP, Host: "127.0.0.1", Port: col.port, StartFrom: "beginning"})
	other := New(f.db, f.log, f.svc.sealer, "rmm.example.com", "1.0.0", f.svc.log)
	t.Cleanup(other.closeConn)
	var wg sync.WaitGroup
	for round := 0; round < 20; round++ {
		f.record(3)
		for _, s := range []*Service{f.svc, other} {
			wg.Go(func() {
				if _, err := s.Forward(f.ctx); err != nil {
					t.Error(err)
				}
			})
		}
		wg.Wait()
	}
	// Whatever is left, then check every id arrived exactly once.
	for f.forward() > 0 {
	}
	seen := map[float64]int{}
	for i := int64(0); i < f.maxID(); i++ {
		seen[receive(t, col).rec["id"].(float64)]++
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("record %v arrived %d times", id, n)
		}
	}
	col.none(t, 100*time.Millisecond)
}

func TestClientCertificatesAndTLSForwarding(t *testing.T) {
	f := newFixture(t)
	pki := newPKI(t)
	col := newCollector(t, TLS, pki.serverTLS(t, true))
	cert, key, _ := pki.issue(t, nil, nil, true)
	in := Input{Enabled: true, Transport: TLS, Host: "127.0.0.1", Port: col.port, CACert: pki.caPEM, ClientCert: cert, ClientKey: key, StartFrom: "beginning"}
	s := f.update(in)
	if !s.ClientKeySet || s.ClientCert != strings.TrimSpace(cert) || s.CACert != strings.TrimSpace(pki.caPEM) {
		t.Fatalf("settings %+v", s)
	}
	var sealed string
	_ = f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT client_key_sealed FROM audit_forwarding`).Scan(&sealed)
	})
	if sealed == "" || strings.Contains(sealed, "PRIVATE KEY") {
		t.Fatalf("client key stored as %q", sealed)
	}
	raw, _ := json.Marshal(s)
	if strings.Contains(string(raw), "PRIVATE KEY") {
		t.Fatal("settings carry the client key")
	}
	if n := f.forward(); int64(n) != f.maxID() {
		t.Fatalf("forwarded %d over mutual TLS", n)
	}
	receive(t, col)

	// Saved again without the key, the stored one is kept.
	in.ClientKey, in.StartFrom = "", ""
	f.update(in)
	f.record(1)
	if n := f.forward(); n != 2 {
		t.Fatalf("forwarded %d with the kept key", n)
	}
	// A different certificate needs its key.
	other, otherKey, _ := pki.issue(t, nil, nil, true)
	in.ClientCert = other
	wantFields(t, func() error { _, err := f.svc.Update(f.ctx, f.admin, in); return err }, "clientKey")
	in.ClientKey = key
	wantFields(t, func() error { _, err := f.svc.Update(f.ctx, f.admin, in); return err }, "clientKey")
	in.ClientKey = otherKey
	f.update(in)
	// Without a certificate the key goes too.
	in.ClientCert, in.ClientKey = "", ""
	if s := f.update(in); s.ClientKeySet || s.ClientCert != "" {
		t.Fatalf("after removing the certificate %+v", s)
	}
	// The collector requires one: the next round fails, and says why.
	f.record(1)
	if _, err := f.svc.Forward(f.ctx); err == nil {
		t.Fatal("forwarded without the required client certificate")
	}
	if s, _ := f.svc.Get(f.ctx); !strings.Contains(s.Status.LastError, "client certificate") {
		t.Fatalf("error %q", s.Status.LastError)
	}
}

func wantFields(t *testing.T, fn func() error, fields ...string) {
	t.Helper()
	err := fn()
	e, ok := apperr.As(err)
	if !ok || e.Kind != apperr.KindInvalid {
		t.Fatalf("error %v, want a validation error on %v", err, fields)
	}
	for _, field := range fields {
		if _, ok := e.Fields[field]; !ok {
			t.Errorf("no error on %s: %v", field, e.Fields)
		}
	}
}

func TestValidation(t *testing.T) {
	f := newFixture(t)
	pki := newPKI(t)
	cert, key, _ := pki.issue(t, nil, nil, true)
	up := func(in Input) func() error {
		return func() error { _, err := f.svc.Update(f.ctx, f.admin, in); return err }
	}
	wantFields(t, up(Input{}), "transport", "host", "port")
	wantFields(t, up(Input{Transport: "relp", Host: "https://siem", Port: 70000, Facility: 3, StartFrom: "later"}),
		"transport", "host", "port", "facility", "startFrom")
	wantFields(t, up(Input{Transport: UDP, Host: "siem", Port: 514, CACert: pki.caPEM, ClientCert: cert}), "caCert", "clientCert")
	wantFields(t, up(Input{Transport: TLS, Host: "siem", Port: 6514, CACert: "nope"}), "caCert")
	wantFields(t, up(Input{Transport: TLS, Host: "siem", Port: 6514, ClientKey: key}), "clientCert")
	wantFields(t, up(Input{Transport: TLS, Host: "siem", Port: 6514, ClientCert: cert}), "clientKey")
	wantFields(t, up(Input{Transport: TLS, Host: "siem", Port: 6514, ClientCert: cert, ClientKey: "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----"}), "clientKey")
	wantFields(t, up(Input{Transport: TLS, Host: "siem", Port: 6514, CACert: strings.Repeat("x", 70000)}), "caCert")
	if s, _ := f.svc.Get(f.ctx); s.Configured {
		t.Fatal("invalid settings were stored")
	}
	// An IPv6 address may come in brackets.
	if s := f.update(Input{Transport: UDP, Host: "[2001:db8::5]", Port: 514}); s.Host != "2001:db8::5" || s.Enabled {
		t.Fatalf("IPv6 %+v", s)
	}
	// A key sealed with a secret key this server no longer has.
	_ = f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(f.ctx, `UPDATE audit_forwarding SET transport = 'tls', host = '127.0.0.1', client_cert = $1, client_key_sealed = 'v1:bogus'`, strings.TrimSpace(cert))
		return err
	})
	wantFields(t, up(Input{Transport: TLS, Host: "127.0.0.1", Port: 514, ClientCert: cert}), "clientKey")
	f.update(Input{Enabled: true, Transport: TLS, Host: "127.0.0.1", Port: 514, ClientCert: cert, ClientKey: key})
	_ = f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(f.ctx, `UPDATE audit_forwarding SET client_key_sealed = 'v1:bogus'`)
		return err
	})
	if _, err := f.svc.Forward(f.ctx); err == nil {
		t.Fatal("forwarded with a key that cannot be opened")
	}
	if s, _ := f.svc.Get(f.ctx); !strings.Contains(s.Status.LastError, "cannot be opened") {
		t.Fatalf("error %q", s.Status.LastError)
	}
}

func TestTestMessage(t *testing.T) {
	f := newFixture(t)
	col := newCollector(t, TCP, nil)
	res, err := f.svc.Test(f.ctx, f.admin, Input{Transport: TCP, Host: "127.0.0.1", Port: col.port, Facility: 10})
	if err != nil || !res.OK {
		t.Fatalf("test: %+v %v", res, err)
	}
	r := receive(t, col)
	if r.msgID != "test" || r.pri != "86" || r.rec["test"] != true || r.rec["requestedBy"] != "admin@msp.example" {
		t.Fatalf("test message %+v", r)
	}
	res, err = f.svc.Test(f.ctx, f.admin, Input{Transport: UDP, Host: "127.0.0.1", Port: closedPort(t, "udp")})
	if err != nil || res.OK || !strings.Contains(res.Message, "nothing accepts UDP") {
		t.Fatalf("UDP to nothing: %+v %v", res, err)
	}
	udp := newCollector(t, UDP, nil)
	if res, _ := f.svc.Test(f.ctx, f.admin, Input{Transport: UDP, Host: "127.0.0.1", Port: udp.port}); !res.OK || !strings.Contains(res.Message, "does not confirm delivery") {
		t.Fatalf("UDP: %+v", res)
	}
	pki := newPKI(t)
	tlsCol := newCollector(t, TLS, pki.serverTLS(t, false))
	if res, _ := f.svc.Test(f.ctx, f.admin, Input{Transport: TLS, Host: "127.0.0.1", Port: tlsCol.port, CACert: pki.caPEM}); !res.OK || !strings.Contains(res.Message, "certificate checked out") {
		t.Fatalf("TLS: %+v", res)
	}
	if res, _ := f.svc.Test(f.ctx, f.admin, Input{Transport: TLS, Host: "127.0.0.1", Port: tlsCol.port}); res.OK || !strings.Contains(res.Message, "trusted certificate authority") {
		t.Fatalf("TLS without the authority: %+v", res)
	}
	wantFields(t, func() error { _, err := f.svc.Test(f.ctx, f.admin, Input{Transport: TCP}); return err }, "host", "port")
	// Each attempt is audited, with its outcome.
	entries, err := f.log.List(f.ctx, database.System, audit.Query{ActionPrefix: "audit_forwarding.test"})
	if err != nil || len(entries) != 5 {
		t.Fatalf("audited tests %d: %v", len(entries), err)
	}
	if entries[0].Outcome != audit.Failure || entries[0].Details["error"] == nil || entries[4].Outcome != audit.Success ||
		entries[4].TargetID != col.addr() {
		t.Fatalf("audited tests %+v", entries)
	}
}

func TestRetentionKeepsWhatIsNotForwarded(t *testing.T) {
	f := newFixture(t)
	old := func(n int) {
		for i := 0; i < n; i++ {
			_ = f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
				_, err := tx.Exec(f.ctx, `SELECT easyrmm_audit_append(now() - interval '100 days', 'system', NULL, 'test', NULL, NULL, NULL,
					'test.old', '', '', 'success', NULL, '', '{}'::jsonb)`)
				return err
			})
		}
	}
	purge := func() int64 {
		var n int64
		if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
			return tx.QueryRow(f.ctx, `SELECT easyrmm_purge_audit(interval '30 days')`).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	old(3)
	col := newCollector(t, TCP, nil)
	f.update(Input{Enabled: true, Transport: TCP, Host: "127.0.0.1", Port: col.port, StartFrom: "beginning"})
	if n := purge(); n != 0 {
		t.Fatalf("purged %d records not yet forwarded", n)
	}
	f.forward()
	old(2)
	if n := purge(); n != 3 {
		t.Fatalf("purged %d forwarded records, want 3", n)
	}
	// Turned off, records still to deliver are kept until they have gone;
	// then retention applies to everything again.
	f.update(Input{Transport: TCP, Host: "127.0.0.1", Port: col.port})
	if n := purge(); n != 0 {
		t.Fatalf("purged %d records still to deliver", n)
	}
	f.forward()
	if n := purge(); n != 2 {
		t.Fatalf("purged %d with forwarding off, want 2", n)
	}
}

func TestSettingsWithoutAnything(t *testing.T) {
	f := newFixture(t)
	s, err := f.svc.Get(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if s.Configured || s.Transport != TLS || s.Port != 6514 || s.Facility != DefaultFacility || s.Hostname != "rmm.example.com" || s.UpdatedAt != nil {
		t.Fatalf("defaults %+v", s)
	}
	_ = f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(f.ctx, `DELETE FROM users`)
		return err
	})
	if _, err := f.svc.Update(f.ctx, audit.SystemActor("test"), Input{Transport: UDP, Host: "siem", Port: 514}); err != nil {
		t.Fatalf("update by the system: %v", err)
	}
	if s, _ := f.svc.Get(f.ctx); s.UpdatedBy != "" || !s.Configured {
		t.Fatalf("after a system update %+v", s)
	}
}
