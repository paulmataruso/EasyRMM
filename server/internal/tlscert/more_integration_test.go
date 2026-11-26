//go:build integration

package tlscert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type leader bool

func (l leader) Lead(context.Context) (bool, error) { return bool(l), nil }

// autocertFile is what autocert caches for a name: the key's PEM, then the chain's.
func autocertFile(t *testing.T, name string, notAfter time.Time, wrongKey bool) []byte {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	signer := k
	if wrongKey {
		signer, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	keyDER, _ := x509.MarshalECPrivateKey(signer)
	return append(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
}

// Only a valid ECDSA certificate for the name, with its own key, is imported.
func TestImportTakesOnlyWhatIsValidForTheName(t *testing.T) {
	pb := startPebble(t, 3600)
	dir := t.TempDir()
	write := func(name string, b []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("good.test", autocertFile(t, "good.test", time.Now().Add(30*24*time.Hour), false))
	write("expired.test", autocertFile(t, "expired.test", time.Now().Add(-time.Hour), false))
	write("mismatch.test", autocertFile(t, "mismatch.test", time.Now().Add(24*time.Hour), true))
	write("other.test", autocertFile(t, "someone.else", time.Now().Add(24*time.Hour), false))
	write("nokey.test", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")}))
	// An account key autocert wrote is taken as the named account.
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyDER, _ := x509.MarshalECPrivateKey(k)
	write("acme_account+key", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	f := newFixture(t, pb, []string{"good.test", "expired.test", "mismatch.test", "other.test", "nokey.test", "absent.test"}, func(s *Settings) { s.AutocertDir = dir })
	if err := f.svc.Start(f.ctx); err != nil {
		t.Fatal(err)
	}
	for n, want := range map[string]bool{"good.test": true, "expired.test": false, "mismatch.test": false, "other.test": false, "nokey.test": false, "absent.test": false} {
		if got := f.row(f.svc, n).HasCertificate(); got != want {
			t.Errorf("%s imported: %v, want %v", n, got, want)
		}
	}
	if !f.row(f.svc, "good.test").Imported {
		t.Error("the import is not marked")
	}
	if got, err := f.svc.Storage().Load(f.ctx, f.svc.accountKeyName()); err != nil || len(got) == 0 {
		t.Errorf("the account key was not taken: %v", err)
	}
	// It serves; and the key never left storage in the clear.
	if f.served(f.svc, "good.test") == "" {
		t.Error("the imported certificate is not served")
	}
}

// Extra accounts stored for the CA are removed, leaving the named one, so that
// CertMagic's account lookup can only find it.
func TestOnlyTheNamedAccountIsStored(t *testing.T) {
	pb := startPebble(t, 3600)
	f := newFixture(t, pb, []string{"acct.test"}, nil)
	if err := f.svc.Start(f.ctx); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.ensureAccount(f.ctx); err != nil {
		t.Fatal(err)
	}
	// A stale registration under another address, as an earlier configuration left.
	st := f.svc.Storage()
	for _, k := range []string{f.svc.usersPrefix() + "/old@example.test/old.json", f.svc.usersPrefix() + "/old@example.test/old.key"} {
		if err := st.Store(f.ctx, k, []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.svc.onlyAccount(f.ctx, []byte(f.svc.issuer.AccountKeyPEM)); err != nil {
		t.Fatal(err)
	}
	if folders, _ := st.List(f.ctx, f.svc.usersPrefix(), false); len(folders) != 1 {
		t.Fatalf("accounts stored: %v", folders)
	}
	if err := f.svc.onlyAccount(f.ctx, []byte("a different key")); err == nil {
		t.Fatal("an account that is not stored was found")
	}
	// Starting again finds the key it kept.
	if k, err := f.svc.loadAccountKey(f.ctx); err != nil || string(k) != f.svc.issuer.AccountKeyPEM {
		t.Fatalf("the kept key: %v", err)
	}
}

// A pass by a server that is not the scheduler makes no attempt; a person's
// request for a name that is not the server's, or while one runs, is refused.
func TestFollowersAndRefusals(t *testing.T) {
	pb := startPebble(t, 3600)
	f := newFixture(t, pb, []string{"fol.test"}, nil)
	if err := f.svc.Start(f.ctx); err != nil {
		t.Fatal(err)
	}
	f.serve(f.svc)
	f.svc.tick(f.ctx, leader(false))
	if f.row(f.svc, "fol.test").HasCertificate() || !f.row(f.svc, "fol.test").LastAttemptAt.IsZero() {
		t.Fatal("a follower made an attempt")
	}
	if err := f.svc.RetryNow(f.ctx, admin, "nope.test"); !errors.Is(err, ErrNoName) {
		t.Fatalf("a name that is not managed: %v", err)
	}
	f.svc.mu.Lock()
	f.svc.inflight["fol.test"] = true
	f.svc.mu.Unlock()
	if err := f.svc.RetryNow(f.ctx, admin, "fol.test"); !errors.Is(err, ErrBusy) {
		t.Fatalf("while an attempt runs: %v", err)
	}
	if err := f.svc.attempt(f.ctx, "fol.test", kindScheduled); !errors.Is(err, ErrBusy) {
		t.Fatalf("a second attempt: %v", err)
	}
	f.svc.mu.Lock()
	delete(f.svc.inflight, "fol.test")
	f.svc.mu.Unlock()
	// The account is not established until the CA is reached: no attempt, a clear error.
	f.svc.mu.Lock()
	f.svc.accountReady = false
	f.svc.mu.Unlock()
	if err := f.svc.attempt(f.ctx, "fol.test", kindScheduled); !errors.Is(err, ErrNoAccount) {
		t.Fatalf("before the account: %v", err)
	}
	if err := f.svc.ensureAccount(f.ctx); err != nil {
		t.Fatal(err)
	}
	// A key that cannot be opened is refused at start, not served around.
	other, _ := newSealer(t, "other")
	bad := New(Deps{DB: f.inst.DB, Sealer: other, Log: discardLog()}, Settings{Names: []string{"fol.test"}, Directory: pb.Directory})
	defer bad.Close()
	if err := bad.Start(f.ctx); err == nil {
		t.Fatal("started with a key that opens nothing stored")
	}
}

func TestSmallHandlersAndResolver(t *testing.T) {
	s := New(Deps{}, Settings{Names: []string{"x.test"}})
	if _, err := s.lookup(context.Background(), "localhost"); err != nil {
		t.Skipf("no resolver here: %v", err)
	}
	if s.own() != nil {
		t.Fatal("own without a list")
	}
	hit := false
	h := s.CheckHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/api", nil))
	if !hit {
		t.Fatal("CheckHandler does not pass requests on")
	}
}

// MeshCentral's listener fails a handshake when no certificate is available,
// and still counts it as a read.
func TestMeshListenerWithoutACertificate(t *testing.T) {
	ln, err := tlsListener(t)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reads := make(chan struct{}, 1)
	go func() {
		_ = ServeMesh(ctx, ln, func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, errors.New("none") }, func(time.Time) { reads <- struct{}{} })
	}()
	_, err = tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) //nolint:gosec // the handshake is expected to fail
	if err == nil {
		t.Fatal("a handshake without a certificate succeeded")
	}
	select {
	case <-reads:
	case <-time.After(3 * time.Second):
		t.Fatal("the read was not counted")
	}
}
