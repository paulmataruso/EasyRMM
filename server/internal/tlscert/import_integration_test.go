//go:build integration

package tlscert

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// An install with autocert's state upgrades to CertMagic and serves the same
// certificate, with no order and no new account (ADR-0055: "the upgrade issues
// nothing, and registers no account"). The state is the real thing: autocert,
// the library the previous release used, orders from Pebble and writes its
// cache directory.
func TestUpgradeFromAutocertServesTheSameCertificate(t *testing.T) {
	pb := startPebble(t, 3600)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pb.RootsPEM)
	dir := filepath.Join(t.TempDir(), "acme")
	m := &autocert.Manager{
		Prompt: autocert.AcceptTOS, Cache: autocert.DirCache(dir), HostPolicy: autocert.HostWhitelist("up.test"), Email: "ops@example.test",
		Client: &acme.Client{DirectoryURL: pb.Directory, HTTPClient: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}},
	}
	tlsLn, err := net.Listen("tcp", "127.0.0.1:"+pb.TLSPort)
	if err != nil {
		t.Fatal(err)
	}
	httpLn, err := net.Listen("tcp", "127.0.0.1:"+pb.HTTPPort)
	if err != nil {
		t.Fatal(err)
	}
	cfg := m.TLSConfig()
	hs := &http.Server{TLSConfig: cfg, Handler: http.NotFoundHandler(), ReadHeaderTimeout: 5 * time.Second}
	ps := &http.Server{Handler: m.HTTPHandler(nil), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = hs.ServeTLS(tlsLn, "", "") }()
	go func() { _ = ps.Serve(httpLn) }()
	conn, err := tls.Dial("tcp", "127.0.0.1:"+pb.TLSPort, &tls.Config{ServerName: "up.test", InsecureSkipVerify: true}) //nolint:gosec // the test reads the serial only
	if err != nil {
		t.Fatalf("autocert did not order: %v", err)
	}
	before := conn.ConnectionState().PeerCertificates[0]
	_ = conn.Close()
	_ = hs.Close()
	_ = ps.Close()
	files := map[string][]byte{}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		files[e.Name()] = b
	}
	if _, ok := files["acme_account+key"]; !ok || files["up.test"] == nil {
		t.Fatalf("autocert's directory: %v", entries)
	}
	orders, accounts := pb.orders(), strings.Count(pb.log(), "There are now 1 accounts")+strings.Count(pb.log(), "There are now 2 accounts")
	if orders != 1 || accounts != 1 {
		t.Fatalf("autocert ordered %d times and registered %d accounts", orders, accounts)
	}

	// The upgrade: CertMagic with the same directory and the account named from the import.
	f := newFixture(t, pb, []string{"up.test"}, func(s *Settings) { s.AutocertDir = dir })
	if err := f.svc.Start(f.ctx); err != nil {
		t.Fatal(err)
	}
	f.serve(f.svc)
	if got := f.served(f.svc, "up.test"); got != serialHex(before) {
		t.Fatalf("serves %s, autocert had %s", got, serialHex(before))
	}
	// The scheduler's passes order nothing and register nothing.
	for i := 0; i < 3; i++ {
		f.tick(f.svc)
	}
	r := f.row(f.svc, "up.test")
	if r.Serial != serialHex(before) || !r.Imported || !r.LastAttemptAt.IsZero() {
		t.Fatalf("after the upgrade: serial %s imported %v attempted %v", r.Serial, r.Imported, r.LastAttemptAt)
	}
	if got := pb.orders(); got != orders {
		t.Fatalf("the upgrade placed %d orders", got-orders)
	}
	if strings.Contains(pb.log(), "There are now 2 accounts") {
		t.Fatal("the upgrade registered an account")
	}
	if f.auditCount("tls.import") != 1 || f.auditCount("tls.certificate_obtain") != 0 || f.auditCount("tls.account_register") != 0 {
		t.Fatal("the audit trail of the upgrade")
	}
	// The directory is left as it was, for a rollback.
	for name, b := range files {
		if got, err := os.ReadFile(filepath.Join(dir, name)); err != nil || string(got) != string(b) {
			t.Fatalf("%s in autocert's directory changed: %v", name, err)
		}
	}
	// A second start imports nothing more.
	svc2 := f.build([]string{"up.test"}, func(s *Settings) { s.AutocertDir = dir })
	defer svc2.Close()
	if err := svc2.Start(f.ctx); err != nil {
		t.Fatal(err)
	}
	if f.auditCount("tls.import") != 1 {
		t.Fatal("the import ran again")
	}
	// The account is the one autocert registered: named for CertMagic, found at the CA, and the only one stored.
	if !f.svc.accountReady {
		t.Fatal("the account was not established")
	}
	folders, err := f.svc.Storage().List(f.ctx, f.svc.usersPrefix(), false)
	if err != nil || len(folders) != 1 {
		t.Fatalf("accounts stored: %v %v", folders, err)
	}
}

// What autocert did not keep valid is not imported.
func TestImportSkipsWhatIsNotUsable(t *testing.T) {
	pb := startPebble(t, 3600)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "x.test"), []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "x.test+rsa"), []byte("skipped"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := newFixture(t, pb, []string{"x.test"}, func(s *Settings) { s.AutocertDir = dir })
	if err := f.svc.Start(f.ctx); err != nil {
		t.Fatal(err)
	}
	if f.row(f.svc, "x.test").HasCertificate() || f.auditCount("tls.import") != 0 {
		t.Fatal("something unusable was imported")
	}
}
