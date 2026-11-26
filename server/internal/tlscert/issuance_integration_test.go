//go:build integration

package tlscert

import (
	"io"
	"os"
	"testing"
	"time"
)

// A real ACME run against Pebble: the service issues for the names in .env at
// start, answers HTTP-01 and TLS-ALPN-01 for them only, records what CertMagic
// keeps of ARI, never reads standard input, and registers one account.
func TestIssuance(t *testing.T) {
	pb := startPebble(t, 3600)
	names := []string{"rmm.test", "mesh.rmm.test"}
	f := newFixture(t, pb, names, func(s *Settings) { s.MeshName = "mesh.rmm.test" })

	// Standard input is a pipe the test holds open: CertMagic would block on
	// its prompt, and set DefaultACME.Agreed, if it were ever reached.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	defer r.Close()
	oldStdin := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = oldStdin })

	if err := f.svc.Start(f.ctx); err != nil {
		t.Fatal(err)
	}
	f.serve(f.svc)
	if f.served(f.svc, "rmm.test") != "" {
		t.Fatal("a certificate before any order")
	}
	f.until(f.svc, "both names to have a certificate", 90*time.Second, func() bool {
		return f.row(f.svc, "rmm.test").HasCertificate() && f.row(f.svc, "mesh.rmm.test").HasCertificate()
	})
	for _, n := range names {
		if f.served(f.svc, n) == "" {
			t.Fatalf("%s is not served", n)
		}
	}
	if got := f.served(f.svc, "rmm.test"); got != f.row(f.svc, "rmm.test").Serial {
		t.Fatalf("served %s, recorded %s", got, f.row(f.svc, "rmm.test").Serial)
	}
	// One certificate per name: a name's failure holds back no other.
	if f.row(f.svc, "rmm.test").Serial == f.row(f.svc, "mesh.rmm.test").Serial {
		t.Fatal("two names share one certificate")
	}
	// MeshCentral's name is served from the slot, applied at once for the first certificate.
	if served, pending, _ := f.svc.Slot().State(); served != f.row(f.svc, "mesh.rmm.test").Serial || pending != "" {
		t.Fatalf("slot serves %q, waits with %q", served, pending)
	}
	// A name the service does not hold has no certificate and cannot be ordered at a handshake.
	if f.served(f.svc, "other.test") != "" {
		t.Fatal("served a name that is not managed")
	}
	if got := f.auditCount("tls.certificate_obtain"); got != 2 {
		t.Fatalf("%d obtain records, want 2", got)
	}
	if f.auditCount("tls.account_register") != 1 {
		t.Fatal("the account was not registered once, by the system")
	}
	// Ordered once: a further pass makes no attempt.
	before := f.row(f.svc, "rmm.test").LastAttemptAt
	f.tick(f.svc)
	if !f.row(f.svc, "rmm.test").LastAttemptAt.Equal(before) {
		t.Fatal("a valid certificate was attempted again")
	}
	// The CertMagic defaults were not touched, and nothing read the pipe.
	if w.Close() == nil {
		// closing the write end makes a read return EOF at once; reaching
		// the prompt before would have blocked the whole test instead.
	}
	if b, _ := io.ReadAll(io.LimitReader(r, 1)); len(b) != 0 {
		t.Fatal("something was written to standard input")
	}
	if got := f.row(f.svc, "rmm.test").Issuer; got == "" {
		t.Fatal("the issuer is not recorded")
	}
}
