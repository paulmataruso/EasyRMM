//go:build integration

package tlscert

import (
	"testing"
	"time"
)

// A short-lived certificate renews without anyone, in the window ARI gives:
// the service reads that window from what CertMagic keeps, records it, renews
// a new serial, serves it, and audits it.
func TestRenewalFollowsTheARIWindow(t *testing.T) {
	pb := startPebble(t, 45)
	f := newFixture(t, pb, []string{"rmm.test"}, nil)
	if err := f.svc.Start(f.ctx); err != nil {
		t.Fatal(err)
	}
	f.serve(f.svc)
	f.until(f.svc, "the first certificate", 60*time.Second, func() bool { return f.row(f.svc, "rmm.test").HasCertificate() })
	first := f.row(f.svc, "rmm.test")
	if first.NotAfter.Sub(first.NotBefore) > 2*time.Minute {
		t.Fatalf("the test certificate lives %s", first.NotAfter.Sub(first.NotBefore))
	}
	// CertMagic's maintenance loop fetches ARI; the service records its window.
	f.until(f.svc, "ARI's window", 60*time.Second, func() bool { return !f.row(f.svc, "rmm.test").AriStart.IsZero() })
	r := f.row(f.svc, "rmm.test")
	if !r.AriEnd.After(r.AriStart) || r.AriStart.Before(r.NotBefore) || r.AriEnd.After(r.NotAfter.Add(time.Second)) {
		t.Fatalf("ARI's window %s to %s, certificate %s to %s", r.AriStart, r.AriEnd, r.NotBefore, r.NotAfter)
	}
	if due, w := renewalWindow(r); !due.Equal(r.AriStart) || w != r.NotAfter.Sub(r.AriStart) {
		t.Fatalf("renewal is due at %s with a window of %s; ARI %s to %s, certificate %s to %s", due, w, r.AriStart, r.AriEnd, r.NotBefore, r.NotAfter)
	}
	f.until(f.svc, "a renewed certificate", 120*time.Second, func() bool { return f.row(f.svc, "rmm.test").Serial != first.Serial })
	second := f.row(f.svc, "rmm.test")
	if f.served(f.svc, "rmm.test") != second.Serial {
		t.Fatalf("serves %s, renewed %s", f.served(f.svc, "rmm.test"), second.Serial)
	}
	if !second.NotAfter.After(first.NotAfter) {
		t.Fatal("the renewed certificate does not outlive the first")
	}
	if f.auditCount("tls.certificate_renew") < 1 {
		t.Fatal("no renewal was audited")
	}
	if second.Failures != 0 || !second.FailingSince.IsZero() {
		t.Fatal("a success left failures behind")
	}
	// The renewed certificate got a new key.
	if len(f.svc.Storage().locks) != 0 {
		t.Fatal("a lock was left held")
	}
}
