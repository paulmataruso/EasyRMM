//go:build windows

package trust

import (
	"crypto/x509"
	"testing"
	"time"
)

// On Windows the system's roots are the platform's own verifier (CryptoAPI),
// so a root update turned off by Group Policy shows in the result. The
// Windows CI job runs this on a real Windows machine (ADR-0055, Testing).

// A chain from an authority this machine does not trust fails the platform's
// verifier, and passes once the authority is in the pool the agent adds.
func TestPlatformVerifierRejectsAnUnknownAuthorityAndTakesTheAddedOne(t *testing.T) {
	ca := newCA(t, "Easyrmm Test Authority Not In The Store")
	leaf := ca.leaf(t, testHost)
	v := Verifier{Now: func() time.Time { return t0 }} // SystemRoots nil: the platform's
	chain := []*x509.Certificate{leaf}

	if err := v.Verify(chain, testHost, true, nil); err == nil {
		t.Fatal("the platform's verifier trusted an authority nobody installed")
	}
	if err := v.Verify(chain, testHost, true, ca.pool()); err != nil {
		t.Errorf("the added authority did not anchor the chain: %v", err)
	}
	if err := v.Verify(chain, "other.example.com", true, ca.pool()); err == nil {
		t.Error("a chain verified for another host name")
	}
}

// A certificate that is not the server's (a certificate authority's own) is
// refused for a host name by the platform's verifier too.
func TestPlatformVerifierChecksTheHostName(t *testing.T) {
	ca := newCA(t, "Easyrmm Test Authority Two")
	v := Verifier{Now: func() time.Time { return t0 }}
	if err := v.Verify([]*x509.Certificate{ca.ca}, testHost, true, ca.pool()); err == nil {
		t.Error("an authority's certificate verified for a host name")
	}
}
