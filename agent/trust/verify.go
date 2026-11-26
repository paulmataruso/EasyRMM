// Package trust is the agent's side of ADR-0055's trust instruction: it
// verifies the certificate chains a server asks about with the trust this
// computer really has, and widens that trust, for the agent's origin only,
// when a target chain verifies and the instruction is signed with the job key
// the agent pinned. Nothing here widens trust from anything else.
package trust

import (
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// Verifier checks chains the way a TLS client would.
type Verifier struct {
	// SystemRoots replaces the computer's own roots (tests). Nil is the
	// platform's verifier on Windows and macOS, and the distribution's bundle
	// on Linux, which is what the agent's connections use.
	SystemRoots *x509.CertPool
	// Now is the time chains are valid at; nil is the clock.
	Now func() time.Time
}

func (v Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// Verify checks that chain (leaf first) is valid for host against the system's
// roots and, when pool is not nil, against pool as well. It passes when either
// does; the chain's other certificates are taken as intermediates. The error
// is the first failure's, bounded for the report.
func (v Verifier) Verify(chain []*x509.Certificate, host string, system bool, pool *x509.CertPool) error {
	if len(chain) == 0 {
		return errors.New("the chain is empty")
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	opts := x509.VerifyOptions{DNSName: host, Intermediates: inter, CurrentTime: v.now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	var first error
	if system {
		opts.Roots = v.SystemRoots // nil: the platform's own
		_, err := chain[0].Verify(opts)
		if err == nil {
			return nil
		}
		first = err
	}
	if pool != nil {
		opts.Roots = pool
		_, err := chain[0].Verify(opts)
		if err == nil {
			return nil
		}
		if first == nil {
			first = err
		}
	}
	if first == nil {
		return errors.New("there are no roots to verify against")
	}
	return first
}

// reason makes an error fit a report: one line, bounded.
func reason(err error) string {
	s := strings.Join(strings.Fields(err.Error()), " ")
	if len(s) > agentproto.MaxTrustError {
		s = s[:agentproto.MaxTrustError]
	}
	return s
}

// parseChain decodes a chain of an instruction.
func parseChain(c agentproto.TrustChain) ([]*x509.Certificate, error) {
	out := make([]*x509.Certificate, 0, len(c.Chain))
	for _, s := range c.Chain {
		cert, err := agentproto.DecodeTrustCert(s)
		if err != nil {
			return nil, fmt.Errorf("the chain does not decode: %w", err)
		}
		out = append(out, cert)
	}
	return out, nil
}
