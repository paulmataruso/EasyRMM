package app

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"sync"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/config"
	"github.com/paulmataruso/easyrmm/server/internal/pki"
	"github.com/paulmataruso/easyrmm/server/internal/tlscert"
	"github.com/paulmataruso/easyrmm/server/internal/tlsmove"
)

// moveCerts is the certificate side of a move (ADR-0055, slice 5b2): it
// gets the target source's chain for a name and holds it. The edge serves a
// name from the source tlsmove records (route), so the swap is the one change
// of that record, atomic and without a restart.
type moveCerts struct {
	tls *tlscert.Service // nil unless the server obtains certificates itself
	pki *pki.Authority   // nil without an internal authority

	mu  sync.RWMutex
	env getCertificate // what .env gives names, set once the edge runs
}

// setEnv is called by the edge with the certificate function .env's mode
// serves, before the route wraps it.
func (m *moveCerts) setEnv(g getCertificate) {
	m.mu.Lock()
	m.env = g
	m.mu.Unlock()
}

func (m *moveCerts) Prepare(ctx context.Context, name, target string) (tlsmove.Prepared, error) {
	switch target {
	case tlsmove.SourceACME:
		if m.tls == nil {
			return tlsmove.Prepared{}, tlsmove.ErrUnavailable
		}
		chain, acct, notes, err := m.tls.PrepareMove(ctx, name)
		return tlsmove.Prepared{Chain: chain, Notes: notes, AccountURL: acct}, err
	case tlsmove.SourceAuthority:
		if m.pki == nil {
			return tlsmove.Prepared{}, tlsmove.ErrUnavailable
		}
		c, err := m.pki.Certificate()
		if err != nil {
			return tlsmove.Prepared{}, err
		}
		p := tlsmove.Prepared{Chain: c.Certificate}
		if b, _ := pem.Decode(m.pki.CAPEM()); b != nil {
			p.AddCerts = [][]byte{b.Bytes}
		}
		return p, nil
	default: // env: the fallback, which is what .env's mode serves
		m.mu.RLock()
		g := m.env
		m.mu.RUnlock()
		if g == nil {
			return tlsmove.Prepared{}, tlsmove.ErrUnavailable
		}
		c, err := g(&tls.ClientHelloInfo{ServerName: name, Conn: probeConn{}})
		if err != nil || c == nil || len(c.Certificate) == 0 {
			return tlsmove.Prepared{}, errors.New("the source .env gives this name has no certificate to move back to")
		}
		p := tlsmove.Prepared{Chain: c.Certificate}
		if m.pki != nil {
			if b, _ := pem.Decode(m.pki.CAPEM()); b != nil {
				p.AddCerts = [][]byte{b.Bytes}
			}
		}
		return p, nil
	}
}

// Swap changes nothing itself: the edge reads the recorded source at each
// handshake, and tlsmove records the new one in the same step.
func (m *moveCerts) Swap(context.Context, string, string) error { return nil }

func (m *moveCerts) SwapDelay(_ context.Context, name string) time.Duration {
	if m.tls == nil {
		return 0
	}
	return m.tls.SwapDelay(name)
}

// route serves a name from the source the console chose for it, and from
// base (what .env gives it) otherwise. TLS-ALPN-01 challenges are always
// base's, which is CertMagic's in acme mode.
func (m *moveCerts) route(moves *tlsmove.Service, base getCertificate) getCertificate {
	m.setEnv(base)
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		for _, p := range hello.SupportedProtos {
			if p == "acme-tls/1" {
				return base(hello)
			}
		}
		switch moves.Served(hello.ServerName) {
		case tlsmove.SourceAuthority:
			if m.pki != nil {
				return m.pki.GetCertificate(hello)
			}
		case tlsmove.SourceACME:
			if m.tls != nil {
				return m.tls.GetCertificate(hello)
			}
		}
		return base(hello)
	}
}

// moveNames are the DNS names whose source the console can move: the names
// .env gives certificates to, none when TLS ends at a proxy.
func moveNames(cfg *config.Config) []string {
	if cfg.TLSMode == config.TLSOffload {
		return nil
	}
	return tlsSettings(cfg).Names
}
