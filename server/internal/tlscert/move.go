package tlscert

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
)

// Remaining is how long until the waiting certificate may be applied under
// the rule for MeshCentral's name: three minutes after its last read of
// certUrl. Zero when MeshCentral never read, or the time has passed.
func (m *MeshSlot) Remaining(now time.Time) time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastRead.IsZero() {
		return 0
	}
	if d := m.lastRead.Add(meshWait).Sub(now); d > 0 {
		return d
	}
	return 0
}

// SwapDelay says how long a move's swap of the name must still wait: for
// MeshCentral's name, until three minutes after its last read of certUrl
// (ADR-0055); other names do not wait.
func (s *Service) SwapDelay(name string) time.Duration {
	if s.set.MeshName == "" || !strings.EqualFold(name, s.set.MeshName) {
		return 0
	}
	return s.slot.Remaining(s.deps.Now())
}

// PrepareMove makes ready what a move to Let's Encrypt needs, serving none of
// it (ADR-0055, "Moving between sources"): the account is registered unless
// the deployment has one, CAA is checked again against the account's URI, and
// the real order is placed when the name has no certificate yet. It returns
// the chain, leaf first, as DER, and the notes the page shows.
//
// The trial order against staging is not run here: CertMagic's issuer is
// bound to the production directory, and the trial needs an issuer of its own.
// The note says so.
func (s *Service) PrepareMove(ctx context.Context, name string) (chain [][]byte, accountURL string, notes []string, err error) {
	name = strings.ToLower(name)
	if !s.Managed(name) {
		return nil, "", nil, ErrNoName
	}
	if err := s.ensureAccount(ctx); err != nil {
		return nil, "", nil, fmt.Errorf("%w: %s", ErrNoAccount, err.Error())
	}
	s.mu.Lock()
	accountURL = s.acctURI
	s.mu.Unlock()
	if c := s.caaCheck(ctx, name); c.Status == CheckFail {
		return nil, "", nil, &RefusedError{Reason: c.Detail + " " + c.Fix}
	}
	notes = []string{"The trial order against Let's Encrypt's staging service was not run; the real order was placed directly."}
	if !s.store.Exists(ctx, certmagic.StorageKeys.SiteCert(s.issuerKey(), name)) {
		if err := s.attempt(ctx, name, kindRetry); err != nil {
			return nil, "", nil, err
		}
	}
	chain, err = s.StoredChain(ctx, name)
	return chain, accountURL, notes, err
}

// StoredChain returns the stored certificate chain of a name, leaf first.
func (s *Service) StoredChain(ctx context.Context, name string) ([][]byte, error) {
	crt, err := s.store.Load(ctx, certmagic.StorageKeys.SiteCert(s.issuerKey(), strings.ToLower(name)))
	if err != nil {
		return nil, errNoCertificate
	}
	var out [][]byte
	for {
		var b *pem.Block
		b, crt = pem.Decode(crt)
		if b == nil {
			break
		}
		if b.Type == "CERTIFICATE" {
			out = append(out, b.Bytes)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("tls: the stored certificate holds no certificate")
	}
	return out, nil
}
