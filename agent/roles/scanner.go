package roles

import (
	"context"
	"sync"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// Interval is how often the roles are read again (ADR-0073).
const Interval = 6 * time.Hour

// Scanner keeps the last result and reads again when it is older than Every
// or a rescan was asked for. A failed read keeps the last result.
type Scanner struct {
	// Read collects the inputs; nil reports no roles at all, which the
	// server takes as unknown.
	Read func(ctx context.Context) (Inputs, error)
	// Every is the interval; Interval when zero.
	Every time.Duration
	// Now is the clock; time.Now when nil.
	Now func() time.Time

	mu    sync.Mutex
	last  []agentproto.Role
	at    time.Time
	force bool
}

// Rescan makes the next call to Roles read again.
func (s *Scanner) Rescan() {
	s.mu.Lock()
	s.force = true
	s.mu.Unlock()
}

// Roles returns the last result, reading first when it is due. It is nil
// until a read has succeeded.
func (s *Scanner) Roles(ctx context.Context) []agentproto.Role {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Read == nil {
		return nil
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	every := s.Every
	if every == 0 {
		every = Interval
	}
	if !s.at.IsZero() && !s.force && now().Sub(s.at) < every {
		return s.last
	}
	in, err := s.Read(ctx)
	s.force = false
	s.at = now() // a failure waits for the next interval too
	if err != nil {
		return s.last
	}
	s.last = Evaluate(in)
	return s.last
}
