package notify

import (
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/addrpolicy"
)

// transportIdle is how long a channel's transport lives unused.
const transportIdle = 10 * time.Minute

// transport is one channel's HTTP client. No connection serves two
// policies: it is made for one channel, keyed by the channel's generation
// (any change of its host, port, approval, trusted authority or policy
// increases it) and by the environment it was made under, and its dialer's
// Control is a closure bound to that policy and those approved prefixes.
type transport struct {
	gen    int64
	envVer uint64
	client *http.Client
	tr     *http.Transport
	used   time.Time
}

// clientFor returns the channel's client, made when first needed or when
// the generation or the environment changed.
func (s *Service) clientFor(id uuid.UUID, gen int64, pol addrpolicy.Policy, ca []byte) (*http.Client, error) {
	s.tmu.Lock()
	defer s.tmu.Unlock()
	ver := s.env.Version()
	if t, ok := s.transports[id]; ok {
		if t.gen == gen && t.envVer == ver {
			t.used = s.now()
			return t.client, nil
		}
		t.tr.CloseIdleConnections()
		delete(s.transports, id)
	}
	c, tr, err := addrpolicy.NewClient(pol, ca)
	if err != nil {
		return nil, err
	}
	s.transports[id] = &transport{gen: gen, envVer: ver, client: c, tr: tr, used: s.now()}
	return c, nil
}

// dropTransport closes a channel's transport and forgets it: its generation
// changed, or it was deleted or turned off.
func (s *Service) dropTransport(id uuid.UUID) {
	s.tmu.Lock()
	defer s.tmu.Unlock()
	if t, ok := s.transports[id]; ok {
		t.tr.CloseIdleConnections()
		delete(s.transports, id)
	}
}

// sweepTransports drops those unused for ten minutes.
func (s *Service) sweepTransports() {
	s.tmu.Lock()
	defer s.tmu.Unlock()
	for id, t := range s.transports {
		if s.now().Sub(t.used) > transportIdle {
			t.tr.CloseIdleConnections()
			delete(s.transports, id)
		}
	}
}

// transportCount is how many channels have a transport now, for tests.
func (s *Service) transportCount() int {
	s.tmu.Lock()
	defer s.tmu.Unlock()
	return len(s.transports)
}
