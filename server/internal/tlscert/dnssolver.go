package tlscert

import (
	"context"
	"fmt"
	"sync"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v3/acme"
)

// dnsSolverMux dispatches DNS-01 challenges to per-zone solvers looked up at
// challenge time (ADR-0055, 5b4). It implements acmez.Solver and acmez.Waiter.
type dnsSolverMux struct {
	lookup func(ctx context.Context, name string) (*certmagic.DNS01Solver, error)

	mu      sync.Mutex
	solvers map[string]*certmagic.DNS01Solver
}

func newDNSSolverMux(lookup func(ctx context.Context, name string) (*certmagic.DNS01Solver, error)) *dnsSolverMux {
	return &dnsSolverMux{lookup: lookup, solvers: map[string]*certmagic.DNS01Solver{}}
}

func (m *dnsSolverMux) solverFor(ctx context.Context, ch acme.Challenge) (*certmagic.DNS01Solver, error) {
	name := ch.Identifier.Value
	m.mu.Lock()
	s, ok := m.solvers[name]
	m.mu.Unlock()
	if ok {
		return s, nil
	}

	s, err := m.lookup(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("tlscert: looking up DNS solver for %q: %w", name, err)
	}
	if s == nil {
		return nil, fmt.Errorf("tlscert: no DNS-01 credentials for %q", name)
	}

	m.mu.Lock()
	m.solvers[name] = s
	m.mu.Unlock()
	return s, nil
}

func (m *dnsSolverMux) Present(ctx context.Context, ch acme.Challenge) error {
	s, err := m.solverFor(ctx, ch)
	if err != nil {
		return err
	}
	return s.Present(ctx, ch)
}

func (m *dnsSolverMux) Wait(ctx context.Context, ch acme.Challenge) error {
	s, err := m.solverFor(ctx, ch)
	if err != nil {
		return err
	}
	return s.Wait(ctx, ch)
}

func (m *dnsSolverMux) CleanUp(ctx context.Context, ch acme.Challenge) error {
	s, err := m.solverFor(ctx, ch)
	if err != nil {
		return err
	}
	defer func() {
		m.mu.Lock()
		delete(m.solvers, ch.Identifier.Value)
		m.mu.Unlock()
	}()
	return s.CleanUp(ctx, ch)
}
