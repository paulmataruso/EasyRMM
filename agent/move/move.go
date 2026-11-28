// Package move changes the address an agent talks to (ADR-0061, slice 1).
//
// Every change ends with the same check, so the job key always decides: the
// agent asks the new address, with a request signed by its device key, to
// confirm itself with a signature by a job key the agent trusts. Only then is
// the configuration written, once no job or install is running, and the
// agent restarted to read it. Nothing here is an instruction from the
// server; the agent changes address when a person runs set-server or install
// again, or when its own address has been unreachable for an hour and the
// address it came from confirms itself.
package move

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/paulmataruso/easyrmm/agent/state"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// Store is where the agent keeps its address (state.Store).
type Store interface {
	LoadAddresses() state.Addresses
	SetServer(c *state.Config, server string, at time.Time) error
}

// Mover changes the address of one enrolled agent.
type Mover struct {
	// Config is the enrollment the agent runs with; its Server is the address
	// it is at.
	Config *state.Config
	Store  Store
	// Check asks an address whether it is the server the agent trusts: nil
	// when it confirmed itself, an error otherwise. It follows no redirect.
	Check func(ctx context.Context, address string) error
	// Report tells the server at address what happened (ADR-0061's /move). A
	// server that has no such route is not retried: the caller drops the
	// answer. It may be nil.
	Report func(ctx context.Context, address string, r agentproto.MoveReport) error
	// Busy reports that a job or an install is running, which a switch waits
	// for as an update does. Nil never waits.
	Busy func() bool
	// Poll is how often Busy is asked while waiting; zero is 5 seconds.
	Poll time.Duration
	// Now is the clock; nil is time.Now.
	Now func() time.Time
	Log *slog.Logger
}

// ErrSame is returned for a move to the address the agent is at.
var ErrSame = errors.New("the agent is already at that address")

func (m *Mover) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// Move checks the address to and, if it confirms itself, switches the agent
// to it, reporting the change there. A check that fails leaves the agent
// where it was and is reported at its current address, as kind. After a
// switch the caller restarts the agent.
func (m *Mover) Move(ctx context.Context, kind, to string) error {
	target, err := agentproto.MoveTarget(to)
	if err != nil {
		return err
	}
	from := m.Config.Server
	if cur, err := agentproto.MoveTarget(from); err == nil && cur == target {
		return ErrSame
	}
	if err := m.Check(ctx, target); err != nil {
		err = fmt.Errorf("%s did not confirm that it is this agent's server: %w", target, err)
		m.report(ctx, from, agentproto.MoveReport{Kind: kind, From: from, To: target, Error: err.Error()})
		return err
	}
	if err := m.waitIdle(ctx); err != nil {
		return err
	}
	if err := m.Store.SetServer(m.Config, target, m.now()); err != nil {
		err = fmt.Errorf("saving the new address: %w", err)
		m.report(ctx, from, agentproto.MoveReport{Kind: kind, From: from, To: target, Error: err.Error()})
		return err
	}
	m.Config.Server = target
	m.log().Info("the agent's server address changed", "kind", kind, "from", from, "to", target)
	m.report(ctx, target, agentproto.MoveReport{Kind: kind, From: from, To: target, Moved: true})
	return nil
}

// Fallback runs the check at the address the agent last moved from and, if it
// confirms itself, switches back to it. It reports whether the agent
// switched. An agent that has moved nowhere has nowhere to go back to.
func (m *Mover) Fallback(ctx context.Context) bool {
	prev, ok := m.Store.LoadAddresses().Previous()
	if !ok {
		return false
	}
	if err := m.Move(ctx, agentproto.MoveFallback, prev.Server); err != nil {
		if !errors.Is(err, ErrSame) && ctx.Err() == nil {
			m.log().Warn("falling back to the previous address failed", "address", prev.Server, "error", err)
		}
		return false
	}
	return true
}

func (m *Mover) waitIdle(ctx context.Context) error {
	if m.Busy == nil {
		return nil
	}
	poll := m.Poll
	if poll <= 0 {
		poll = 5 * time.Second
	}
	for m.Busy() {
		t := time.NewTimer(poll)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
	return nil
}

// report sends a report to the server at address, bounded and best effort:
// the change is made whatever the answer, and a server without the route
// (a 404) is not tried again.
func (m *Mover) report(ctx context.Context, address string, r agentproto.MoveReport) {
	if m.Report == nil {
		return
	}
	r.Error = truncate(r.Error, agentproto.MaxMoveError)
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if err := m.Report(rctx, address, r); err != nil {
		m.log().Debug("the server did not take the report of the address change", "address", address, "error", err)
	}
}

func (m *Mover) log() *slog.Logger {
	if m.Log != nil {
		return m.Log
	}
	return slog.New(slog.DiscardHandler)
}

func truncate(s string, n int) string {
	s = strings.ToValidUTF8(s, "")
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}
