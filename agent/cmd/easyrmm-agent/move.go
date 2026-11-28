package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/paulmataruso/easyrmm/agent/client"
	"github.com/paulmataruso/easyrmm/agent/move"
	"github.com/paulmataruso/easyrmm/agent/state"
	"github.com/paulmataruso/easyrmm/agent/trust"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// Changing the address the agent talks to (ADR-0061, slice 1): set-server, an
// install run again, and the fall-back of a running agent. Each ends with the
// check the move package makes, so the job key always decides.

// moverFor builds the Mover of an enrolled agent: its check and its reports
// are made with clients built for the address concerned, with the trust the
// agent has now (its CA file, and the system's roots when a trust instruction
// widened it).
func (e *env) moverFor(cfg *state.Config, key ed25519.PrivateKey, keys func() agentproto.Keys, busy func() bool) *move.Mover {
	clientFor := func(address string, noRedirect bool) (*client.Client, error) {
		c, err := client.New(client.Options{Server: address, CAFile: cfg.CAFile, TrustSystem: cfg.TrustSystem, Version: Version, NoRedirect: noRedirect})
		if err != nil {
			return nil, err
		}
		c.SetIdentity(cfg.DeviceID, key)
		return c, nil
	}
	return &move.Mover{
		Config: cfg, Store: e.store, Busy: busy, Log: e.log,
		Check: func(ctx context.Context, address string) error {
			c, err := clientFor(address, true)
			if err != nil {
				return err
			}
			return c.ConfirmAddress(ctx, keys())
		},
		Report: func(ctx context.Context, address string, r agentproto.MoveReport) error {
			c, err := clientFor(address, false)
			if err != nil {
				return err
			}
			// A server that predates the route answers 404: dropped, no retry.
			if err := c.Moved(ctx, r); err != nil && !is404(err) {
				return err
			}
			return nil
		},
	}
}

func is404(err error) bool {
	var se *client.Error
	return errors.As(err, &se) && se.Status == 404
}

// storeMover is the Mover of the enrolled agent in the store, for the
// commands that run once: it trusts the keys the store holds.
func (e *env) storeMover(cfg *state.Config, key ed25519.PrivateKey) *move.Mover {
	ks := &trust.KeyStore{DeviceID: cfg.DeviceID, Install: agentproto.InstallID(key.Public().(ed25519.PublicKey)), Config: cfg, Store: e.store, Log: e.log}
	return e.moverFor(cfg, key, ks.Keys, nil)
}

// setServer is `easyrmm-agent set-server https://rmm.example.com` (ADR-0061):
// it asks the address to confirm itself with a job key this agent trusts and,
// if it does, makes it the agent's server and restarts the agent's service.
// It is run as root or administrator on the computer, through Group Policy,
// Intune or at the console; it carries no secret. It is for a computer that
// comes back after the old name was removed, or that is moved by hand.
func (e *env) setServer(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: easyrmm-agent set-server https://rmm.example.com")
	}
	if !e.isRoot() {
		return e.needAdmin("set-server command")
	}
	if err := e.openStore(); err != nil {
		return err
	}
	cfg, key, err := e.store.Load()
	if err != nil {
		return err
	}
	from := cfg.Server
	err = e.storeMover(cfg, key).Move(ctx, agentproto.MoveSetServer, args[0])
	switch {
	case errors.Is(err, move.ErrSame):
		_, _ = fmt.Fprintf(e.stdout, "This agent is already at %s.\n", from)
		return nil
	case err != nil:
		return err
	}
	_, _ = fmt.Fprintf(e.stdout, "This agent now talks to %s (it was at %s).\n", cfg.Server, from)
	e.restartService(ctx, "the new address")
	return nil
}

// restartService restarts the agent's service so that it reads what was saved,
// or says to.
func (e *env) restartService(ctx context.Context, what string) {
	if supported() && e.hasServices() && e.serviceInstalled(ctx) {
		if err := e.sd.Restart(ctx, e.paths.AgentService().Name); err != nil {
			_, _ = fmt.Fprintf(e.stdout, "%s is saved, but restarting the agent's service failed; restart it by hand: %v\n", what, err)
			return
		}
		_, _ = fmt.Fprintln(e.stdout, "The agent's service was restarted.")
		return
	}
	_, _ = fmt.Fprintln(e.stdout, "Restart the agent to use it.")
}

// alreadyEnrolledElsewhere handles `install` run on a computer whose agent is
// enrolled at another address than the one given. When that address is one the
// agent moved from, it says so and succeeds; otherwise it runs the check there
// and, if this same server confirms it for this device, switches as set-server
// does. It returns false when neither holds, and the caller refuses as before.
func (e *env) alreadyEnrolledElsewhere(ctx context.Context, cfg *state.Config, server string) bool {
	_, key, err := e.store.Load()
	if err != nil {
		return false
	}
	// An address the agent left is kept as it was configured, whatever its scheme.
	if e.store.LoadAddresses().Has(mustServer(server)) {
		_, _ = fmt.Fprintf(e.stdout, "Already enrolled; this server is now at %s.\n", cfg.Server)
		return true
	}
	target, err := agentproto.MoveTarget(server)
	if err != nil {
		return false
	}
	if err := e.storeMover(cfg, key).Move(ctx, agentproto.MoveInstall, target); err != nil {
		e.log.Debug("the address given to install is not this agent's server", "address", target, "error", err)
		return false
	}
	_, _ = fmt.Fprintf(e.stdout, "Already enrolled; this server confirmed %s as its address, and the agent now talks to it.\n", cfg.Server)
	return true
}

// printAddress adds the address the agent moved from to `status`.
func (e *env) printAddress() {
	if p, ok := e.store.LoadAddresses().Previous(); ok {
		_, _ = fmt.Fprintf(e.stdout, "Previous:   %s (left %s)\n", p.Server, p.At.Local().Format("2006-01-02 15:04 MST"))
	}
}
