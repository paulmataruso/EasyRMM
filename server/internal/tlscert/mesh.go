package tlscert

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"
)

// MeshCentral reads the certificate its agents see through certUrl, and
// throttles its reads, not EasyRMM's swaps: a read within two minutes of the
// previous one returns at once, and a held agent is released only by a read
// that finds a changed certificate. A swap shortly after a read would leave
// agents that reconnect held for hours in a small fleet, so a new certificate
// for MeshCentral's name waits until it has been three minutes since the last
// read, at most fifteen after it was ready (ADR-0055).
var (
	meshWait = 3 * time.Minute
	meshCap  = 15 * time.Minute
)

// MeshSlot holds the certificate served for MeshCentral's name, and the one
// waiting to be applied. The edge serves the slot's certificate for that
// name on every listener, MeshCentral's dedicated one included, so that what
// MeshAgents see and what MeshCentral reads are one thing, swapped atomically.
type MeshSlot struct {
	mu       sync.Mutex
	served   *tls.Certificate
	servedSN string
	pending  *tls.Certificate
	pendSN   string
	ready    time.Time
	urgent   bool
	lastRead time.Time
}

// Served returns the certificate being served, nil before there is one.
func (m *MeshSlot) Served() *tls.Certificate {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.served
}

// State returns the serial served, and the one waiting with the time it
// became ready.
func (m *MeshSlot) State() (served, pending string, ready time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.servedSN, m.pendSN, m.ready
}

// Offer makes cert the next one to serve. The first certificate is applied
// at once, since nothing is held on it; a later one waits (Tick). urgent is
// the CA's signal that what is served will be revoked: it applies at once.
func (m *MeshSlot) Offer(cert *tls.Certificate, serial string, ready time.Time, urgent bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if serial == m.servedSN || serial == m.pendSN {
		return
	}
	if m.served == nil {
		m.served, m.servedSN = cert, serial
		return
	}
	m.pending, m.pendSN, m.ready, m.urgent = cert, serial, ready, urgent
}

// RecordRead notes a read by MeshCentral.
func (m *MeshSlot) RecordRead(t time.Time) {
	m.mu.Lock()
	m.lastRead = t
	m.mu.Unlock()
}

// SetLastRead restores the time of the last read after a restart.
func (m *MeshSlot) SetLastRead(t time.Time) {
	m.mu.Lock()
	if t.After(m.lastRead) {
		m.lastRead = t
	}
	m.mu.Unlock()
}

// Tick applies the waiting certificate when its time has come: three minutes
// after MeshCentral's last read, fifteen after it was ready whatever the
// reads, at once when urgent, and never later than the served certificate's
// expiry. It reports whether it applied one.
func (m *MeshSlot) Tick(now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pending == nil {
		return false
	}
	apply := m.urgent ||
		m.lastRead.IsZero() || now.Sub(m.lastRead) >= meshWait ||
		now.Sub(m.ready) >= meshCap
	if !apply && m.served != nil && m.served.Leaf != nil && !now.Before(m.served.Leaf.NotAfter) {
		apply = true
	}
	if !apply {
		return false
	}
	m.served, m.servedSN = m.pending, m.pendSN
	m.pending, m.pendSN, m.urgent = nil, "", false
	return true
}

// ServeMesh serves MeshCentral's reads of certUrl: a listener of its own on
// loopback, which completes the handshake with whatever certificate get
// returns, whatever server name it is sent, and closes. Each handshake is
// one read, passed to onRead. Handshakes on the main listeners never count,
// so a local agent or a monitoring probe is not taken for MeshCentral.
func ServeMesh(ctx context.Context, ln net.Listener, get func(*tls.ClientHelloInfo) (*tls.Certificate, error), onRead func(time.Time)) error {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if onRead != nil {
				onRead(time.Now())
			}
			return get(h)
		},
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil //nolint:nilerr // the listener was closed to stop it
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		go func() {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			_ = tls.Server(c, cfg).HandshakeContext(hctx)
		}()
	}
}
