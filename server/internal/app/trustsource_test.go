package app

import (
	"crypto/tls"
	"errors"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// The agent trust service learns what a host is served with from the same
// function the edge answers handshakes with, called with the host's name and a
// connection of its own (certmagic reads the peer's address).
func TestEdgeSourceAsksTheEdgeForTheHostsChain(t *testing.T) {
	var asked *tls.ClientHelloInfo
	get := func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		asked = h
		return &tls.Certificate{Certificate: [][]byte{{1}, {2}}}, nil
	}
	got := edgeSource{get: get}.Chains("rmm.example.com")
	if len(got) != 1 || got[0].Purpose != agentproto.TrustServed || len(got[0].DER) != 2 {
		t.Fatalf("chains = %+v", got)
	}
	if asked.ServerName != "rmm.example.com" || asked.Conn == nil || asked.Conn.RemoteAddr() == nil || asked.Conn.LocalAddr() == nil {
		t.Errorf("hello = %+v", asked)
	}
	if err := asked.Conn.Close(); err != nil {
		t.Error(err)
	}
	if err := asked.Conn.(probeConn).SetDeadline(time.Time{}); err != nil {
		t.Error(err)
	}
	for name, f := range map[string]getCertificate{
		"an error":      func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, errors.New("none") },
		"no certifcate": func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, nil },
		"no chain":      func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &tls.Certificate{}, nil },
	} {
		if got := (edgeSource{get: f}).Chains("x.example.com"); got != nil {
			t.Errorf("%s: chains = %+v", name, got)
		}
	}
}
