package app

import (
	"context"
	"crypto/tls"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/tlstrust"
)

// edgeSource tells the agent trust service what the edge serves for a host:
// the chain it would hand a handshake for that server name, by the same
// function (ADR-0055, slice 5b1). A name's fallback chain comes with the
// sources of 5b2; until then a name has only the chain it is served with.
type edgeSource struct{ get getCertificate }

func (s edgeSource) Chains(host string) []tlstrust.Chain {
	c, err := s.get(&tls.ClientHelloInfo{ServerName: host, Conn: probeConn{}})
	if err != nil || c == nil || len(c.Certificate) == 0 {
		return nil
	}
	return []tlstrust.Chain{{Purpose: agentproto.TrustServed, DER: c.Certificate}}
}

// probeConn stands for the connection of a handshake that is not one: the
// certificate functions read the peer's address, and this one is local.
type probeConn struct{ net.Conn }

func (probeConn) RemoteAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1} }
func (probeConn) LocalAddr() net.Addr  { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443} }
func (probeConn) Close() error         { return nil }
func (probeConn) SetDeadline(time.Time) error {
	return nil
}

// easyPatchHost is the host a device's EasyPatch agent connects to, when the
// device has one linked: the engine's public URL, EASYRMM_PUBLIC_URL, which
// is what EasyPatch agents are installed with (ADR-0055). Empty otherwise.
func easyPatchHost(db *database.DB, publicURL *url.URL) func(context.Context, uuid.UUID) string {
	return func(ctx context.Context, device uuid.UUID) string {
		if publicURL == nil {
			return ""
		}
		var linked bool
		err := db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM easypatch_devices WHERE device_id = $1 AND state = 'linked')`, device).Scan(&linked)
		})
		if err != nil || !linked {
			return ""
		}
		return strings.ToLower(publicURL.Hostname())
	}
}
