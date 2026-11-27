package app

import (
	"context"
	"log/slog"
	"net"
	"net/netip"

	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/config"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/tlsaddname"
)

// newTLSAdd builds the service that adds a name pair to an IP install
// (ADR-0055, 5b3). Without the certificate service (it exists in acme mode)
// adding is refused as unavailable; see docs/notes/5b3.md.
func newTLSAdd(cfg *config.Config, db *database.DB, auditLog *audit.Logger, d *Deps, log *slog.Logger) *tlsaddname.Service {
	dep := tlsaddname.Deps{
		DB: db, Audit: auditLog, Moves: d.TLSMove, Trust: d.TLSTrust, Log: log,
		IPInstall: func() bool {
			if cfg.PublicURL == nil {
				return false
			}
			_, err := netip.ParseAddr(cfg.PublicURL.Hostname())
			return err == nil
		},
		ServerIPs: func(context.Context) []net.IP {
			var out []net.IP
			for _, a := range ownAddresses(cfg) {
				out = append(out, net.IP(a.AsSlice()))
			}
			return out
		},
		OnTrust: func(console, mesh string, trusted bool) {
			log.Info("tls: the added name pair changed trust", "console", console, "mesh", mesh, "trusted", trusted)
		},
	}
	if d.PKI != nil {
		dep.Auth = d.PKI
	}
	if d.Notify != nil {
		dep.Notices = tlsNotices{n: d.Notify}
	}
	if d.TLS != nil {
		dep.Held = func(ctx context.Context, name string) bool {
			chain, err := d.TLS.StoredChain(ctx, name)
			return err == nil && len(chain) > 0
		}
	}
	return tlsaddname.New(dep)
}
