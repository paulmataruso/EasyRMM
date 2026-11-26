package app

import (
	"log/slog"
	"net/netip"
	"strings"

	"github.com/paulmataruso/easyrmm/server/internal/addrpolicy"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/config"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/mailserver"
	"github.com/paulmataruso/easyrmm/server/internal/notify"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
)

// newNotify builds the notification sender (ADR-0053). The address policy
// learns the server's own addresses (its interfaces', and
// EASYRMM_IP_ADDRESSES) and names (the public URLs' hosts and the extra
// names the edge serves), which no organization's destination may be.
func newNotify(cfg *config.Config, db *database.DB, auditLog *audit.Logger, sealer *secrets.Sealer, mail *mailserver.Service, log *slog.Logger) *notify.Service {
	names := func() []string {
		var out []string
		if cfg.PublicURL != nil {
			out = append(out, cfg.PublicURL.Hostname())
		}
		if cfg.MeshPublicURL != nil {
			out = append(out, cfg.MeshPublicURL.Hostname())
		}
		return append(out, cfg.ExtraHostnames()...)
	}
	var extra []netip.Addr
	extra = append(extra, cfg.IPAddresses...)
	for _, n := range names() {
		if a, err := netip.ParseAddr(strings.Trim(n, "[]")); err == nil {
			extra = append(extra, a.Unmap())
		}
	}
	svc := notify.New(db, auditLog, sealer, addrpolicy.NewEnvironment(names, extra), mail, log)
	if cfg.PublicURL != nil {
		svc.SetConsoleURL(cfg.PublicURL.String())
	}
	return svc
}
