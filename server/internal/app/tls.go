package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"

	"github.com/paulmataruso/easyrmm/server/internal/config"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
	"github.com/paulmataruso/easyrmm/server/internal/tlscert"
)

// tlsSettings are the certificate service's settings from the environment.
func tlsSettings(cfg *config.Config) tlscert.Settings {
	names := acmeHosts(cfg)
	sort.Strings(names)
	names = slices.Compact(names)
	mesh := ""
	if cfg.MeshPublicURL != nil && slices.Contains(names, cfg.MeshPublicURL.Hostname()) {
		mesh = cfg.MeshPublicURL.Hostname()
	}
	host, _ := os.Hostname()
	set := tlscert.Settings{
		Names: names, MeshName: mesh,
		Directory: cfg.ACMEDirectory, Email: cfg.ACMEEmail, RootsPEM: cfg.ACMERoots,
		TLSPort:     portOf(cfg.ListenHTTPS),
		AutocertDir: filepath.Join(cfg.DataDir, "acme"),
		Instance:    host,
		Own:         func() []netip.Addr { return ownAddresses(cfg) },
		Warnings:    cfg.Notes,
	}
	if cfg.ListenHTTP != "" {
		set.HTTPPort = portOf(cfg.ListenHTTP)
	}
	return set
}

func portOf(listen string) string {
	if _, p, err := net.SplitHostPort(listen); err == nil {
		return p
	}
	return ""
}

// ownAddresses are this server's addresses: those of its interfaces, and
// EASYRMM_IP_ADDRESSES (which the operator corrects behind NAT).
func ownAddresses(cfg *config.Config) []netip.Addr {
	out := slices.Clone(cfg.IPAddresses)
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if p, err := netip.ParsePrefix(a.String()); err == nil {
				out = append(out, p.Addr().Unmap())
			}
		}
	}
	return out
}

// ErrTLSChecksFailed is returned by TLSCheck when a check failed.
var ErrTLSChecksFailed = errors.New("a check failed")

// TLSCheck runs the checks of the Certificates page for every name the server
// holds a certificate for, as the page does, and prints each as a tick, a
// warning or a failure with its fix. It returns ErrTLSChecksFailed when a
// check failed; a warning does not fail it (setup.sh runs it after install,
// and DNS may follow).
//
//	docker compose exec server easyrmm-server tls check
func TLSCheck(ctx context.Context, cfg *config.Config, log *slog.Logger, out io.Writer) error {
	if cfg.TLSMode != config.TLSAcme {
		_, err := fmt.Fprintf(out, "TLS mode is %s: this server does not obtain certificates, so there is nothing to check.\n", cfg.TLSMode)
		return err
	}
	sealer, err := secrets.NewSealer(cfg.SecretKeys...)
	if err != nil {
		return err
	}
	db, err := database.Open(ctx, cfg.DatabaseURL, database.PoolOptions{MaxConns: 2, Version: Version})
	if err != nil {
		return err
	}
	defer db.Close()
	svc := tlscert.New(tlscert.Deps{DB: db, Sealer: sealer, Log: log}, tlsSettings(cfg))
	failed := false
	for _, name := range tlsSettings(cfg).Names {
		fmt.Fprintf(out, "%s\n", name)
		checks, err := svc.Check(ctx, name)
		if err != nil {
			return err
		}
		for _, c := range checks {
			mark := map[string]string{tlscert.CheckOK: "ok  ", tlscert.CheckWarn: "warn", tlscert.CheckFail: "FAIL"}[c.Status]
			fmt.Fprintf(out, "  [%s] %s: %s\n", mark, c.Title, c.Detail)
			if c.Fix != "" && c.Status != tlscert.CheckOK {
				fmt.Fprintf(out, "         fix: %s\n", c.Fix)
			}
			failed = failed || c.Status == tlscert.CheckFail
		}
	}
	if failed {
		return ErrTLSChecksFailed
	}
	return nil
}
