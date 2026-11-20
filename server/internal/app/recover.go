package app

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/config"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// Recover prints a one-time sign-in link for a super administrator (the
// one with email, or the only one): the way in when single sign-on is down
// (ADR-0044). It needs the server's configuration and database, nothing
// else: Authentik may be stopped.
func Recover(ctx context.Context, cfg *config.Config, log *slog.Logger, email string, out io.Writer) error {
	migCfg, err := pgx.ParseConfig(cfg.DatabaseMigrationURL)
	if err != nil {
		return fmt.Errorf("EASYRMM_DATABASE_MIGRATION_URL: %w", err)
	}
	if err := database.MigrateWithConfig(ctx, migCfg, log); err != nil {
		return err
	}
	db, err := database.Open(ctx, cfg.DatabaseURL, database.PoolOptions{MaxConns: 2})
	if err != nil {
		return err
	}
	defer db.Close()
	link, err := auth.IssueRecoveryLink(ctx, db, audit.New(db, time.Now), email, time.Now())
	if err != nil {
		return err
	}
	u := *cfg.PublicURL
	u.Path, u.RawQuery, u.Fragment = auth.RecoveryPath, "", "token="+link.Token
	_, err = fmt.Fprintf(out, "One-time sign-in link for %s, valid for %d minutes:\n\n  %s\n\n"+
		"Open it in a browser. It works once, signs in without single sign-on, and is in the audit log.\n",
		link.Email, int(auth.RecoveryLinkTTL/time.Minute), u.String())
	return err
}
