package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/config"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/easypatch"
	"github.com/paulmataruso/easyrmm/server/internal/tenancy"
)

// ImportEasyPatch is `easyrmm-server import-easypatch` (ADR-0045): with a
// standalone EasyPatch's database restored as the patching engine's, it makes
// the engine's organizations and sites EasyRMM's and prints what it did.
// deploy/scripts/import-easypatch.sh runs it with the server stopped, so that
// the reconciler does not act on the engine's records before they are linked.
func ImportEasyPatch(ctx context.Context, cfg *config.Config, log *slog.Logger, out io.Writer) error {
	migCfg, err := pgx.ParseConfig(cfg.DatabaseMigrationURL)
	if err != nil {
		return fmt.Errorf("EASYRMM_DATABASE_MIGRATION_URL: %w", err)
	}
	if err := waitFor(ctx, log, "database", func(ctx context.Context) error {
		return database.MigrateWithConfig(ctx, migCfg, log)
	}); err != nil {
		return err
	}
	db, err := database.Open(ctx, cfg.DatabaseURL, database.PoolOptions{MaxConns: 4, Version: Version})
	if err != nil {
		return err
	}
	defer db.Close()
	signer, err := easypatch.NewSigner(cfg.Patching.Key)
	if err != nil {
		return err
	}
	engine, err := easypatch.NewEngineClient(cfg.Patching.URL, signer, Version)
	if err != nil {
		return err
	}
	// Waits while the engine starts; an answer, even a refusal, ends the
	// wait, and Import then says what the engine refused.
	if err := waitFor(ctx, log, "patching engine", func(ctx context.Context) error {
		_, err := engine.ServerInfo(ctx)
		var answer *easypatch.Error
		if errors.As(err, &answer) && answer.Status != 0 {
			return nil
		}
		return err
	}); err != nil {
		return err
	}
	auditLog := audit.New(db, time.Now)
	svc := easypatch.New(db, auditLog, Version, log)
	if err := svc.UseEngine(engine); err != nil {
		return err
	}
	rep, err := svc.Import(ctx, tenancy.New(db, auditLog))
	if err != nil {
		return err
	}
	return WriteImportReport(out, &rep)
}

// WriteImportReport prints an import's report for the operator.
func WriteImportReport(w io.Writer, rep *easypatch.ImportReport) error {
	var err error
	p := func(format string, args ...any) {
		if err == nil {
			_, err = fmt.Fprintf(w, format, args...)
		}
	}
	orgsJoined, orgsCreated := rep.Count("organization")
	sitesJoined, sitesCreated := rep.Count("site")
	p("Imported %d organization(s) (%d new in EasyRMM, %d joined EasyRMM's of the same name) and %d site(s) (%d new, %d joined).\n",
		orgsJoined+orgsCreated, orgsCreated, orgsJoined, sitesJoined+sitesCreated, sitesCreated, sitesJoined)
	for _, r := range rep.Records {
		what := "new"
		if r.Joined {
			what = "joined"
		}
		switch {
		case r.Kind == "organization" && r.Name == r.EngineName:
			p("  organization %q (%s)\n", r.Name, what)
		case r.Kind == "organization":
			p("  organization %q, now %q (%s): EasyRMM's names are unique ignoring case\n", r.EngineName, r.Name, what)
		case r.Name == r.EngineName:
			p("    site %q (%s)\n", r.Name, what)
		default:
			p("    site %q, now %q (%s): EasyRMM's names are unique ignoring case\n", r.EngineName, r.Name, what)
		}
	}
	if rep.ArchivedOrganizations > 0 || rep.ArchivedSites > 0 {
		p("Not imported: %d archived organization(s) and %d archived site(s), which stay archived in the patching engine.\n",
			rep.ArchivedOrganizations, rep.ArchivedSites)
	}
	for _, x := range rep.Warnings {
		p("Note: %s\n", x)
	}
	return err
}
