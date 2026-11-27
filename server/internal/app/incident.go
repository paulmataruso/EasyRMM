package app

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/config"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/jobkeys"
)

// IncidentRestored records that this server was restored from a backup
// (ADR-0057): `easyrmm-server incident restored`, which the guide's restore
// procedure runs on the host after pg_restore. Every device's instruction log
// entries dated before at become not checked (the rows that would match them
// may be gone), and a possible unrecorded restore that devices raised is
// confirmed. It needs the server's configuration and database, nothing else.
func IncidentRestored(ctx context.Context, cfg *config.Config, log *slog.Logger, at time.Time, out io.Writer) error {
	migCfg, err := pgx.ParseConfig(cfg.DatabaseMigrationURL)
	if err != nil {
		return fmt.Errorf("EASYRMM_DATABASE_MIGRATION_URL: %w", err)
	}
	if err := database.MigrateWithConfig(ctx, migCfg, log); err != nil {
		return err
	}
	db, err := database.Open(ctx, cfg.DatabaseURL, database.PoolOptions{MaxConns: 2, Version: Version})
	if err != nil {
		return err
	}
	defer db.Close()
	confirmed, err := jobkeys.RecordRestore(ctx, db, audit.New(db, time.Now), at)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "Recorded a restore at %s: instruction log entries dated before it are no longer checked, for every device.\n"+
		"Possible unrecorded restores confirmed: %d.\n", at.UTC().Format(time.RFC3339), confirmed)
	return err
}
