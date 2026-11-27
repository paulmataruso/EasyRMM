package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/config"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/jobkeys"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
	"github.com/paulmataruso/easyrmm/server/internal/updater"
)

// JobKeyUsage is what `easyrmm-server job-key` prints for a mistake.
const JobKeyUsage = `usage: easyrmm-server job-key status
       easyrmm-server job-key rotate --reason planned|moving|compromised
       easyrmm-server job-key finish --backup-taken [--now]
       easyrmm-server job-key forget <generation>
       easyrmm-server job-key replace-lost
       easyrmm-server job-key recover <generation>`

// ErrJobKeyUsage is returned for a command line that is not understood.
var ErrJobKeyUsage = errors.New(JobKeyUsage)

// JobKey runs a host command on the ring of job keys (ADR-0057): the same
// operations as the console's, through the same code, each under the ring's
// lock and refused while the updater holds the server or has an upgrade under
// way. It needs the server's configuration and database and loads no key, so it
// works when the server cannot start.
func JobKey(ctx context.Context, cfg *config.Config, log *slog.Logger, args []string, out io.Writer) error {
	if len(args) == 0 {
		return ErrJobKeyUsage
	}
	cmd, rest := args[0], args[1:]
	fs := flag.NewFlagSet("job-key "+cmd, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var (
		reason      = fs.String("reason", "", "")
		backupTaken = fs.Bool("backup-taken", false, "")
		now         = fs.Bool("now", false, "")
	)
	if err := fs.Parse(rest); err != nil {
		return ErrJobKeyUsage
	}
	var gen int64
	switch cmd {
	case "status", "replace-lost":
		if fs.NArg() != 0 {
			return ErrJobKeyUsage
		}
	case "rotate":
		if fs.NArg() != 0 || *reason == "" {
			return ErrJobKeyUsage
		}
	case "finish":
		if fs.NArg() != 0 {
			return ErrJobKeyUsage
		}
	case "forget", "recover":
		if fs.NArg() != 1 {
			return ErrJobKeyUsage
		}
		g, err := strconv.ParseInt(fs.Arg(0), 10, 64)
		if err != nil || g < 1 {
			return ErrJobKeyUsage
		}
		gen = g
	default:
		return ErrJobKeyUsage
	}

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
	sealer, err := secrets.NewSealer(cfg.SecretKeys...)
	if err != nil {
		return err
	}
	ring := jobkeys.NewHost(db, sealer, audit.New(db, time.Now), log, Version, updater.Guard(cfg.UpdaterStatusDir))
	by := jobkeys.HostBy()

	switch cmd {
	case "status":
		keys, err := ring.Snapshot(ctx)
		if err != nil {
			return err
		}
		for _, k := range keys {
			state := "held"
			switch {
			case k.LostAt != nil:
				state = "lost"
			case k.SeedDeletedAt != nil:
				state = "seed forgotten"
			}
			if k.CompromisedAt != nil {
				state += ", compromised"
			}
			if k.CutOverAt != nil {
				state += ", cut over to"
			}
			_, _ = fmt.Fprintf(out, "%d  %s  %s  made %s  %s\n", k.Generation, k.Fingerprint(), k.Reason, k.CreatedAt.UTC().Format(time.RFC3339), state)
		}
		return nil
	case "rotate":
		s, err := ring.Start(ctx, jobkeys.Reason(*reason), by)
		if err != nil {
			return hostErr(err)
		}
		_, err = fmt.Fprintf(out, "Started a rotation: generation %d, %s. Keys marked compromised: %v.\n", s.Key.Generation, s.Key.Fingerprint(), s.Compromised)
		return err
	case "finish":
		f, err := ring.Finish(ctx, jobkeys.FinishInput{BackupTaken: *backupTaken, Now: *now, By: by})
		if err != nil {
			return hostErr(err)
		}
		_, err = fmt.Fprintf(out, "Cut over to generation %d. Devices moved: %d; not yet: %d (they follow when they come back).\n", f.Key.Generation, f.Moved, f.NotMoved)
		return err
	case "forget":
		n, err := ring.Forget(ctx, gen, by)
		if err != nil {
			return hostErr(err)
		}
		_, err = fmt.Fprintf(out, "Forgot the seed of generation %d. Devices left needing re-pinning: %d.\n", gen, n)
		return err
	case "replace-lost":
		lost, k, err := ring.ReplaceLost(ctx, by)
		if err != nil {
			return hostErr(err)
		}
		_, err = fmt.Fprintf(out, "Marked lost: %v. New key: generation %d, %s, the floor now. Every device on a lost key needs re-pinning.\n", lost, k.Generation, k.Fingerprint())
		return err
	default: // recover
		n, err := ring.Recover(ctx, gen, by)
		if err != nil {
			return hostErr(err)
		}
		_, err = fmt.Fprintf(out, "Generation %d is held again. Devices that no longer need re-pinning: %d.\n", gen, n)
		return err
	}
}

// hostErr says a refusal in the operator's words.
func hostErr(err error) error {
	if e, ok := apperr.As(err); ok {
		return errors.New(e.Message)
	}
	return err
}
