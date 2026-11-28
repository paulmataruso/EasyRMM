package app

import (
	"context"
	"log/slog"
	"net/url"
	"strings"

	"github.com/paulmataruso/easyrmm/server/internal/config"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/serverenv"
)

// envRecorder returns what keeps this server's record of the names its .env
// gives it (ADR-0061, slice 1), or nil when the server's ID cannot be made:
// nothing acts on the record yet, so that is logged and the server starts.
func envRecorder(cfg *config.Config, db *database.DB, log *slog.Logger) *serverenv.Recorder {
	id, replaced, err := serverenv.ServerID(cfg.DataDir)
	if err != nil {
		log.Error("this server's ID could not be kept in the data directory; its names are not recorded", "error", err, "dir", cfg.DataDir)
		return nil
	}
	if replaced {
		log.Warn("the server ID file held something else and was replaced; this server has a new ID", "file", serverenv.FileName)
	}
	r := &serverenv.Recorder{DB: db, Log: log, ID: id, Console: recordedOrigin(cfg.PublicURL)}
	if cfg.Mesh.Enabled && cfg.MeshPublicURL != nil {
		r.Mesh = recordedOrigin(cfg.MeshPublicURL)
	}
	return r
}

// recordedOrigin is a name as the record keeps it: the origin, in lower case,
// so that two spellings of one name are one pair.
func recordedOrigin(u *url.URL) string { return strings.ToLower(originString(u)) }

// runEnvRecord records the pair now and keeps it seen until ctx ends.
func runEnvRecord(ctx context.Context, cfg *config.Config, db *database.DB, log *slog.Logger) {
	if r := envRecorder(cfg, db, log); r != nil {
		r.Run(ctx)
	}
}
