// Package serverenv keeps each server's record of the names its .env gives it
// (ADR-0061, slice 1).
//
// Each server makes a random ID at its first start and keeps it in its data
// directory. The pair of names its .env names, EASYRMM_PUBLIC_URL and
// EASYRMM_MESH_PUBLIC_URL, is kept in server_env_pairs under that ID, with
// when it was recorded and when the server was last seen. Nothing acts on
// the record yet: the release that moves agents starts from it, so that a
// .env edited just before the upgrade is not taken for the pair agents use.
package serverenv

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// FileName is the file in the data directory that holds the server's ID.
const FileName = "server-id"

// Intervals of Run.
const (
	// RetryEvery is the wait after a record could not be written.
	RetryEvery = time.Minute
	// SeenEvery is the wait between two refreshes of when the server was seen.
	SeenEvery = time.Hour
)

const idBytes = 16

// validID reports whether s is an ID this package made: lower-case hex.
func validID(s string) bool {
	if len(s) != idBytes*2 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil && s == strings.ToLower(s)
}

// ServerID returns the server's ID from dir, making and keeping one when
// there is none. A file that holds something else is replaced, and replaced
// is reported, so that the caller can log it: the server then has a new ID
// and the old row stays until it is forgotten.
func ServerID(dir string) (id string, replaced bool, err error) {
	path := filepath.Join(dir, FileName)
	b, err := os.ReadFile(path) //nolint:gosec // the server's own data directory
	switch {
	case err == nil:
		if s := strings.TrimSpace(string(b)); validID(s) {
			return s, false, nil
		}
		replaced = true
	case !errors.Is(err, os.ErrNotExist):
		return "", false, fmt.Errorf("reading %s: %w", path, err)
	}
	raw := make([]byte, idBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", false, err
	}
	id = hex.EncodeToString(raw)
	// Written aside and moved into place, so that no reader, and no second
	// server on the same directory, sees a half-written file. A file another
	// start made first wins and is the one read back.
	tmp, err := os.CreateTemp(dir, FileName+".*")
	if err != nil {
		return "", false, err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.WriteString(id + "\n"); err != nil {
		_ = tmp.Close()
		return "", false, err
	}
	if err := tmp.Close(); err != nil {
		return "", false, err
	}
	if replaced {
		if err := os.Rename(tmp.Name(), path); err != nil {
			return "", false, err
		}
		return id, true, nil
	}
	if err := os.Link(tmp.Name(), path); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return "", false, err
		}
		again, _, rerr := ServerID(dir)
		return again, false, rerr
	}
	return id, false, nil
}

// Recorder writes the record of one server.
type Recorder struct {
	DB  *database.DB
	Log *slog.Logger
	// ID is the server's ID (ServerID).
	ID string
	// Console and Mesh are the pair .env names; Mesh is empty without remote
	// access. Both are origins, https://rmm.example.com.
	Console, Mesh string
	// Now is the clock; nil is time.Now.
	Now func() time.Time
	// Retry and Seen replace RetryEvery and SeenEvery when not zero.
	Retry, Seen time.Duration
}

func (r *Recorder) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

// Record writes the pair .env names under the server's ID and when the
// server was seen. The time the pair was recorded changes only when the pair
// differs from the one recorded before.
func (r *Recorder) Record(ctx context.Context) error {
	if !validID(r.ID) || r.Console == "" {
		return errors.New("serverenv: no server ID or console name to record")
	}
	var mesh *string
	if r.Mesh != "" {
		mesh = &r.Mesh
	}
	now := r.now()
	return r.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO server_env_pairs (server_id, console_url, mesh_url, recorded_at, seen_at)
			VALUES ($1, $2, $3, $4, $4)
			ON CONFLICT (server_id) DO UPDATE SET
				recorded_at = CASE WHEN server_env_pairs.console_url IS DISTINCT FROM EXCLUDED.console_url
					OR server_env_pairs.mesh_url IS DISTINCT FROM EXCLUDED.mesh_url
					THEN EXCLUDED.recorded_at ELSE server_env_pairs.recorded_at END,
				console_url = EXCLUDED.console_url,
				mesh_url = EXCLUDED.mesh_url,
				seen_at = EXCLUDED.seen_at`, r.ID, r.Console, mesh, now)
		return err
	})
}

// Run records the pair at once and then each Seen, until ctx ends. A record
// that cannot be written is logged and tried again every Retry.
func (r *Recorder) Run(ctx context.Context) {
	retry, seen := r.Retry, r.Seen
	if retry <= 0 {
		retry = RetryEvery
	}
	if seen <= 0 {
		seen = SeenEvery
	}
	for {
		wait := seen
		if err := r.Record(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			r.Log.Error("serverenv: recording the names this server's .env gives it failed; trying again", "error", err, "retry_in", retry.String())
			wait = retry
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}
