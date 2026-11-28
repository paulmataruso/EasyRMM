//go:build integration

package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/config"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/serverenv"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

func TestAServerRecordsTheNamesItsEnvGivesIt(t *testing.T) {
	inst := testdb.New(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{
		DataDir: t.TempDir(), PublicURL: mustURL("https://RMM.example.com"), MeshPublicURL: mustURL("https://mesh.rmm.example.com"),
		Mesh: config.MeshConfig{Enabled: true},
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { runEnvRecord(ctx, cfg, inst.DB, log); close(done) }()
	id := ""
	deadline := time.Now().Add(10 * time.Second)
	for id == "" && time.Now().Before(deadline) {
		if b, err := os.ReadFile(filepath.Join(cfg.DataDir, serverenv.FileName)); err == nil && len(b) > 0 {
			id = string(b[:len(b)-1])
		}
		time.Sleep(10 * time.Millisecond)
	}
	var console string
	var mesh *string
	for time.Now().Before(deadline) {
		err := inst.DB.ReadTx(context.Background(), database.System, func(tx pgx.Tx) error {
			err := tx.QueryRow(context.Background(), `SELECT console_url, mesh_url FROM server_env_pairs WHERE server_id = $1`, id).Scan(&console, &mesh)
			if errors.Is(err, pgx.ErrNoRows) {
				console = ""
				return nil
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		if console != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if console != "https://rmm.example.com" || mesh == nil || *mesh != "https://mesh.rmm.example.com" {
		t.Fatalf("recorded %q %v under %q", console, mesh, id)
	}
}

func TestEnvRecorderWithoutRemoteAccessRecordsNoMeshName(t *testing.T) {
	inst := testdb.New(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{DataDir: t.TempDir(), PublicURL: mustURL("https://203.0.113.10"), MeshPublicURL: mustURL("https://203.0.113.10:4443")}
	r := envRecorder(cfg, inst.DB, log)
	if r == nil || r.Mesh != "" || r.Console != "https://203.0.113.10" {
		t.Fatalf("%+v", r)
	}
	if err := r.Record(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestEnvRecorderToleratesADataDirectoryItCannotUse(t *testing.T) {
	inst := testdb.New(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{DataDir: filepath.Join(t.TempDir(), "missing"), PublicURL: mustURL("https://rmm.example.com")}
	if r := envRecorder(cfg, inst.DB, log); r != nil {
		t.Error("a recorder with no server ID")
	}
	// runEnvRecord returns at once, as the server goes on without the record.
	done := make(chan struct{})
	go func() { runEnvRecord(context.Background(), cfg, inst.DB, log); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runEnvRecord did not return")
	}

	// A damaged ID file is replaced, not trusted.
	cfg.DataDir = t.TempDir()
	if err := os.WriteFile(filepath.Join(cfg.DataDir, serverenv.FileName), []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := envRecorder(cfg, inst.DB, log); r == nil || r.ID == "junk" {
		t.Errorf("%+v", r)
	}
}
