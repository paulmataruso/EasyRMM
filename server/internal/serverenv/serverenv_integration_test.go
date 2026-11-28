//go:build integration

package serverenv

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

type row struct {
	console  string
	mesh     *string
	recorded time.Time
	seen     time.Time
}

func readRow(t *testing.T, db *database.DB, id string) (row, bool) {
	t.Helper()
	var r row
	found := false
	err := db.InTx(context.Background(), database.System, func(tx pgx.Tx) error {
		err := tx.QueryRow(context.Background(), `SELECT console_url, mesh_url, recorded_at, seen_at FROM server_env_pairs WHERE server_id = $1`, id).
			Scan(&r.console, &r.mesh, &r.recorded, &r.seen)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		found = err == nil
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return r, found
}

func count(t *testing.T, db *database.DB) (n int) {
	t.Helper()
	if err := db.InTx(context.Background(), database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT count(*) FROM server_env_pairs`).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestRecordKeepsThePairAndWhenItWasSeen(t *testing.T) {
	inst := testdb.New(t)
	dir := t.TempDir()
	id, replaced, err := ServerID(dir)
	if err != nil || replaced {
		t.Fatalf("ServerID: %v %v", replaced, err)
	}
	t0 := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)
	clock := t0
	r := &Recorder{DB: inst.DB, Log: quiet(), ID: id, Console: "https://rmm.example.com", Mesh: "https://mesh.rmm.example.com", Now: func() time.Time { return clock }}

	if err := r.Record(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, ok := readRow(t, inst.DB, id)
	if !ok || got.console != "https://rmm.example.com" || got.mesh == nil || *got.mesh != "https://mesh.rmm.example.com" || !got.recorded.Equal(t0) || !got.seen.Equal(t0) {
		t.Fatalf("first record: %+v found=%v", got, ok)
	}

	// The same pair seen again an hour later: seen moves, recorded does not.
	clock = t0.Add(time.Hour)
	if err := r.Record(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, _ = readRow(t, inst.DB, id)
	if !got.recorded.Equal(t0) || !got.seen.Equal(clock) {
		t.Errorf("same pair: recorded %v seen %v", got.recorded, got.seen)
	}

	// A new pair (an edited .env) is recorded again, with its own time.
	clock = t0.Add(2 * time.Hour)
	r.Console, r.Mesh = "https://new.example.com", ""
	if err := r.Record(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, _ = readRow(t, inst.DB, id)
	if got.console != "https://new.example.com" || got.mesh != nil || !got.recorded.Equal(clock) || !got.seen.Equal(clock) {
		t.Errorf("new pair: %+v", got)
	}
	if n := count(t, inst.DB); n != 1 {
		t.Errorf("%d rows for one server", n)
	}

	// A mesh name that appears later changes the pair too.
	clock = t0.Add(3 * time.Hour)
	r.Mesh = "https://mesh.new.example.com"
	if err := r.Record(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, _ = readRow(t, inst.DB, id); got.mesh == nil || !got.recorded.Equal(clock) {
		t.Errorf("mesh name added: %+v", got)
	}
}

func TestServersWithTheirOwnIDsKeepTheirOwnRows(t *testing.T) {
	inst := testdb.New(t)
	a, _, _ := ServerID(t.TempDir())
	b, _, _ := ServerID(t.TempDir())
	if a == b {
		t.Fatal("two servers made the same ID")
	}
	for id, console := range map[string]string{a: "https://a.example.com", b: "https://b.example.com"} {
		if err := (&Recorder{DB: inst.DB, Log: quiet(), ID: id, Console: console}).Record(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if n := count(t, inst.DB); n != 2 {
		t.Fatalf("%d rows", n)
	}
	if got, _ := readRow(t, inst.DB, a); got.console != "https://a.example.com" {
		t.Errorf("server a's row: %+v", got)
	}
}

func TestRecordRefusesWhatCannotBeKept(t *testing.T) {
	inst := testdb.New(t)
	for name, r := range map[string]*Recorder{
		"no id":        {DB: inst.DB, Console: "https://rmm.example.com"},
		"short id":     {DB: inst.DB, ID: "abc", Console: "https://rmm.example.com"},
		"no console":   {DB: inst.DB, ID: strings.Repeat("a", 32)},
		"upper-case":   {DB: inst.DB, ID: strings.Repeat("A", 32), Console: "https://rmm.example.com"},
		"not hex":      {DB: inst.DB, ID: strings.Repeat("z", 32), Console: "https://rmm.example.com"},
		"long console": {DB: inst.DB, ID: strings.Repeat("a", 32), Console: "https://" + strings.Repeat("a", 400)},
	} {
		if err := r.Record(context.Background()); err == nil {
			t.Errorf("%s: recorded", name)
		}
	}
	if n := count(t, inst.DB); n != 0 {
		t.Errorf("%d rows after refusals", n)
	}
}

func TestTheRecordIsForTheSystemScopeOnly(t *testing.T) {
	inst := testdb.New(t)
	id, _, _ := ServerID(t.TempDir())
	if err := (&Recorder{DB: inst.DB, Log: quiet(), ID: id, Console: "https://rmm.example.com"}).Record(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Without the system scope row-level security shows nothing and refuses a write.
	var n int
	if err := inst.DB.InTx(context.Background(), database.Scope{}, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT count(*) FROM server_env_pairs`).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("a tenant scope sees %d rows", n)
	}
	err := inst.DB.InTx(context.Background(), database.Scope{}, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `INSERT INTO server_env_pairs (server_id, console_url) VALUES ($1, 'https://x.example.com')`, strings.Repeat("b", 32))
		return err
	})
	if err == nil {
		t.Error("a tenant scope wrote a row")
	}
}

func TestRunRecordsAtOnceRetriesAndKeepsSeen(t *testing.T) {
	inst := testdb.New(t)
	id, _, _ := ServerID(t.TempDir())
	r := &Recorder{DB: inst.DB, Log: quiet(), ID: id, Console: "https://rmm.example.com", Retry: 20 * time.Millisecond, Seen: 30 * time.Millisecond}

	// While the record cannot be written (no table row can hold this ID until
	// it is valid), Run keeps trying; once it can, it records.
	bad := r.ID
	r.ID = "bad"
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Go(func() { r.Run(ctx) })
	time.Sleep(100 * time.Millisecond)
	if n := count(t, inst.DB); n != 0 {
		t.Fatalf("recorded %d rows with a bad ID", n)
	}
	cancel()
	wg.Wait()

	r.ID = bad
	ctx, cancel = context.WithCancel(context.Background())
	wg.Go(func() { r.Run(ctx) })
	deadline := time.Now().Add(5 * time.Second)
	var first row
	for {
		if got, ok := readRow(t, inst.DB, bad); ok {
			first = got
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Run did not record")
		}
		time.Sleep(10 * time.Millisecond)
	}
	for {
		if got, _ := readRow(t, inst.DB, bad); got.seen.After(first.seen) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Run did not refresh when the server was seen")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	wg.Wait()
}

func TestRunWithDefaultsStopsWithItsContext(t *testing.T) {
	inst := testdb.New(t)
	id, _, _ := ServerID(t.TempDir())
	r := &Recorder{DB: inst.DB, Log: quiet(), ID: id, Console: "https://rmm.example.com"}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	for i := 0; i < 500; i++ {
		if _, ok := readRow(t, inst.DB, id); ok {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
}

func TestServerIDIsKeptAcrossStartsAndRepairedWhenDamaged(t *testing.T) {
	dir := t.TempDir()
	id, replaced, err := ServerID(dir)
	if err != nil || replaced || !validID(id) {
		t.Fatalf("first: %q %v %v", id, replaced, err)
	}
	if info, err := os.Stat(filepath.Join(dir, FileName)); err != nil || info.Mode().Perm()&0o077 != 0 {
		t.Errorf("file: %v %v", info, err)
	}
	again, replaced, err := ServerID(dir)
	if err != nil || replaced || again != id {
		t.Fatalf("second start: %q %v %v", again, replaced, err)
	}
	for _, bad := range []string{"", "not an id", strings.ToUpper(id), id + "00"} {
		if err := os.WriteFile(filepath.Join(dir, FileName), []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		fresh, replaced, err := ServerID(dir)
		if err != nil || !replaced || !validID(fresh) || fresh == id {
			t.Errorf("damaged %q: %q %v %v", bad, fresh, replaced, err)
		}
		if got, replaced, _ := ServerID(dir); got != fresh || replaced {
			t.Errorf("the repaired ID was not kept: %q", got)
		}
	}
	// Every leftover temporary file was removed.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("%d files in the data directory", len(entries))
	}
}

func TestServerIDRacingStartsAgree(t *testing.T) {
	dir := t.TempDir()
	ids := make([]string, 16)
	var wg sync.WaitGroup
	for i := range ids {
		wg.Go(func() {
			id, _, err := ServerID(dir)
			if err != nil {
				t.Error(err)
			}
			ids[i] = id
		})
	}
	wg.Wait()
	for _, id := range ids {
		if id != ids[0] || !validID(id) {
			t.Fatalf("starts disagree: %v", ids)
		}
	}
}

func TestServerIDErrors(t *testing.T) {
	if _, _, err := ServerID(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("a missing data directory was accepted")
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, FileName), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ServerID(dir); err == nil {
		t.Error("a directory in place of the file was accepted")
	}
}
