//go:build integration

package tlscert

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"slices"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

func newSealer(t *testing.T, id string) (*secrets.Sealer, secrets.Key) {
	t.Helper()
	raw := make([]byte, secrets.KeySize)
	_, _ = rand.Read(raw)
	k := secrets.Key{ID: id, Raw: raw}
	s, err := secrets.NewSealer(k)
	if err != nil {
		t.Fatal(err)
	}
	return s, k
}

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestStorageContract(t *testing.T) {
	ctx := context.Background()
	inst := testdb.New(t)
	sealer, _ := newSealer(t, "k1")
	st := NewStorage(inst.DB, sealer)

	if _, err := st.Load(ctx, "a/b/c"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a missing key: %v", err)
	}
	secret := []byte("-----BEGIN EC PRIVATE KEY-----\nnot a real key\n-----END EC PRIVATE KEY-----\n")
	for _, k := range []string{"acme/ca/users/default/default.json", "acme/ca/users/default/private.key", "acme/ca/users/me@x.test/me.json", "certificates/ca/x.test/x.test.crt"} {
		if err := st.Store(ctx, k, secret); err != nil {
			t.Fatal(err)
		}
	}
	got, err := st.Load(ctx, "acme/ca/users/default/private.key")
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("round trip: %v", err)
	}

	// A value is sealed at rest, and no key is stored as it is.
	var raw string
	if err := inst.DB.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT value FROM tls_storage WHERE key = 'acme/ca/users/default/private.key'`).Scan(&raw)
	}); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains([]byte(raw), []byte("PRIVATE KEY")) || bytes.Contains([]byte(raw), []byte("not a real key")) {
		t.Fatal("a private key is stored in the clear")
	}

	// The key is the associated data: a value copied to another row does not open.
	if err := inst.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO tls_storage (key, value) VALUES ('stolen', $1)`, raw)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Load(ctx, "stolen"); err == nil {
		t.Fatal("a value copied to another row opened")
	}

	// CertMagic's account lookup lists the folders of acme/<CA>/users without
	// recursing and keeps those Stat reports as not terminal.
	folders, err := st.List(ctx, "acme/ca/users", false)
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(folders)
	if !slices.Equal(folders, []string{"acme/ca/users/default", "acme/ca/users/me@x.test"}) {
		t.Fatalf("non-recursive list: %v", folders)
	}
	for _, f := range folders {
		info, err := st.Stat(ctx, f)
		if err != nil || info.IsTerminal {
			t.Fatalf("Stat(%s) = %+v, %v: a folder is not terminal", f, info, err)
		}
	}
	if info, err := st.Stat(ctx, "acme/ca/users/default/private.key"); err != nil || !info.IsTerminal || info.Modified.IsZero() {
		t.Fatalf("Stat of a key: %+v, %v", info, err)
	}
	all, err := st.List(ctx, "acme/ca", true)
	if err != nil || len(all) != 3 {
		t.Fatalf("recursive list: %v, %v", all, err)
	}
	if !st.Exists(ctx, "acme/ca/users") || st.Exists(ctx, "acme/nope") {
		t.Fatal("Exists")
	}
	if _, err := st.List(ctx, "acme/none", false); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("listing nothing: %v", err)
	}

	// Deleting a folder deletes what is under it, and only that.
	if err := st.Delete(ctx, "acme/ca/users/default"); err != nil {
		t.Fatal(err)
	}
	if st.Exists(ctx, "acme/ca/users/default") || !st.Exists(ctx, "acme/ca/users/me@x.test/me.json") {
		t.Fatal("Delete")
	}

	// CertMagic's own checks, on this storage (its contract).
	if err := certmagic.New(certmagic.NewCache(certmagic.CacheOptions{GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) { return nil, nil }}), certmagic.Config{Storage: st}).Storage.Store(ctx, "x", []byte("y")); err != nil {
		t.Fatal(err)
	}
}

func TestStorageResealsWithTheCurrentKey(t *testing.T) {
	ctx := context.Background()
	inst := testdb.New(t)
	old, oldKey := newSealer(t, "old")
	if err := NewStorage(inst.DB, old).Store(ctx, "acme/ca/users/default/private.key", []byte("account key")); err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, secrets.KeySize)
	_, _ = rand.Read(raw)
	both, err := secrets.NewSealer(secrets.Key{ID: "new", Raw: raw}, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	st := NewStorage(inst.DB, both)
	if err := st.Reseal(ctx); err != nil {
		t.Fatal(err)
	}
	var sealed string
	if err := inst.DB.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT value FROM tls_storage WHERE key = 'acme/ca/users/default/private.key'`).Scan(&sealed)
	}); err != nil {
		t.Fatal(err)
	}
	if both.NeedsReseal(sealed) {
		t.Fatal("still sealed with the previous key")
	}
	only, _ := secrets.NewSealer(secrets.Key{ID: "new", Raw: raw})
	if got, err := NewStorage(inst.DB, only).Load(ctx, "acme/ca/users/default/private.key"); err != nil || string(got) != "account key" {
		t.Fatalf("after dropping the previous key: %q, %v", got, err)
	}
	// A key that is gone is an error at start, not a silent loss.
	lost, _ := newSealer(t, "lost")
	if err := NewStorage(inst.DB, lost).Reseal(ctx); err == nil {
		t.Fatal("a stored key no listed secret opens was passed over")
	}
}

func TestStorageLocks(t *testing.T) {
	ctx := context.Background()
	inst := testdb.New(t)
	sealer, _ := newSealer(t, "k1")
	a, b := NewStorage(inst.DB, sealer), NewStorage(inst.DB, sealer) // two servers

	if err := a.Lock(ctx, "issue_cert_x.test"); err != nil {
		t.Fatal(err)
	}
	short, cancel := context.WithTimeout(ctx, 600*time.Millisecond)
	defer cancel()
	if err := b.Lock(short, "issue_cert_x.test"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("another server took a held lock: %v", err)
	}
	if err := b.Lock(ctx, "issue_cert_other"); err != nil {
		t.Fatalf("another name: %v", err)
	}
	_ = b.Unlock(ctx, "issue_cert_other")
	if err := a.Unlock(ctx, "issue_cert_x.test"); err != nil {
		t.Fatal(err)
	}
	if err := b.Lock(ctx, "issue_cert_x.test"); err != nil {
		t.Fatalf("after the release: %v", err)
	}
	_ = b.Unlock(ctx, "issue_cert_x.test")
	if err := b.Unlock(ctx, "never held"); err == nil {
		t.Fatal("unlocking a lock not held")
	}
}

func TestLockIsLostWhenItsConnectionDies(t *testing.T) {
	ctx := context.Background()
	inst := testdb.New(t)
	sealer, _ := newSealer(t, "k1")
	old := lockPing
	lockPing = 200 * time.Millisecond
	t.Cleanup(func() { lockPing = old })
	st := NewStorage(inst.DB, sealer)
	if err := st.Lock(ctx, "issue_cert_y.test"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-st.Lost("issue_cert_y.test"):
		t.Fatal("lost at once")
	default:
	}
	// Kill the lock's backend as a dead network would.
	admin, err := pgx.Connect(ctx, inst.SuperDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	var n int
	if err := admin.QueryRow(ctx, `SELECT count(pg_terminate_backend(pid)) FROM pg_locks l JOIN pg_stat_activity a USING (pid)
		WHERE l.locktype = 'advisory' AND l.granted AND a.datname = current_database() AND pid <> pg_backend_pid()`).Scan(&n); err != nil || n == 0 {
		t.Fatalf("terminating the lock's connection: %d, %v", n, err)
	}
	select {
	case <-st.Lost("issue_cert_y.test"):
	case <-time.After(5 * time.Second):
		t.Fatal("the lock was not noticed as lost")
	}
	// And another server can take it.
	other := NewStorage(inst.DB, sealer)
	if err := other.Lock(ctx, "issue_cert_y.test"); err != nil {
		t.Fatalf("after the connection died: %v", err)
	}
	_ = other.Unlock(ctx, "issue_cert_y.test")
}
