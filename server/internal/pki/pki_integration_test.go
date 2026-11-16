//go:build integration

package pki

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

func key(t *testing.T, id string) secrets.Key {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	k, err := secrets.ParseKey(id, base64.StdEncoding.EncodeToString(b))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestAuthorityPersists checks that the authority, and so the trust browsers
// and agents place in it and the install pin, survives restarts and key
// rotation, and that servers starting together agree on one authority.
func TestAuthorityPersists(t *testing.T) {
	inst := testdb.New(t)
	ctx := context.Background()
	k1 := key(t, "k1")
	sealer, err := secrets.NewSealer(k1)
	if err != nil {
		t.Fatal(err)
	}

	// Several servers starting at once.
	var wg sync.WaitGroup
	got := make([]*Authority, 4)
	errs := make([]error, 4)
	for i := range got {
		wg.Go(func() { got[i], errs[i] = Load(ctx, inst.DB, sealer) })
	}
	wg.Wait()
	for i := range got {
		if errs[i] != nil {
			t.Fatal(errs[i])
		}
		if got[i].Fingerprint() != got[0].Fingerprint() || got[i].Pin() != got[0].Pin() {
			t.Fatal("concurrent starts created different authorities")
		}
	}

	// A restart.
	again, err := Load(ctx, inst.DB, sealer)
	if err != nil {
		t.Fatal(err)
	}
	if again.Fingerprint() != got[0].Fingerprint() || again.Pin() != got[0].Pin() {
		t.Fatal("the authority changed across a restart")
	}

	// Stored sealed: neither key appears in the clear.
	var raw string
	if err := inst.DB.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT value::text FROM settings WHERE key = $1`, setting).Scan(&raw)
	}); err != nil {
		t.Fatal(err)
	}
	if len(raw) < 100 || !strings.HasPrefix(raw, `{"sealed":`) || strings.Contains(raw, "PRIVATE") {
		t.Fatalf("stored value = %.80s", raw)
	}

	// Rotating the secret key reseals with the new primary key.
	k2 := key(t, "k2")
	rotated, err := secrets.NewSealer(k2, k1)
	if err != nil {
		t.Fatal(err)
	}
	if r, err := Load(ctx, inst.DB, rotated); err != nil || r.Pin() != got[0].Pin() {
		t.Fatalf("after rotation: %v", err)
	}
	k2Only, _ := secrets.NewSealer(k2)
	if r, err := Load(ctx, inst.DB, k2Only); err != nil || r.Pin() != got[0].Pin() {
		t.Fatalf("not resealed under the new key: %v", err)
	}
	// A server with the wrong key refuses rather than replacing the authority.
	if _, err := Load(ctx, inst.DB, sealer); err == nil {
		t.Fatal("unsealed with a retired key")
	}
}
