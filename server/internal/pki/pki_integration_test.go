//go:build integration

package pki

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

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

// TestServerCertificatePersists checks that a restart serves the same server
// certificate: MeshAgent pins the exact certificate, and a new one on every
// restart left agents held by MeshCentral, unable to connect.
func TestServerCertificatePersists(t *testing.T) {
	inst := testdb.New(t)
	ctx := context.Background()
	sealer, err := secrets.NewSealer(key(t, "k1"))
	if err != nil {
		t.Fatal(err)
	}
	ips := []net.IP{net.ParseIP("203.0.113.20")}
	start := func(names []string, ips []net.IP) []byte {
		t.Helper()
		a, err := Load(ctx, inst.DB, sealer)
		if err != nil {
			t.Fatal(err)
		}
		if err := a.SetAddresses(ctx, names, ips); err != nil {
			t.Fatal(err)
		}
		c, err := a.Certificate()
		if err != nil {
			t.Fatal(err)
		}
		return c.Certificate[0]
	}
	stored := func() []byte {
		t.Helper()
		var v storedCert
		if err := inst.DB.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT value FROM settings WHERE key = $1`, certSetting).Scan(&v)
		}); err != nil {
			t.Fatal(err)
		}
		return v.Cert
	}

	// Servers starting together serve one certificate, the stored one.
	var wg sync.WaitGroup
	got := make([][]byte, 4)
	for i := range got {
		wg.Go(func() { got[i] = start([]string{"rmm.example.com"}, ips) })
	}
	wg.Wait()
	first := stored()
	for i := range got {
		if !bytes.Equal(got[i], first) {
			t.Fatalf("server %d serves a certificate other than the stored one", i)
		}
	}

	// A restart serves it again.
	if !bytes.Equal(start([]string{"RMM.example.com."}, ips), first) {
		t.Fatal("a restart changed the certificate")
	}

	// New addresses: a new certificate, stored, and served after a restart.
	moved := start([]string{"rmm.example.com"}, []net.IP{net.ParseIP("203.0.113.21")})
	if bytes.Equal(moved, first) || !bytes.Equal(stored(), moved) {
		t.Fatal("new addresses did not issue and store a new certificate")
	}
	if !bytes.Equal(start([]string{"rmm.example.com"}, []net.IP{net.ParseIP("203.0.113.21")}), moved) {
		t.Fatal("a restart changed the new certificate")
	}

	// A stored certificate due for renewal is replaced at start.
	a, err := Load(ctx, inst.DB, sealer)
	if err != nil {
		t.Fatal(err)
	}
	a.now = func() time.Time { return time.Now().Add(leafLifetime - renewBefore + time.Hour) }
	if err := a.SetAddresses(ctx, []string{"rmm.example.com"}, []net.IP{net.ParseIP("203.0.113.21")}); err != nil {
		t.Fatal(err)
	}
	c, err := a.Certificate()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(c.Certificate[0], moved) || !bytes.Equal(stored(), c.Certificate[0]) {
		t.Fatal("a certificate due for renewal was served")
	}

	// Renewal while running stores the renewed certificate.
	renewing := c.Certificate[0]
	a.now = func() time.Time { return time.Now().Add(2 * leafLifetime) }
	if c, err = a.Certificate(); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(c.Certificate[0], renewing) || !bytes.Equal(stored(), c.Certificate[0]) {
		t.Fatal("a renewal was not stored")
	}

	// Something unreadable stored is replaced, not fatal.
	if err := inst.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE settings SET value = '{"cert":"bm90IGEgY2VydGlmaWNhdGU="}' WHERE key = $1`, certSetting)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if after := start([]string{"rmm.example.com"}, ips); !bytes.Equal(stored(), after) {
		t.Fatal("an unreadable stored certificate was not replaced")
	}

	// Another authority's certificate (its key or CA replaced) is not served.
	other, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if err := other.SetAddresses(ctx, []string{"rmm.example.com"}, ips); err != nil {
		t.Fatal(err)
	}
	oc, _ := other.Certificate()
	if err := inst.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
		return storeCert(ctx, tx, oc.Certificate[0])
	}); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(start([]string{"rmm.example.com"}, ips), oc.Certificate[0]) {
		t.Fatal("served another authority's certificate")
	}
}
