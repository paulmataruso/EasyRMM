//go:build integration

package quickassist_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/jobkeys"
	"github.com/paulmataruso/easyrmm/server/internal/quickassist"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

// A runner is given the key its device is signed for (ADR-0057): the ring's
// newest at enrollment, whatever key signed the ticket it downloaded earlier.
func TestRunnerIsGivenTheNewestKeyAndTicketsOutliveARotation(t *testing.T) {
	inst := testdb.New(t)
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	sealer, err := secrets.NewSealer(secrets.Key{ID: "k1", Raw: raw})
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	auditLog := audit.New(inst.DB, nil)
	ring, err := jobkeys.Open(t.Context(), inst.DB, sealer, log, jobkeys.Options{Version: "1.0.0", Audit: auditLog})
	if err != nil {
		t.Fatal(err)
	}
	f := &fx{t: t, ctx: t.Context(), db: inst.DB, svc: quickassist.New(inst.DB, auditLog, ring.Newest().Private, server)}
	f.svc.UseRing(ring)
	f.acme = f.id(`INSERT INTO organizations (name) VALUES ('Acme') RETURNING id`)
	tech := f.user(rbac.RoleTechnician, f.acme)

	first := ring.Newest()
	// A ticket downloaded before the rotation, signed with the first key.
	link := f.oneTime(tech, f.acme)
	old, _, err := f.svc.Download(f.ctx, f.ip(), link.Token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ring.Start(f.ctx, jobkeys.ReasonPlanned, jobkeys.HostBy()); err != nil {
		t.Fatal(err)
	}
	second := ring.Newest()
	if second.Generation == first.Generation {
		t.Fatal("no new key")
	}
	if f.svc.PublicKey().Equal(first.Public) || !f.svc.PublicKey().Equal(second.Public) {
		t.Fatal("the service does not follow the ring's newest key")
	}

	res, err := f.enroll(old, "123456")
	if err != nil {
		t.Fatalf("a ticket signed before the rotation: %v", err)
	}
	if res.JobKey != agentproto.EncodeKey(second.Public) {
		t.Fatalf("the runner was given %s", res.JobKey)
	}
	var given *int64
	if err := inst.DB.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT job_key_given_generation FROM devices WHERE id = $1::uuid`, res.DeviceID).Scan(&given)
	}); err != nil || given == nil || *given != second.Generation {
		t.Fatalf("given generation %v: %v", given, err)
	}
	// Until it reports what it trusts, its device is signed for with that key.
	var c jobkeys.Choice
	if err := inst.DB.InTx(f.ctx, database.System, func(tx pgx.Tx) (err error) {
		c, err = ring.For(f.ctx, tx, mustUUID(t, res.DeviceID))
		return err
	}); err != nil || c.Key.Generation != second.Generation {
		t.Fatalf("signed for %d: %v", c.Key.Generation, err)
	}

	// A ticket another server signed is still refused.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	f2 := quickassist.New(inst.DB, auditLog, other, server)
	l2 := f.oneTime(tech, f.acme)
	tr2, _, _ := f2.Download(f.ctx, f.ip(), l2.Token)
	if _, err := f.enroll(tr2, "123456"); err == nil {
		t.Fatal("a foreign ticket enrolled")
	}
}

func mustUUID(t *testing.T, s string) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
