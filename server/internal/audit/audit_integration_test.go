//go:build integration

package audit_test

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

func TestAuditChainRecordsAndVerifies(t *testing.T) {
	inst := testdb.New(t)
	ctx := context.Background()
	log := audit.New(inst.DB, nil)
	orgA, orgB := uuid.New(), uuid.New()
	user := uuid.New()

	for i, org := range []uuid.UUID{orgA, orgB, uuid.Nil, orgA} {
		err := log.Record(ctx, audit.Event{
			Actor:          audit.Actor{Type: audit.ActorUser, ID: user, Label: "tech@example.com", SourceIP: netip.MustParseAddr("203.0.113.7"), UserAgent: "test"},
			Action:         "device.remote_desktop.start",
			OrganizationID: org,
			TargetType:     "device",
			TargetID:       uuid.NewString(),
			Outcome:        audit.Success,
			Details:        map[string]any{"n": i, "nested": map[string]any{"b": 2, "a": 1}},
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	res, err := log.Verify(ctx, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if res.Checked != 4 || res.FirstBadID != nil {
		t.Fatalf("verify: %+v", res)
	}

	// Tenant scoping: org A sees its two records only; platform records are
	// hidden from tenant scopes.
	got, err := log.List(ctx, database.Scope{Orgs: []uuid.UUID{orgA}}, audit.Query{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("org A sees %d records, want 2", len(got))
	}
	for _, e := range got {
		if e.OrganizationID == nil || *e.OrganizationID != orgA {
			t.Fatalf("leaked record %+v", e)
		}
		if e.SourceIP == nil || e.SourceIP.String() != "203.0.113.7" {
			t.Fatalf("source ip not stored: %+v", e.SourceIP)
		}
	}
	all, _ := log.List(ctx, database.System, audit.Query{ActionPrefix: "device.remote_desktop", Limit: 2})
	if len(all) != 2 || all[0].ID <= all[1].ID {
		t.Fatalf("expected newest-first page of 2, got %+v", all)
	}
	older, _ := log.List(ctx, database.System, audit.Query{Before: all[1].ID})
	if len(older) != 2 {
		t.Fatalf("keyset pagination returned %d", len(older))
	}
}

func TestAuditTamperingIsDetected(t *testing.T) {
	inst := testdb.New(t)
	ctx := context.Background()
	log := audit.New(inst.DB, nil)
	for i := 0; i < 3; i++ {
		if err := log.Record(ctx, audit.Event{Actor: audit.SystemActor("test"), Action: "test.event", Outcome: audit.Success, Details: map[string]any{"i": i}}); err != nil {
			t.Fatal(err)
		}
	}
	// Simulate an attacker with owner access editing a record behind the
	// trigger's back.
	conn, err := pgx.Connect(ctx, inst.SuperDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, `ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `UPDATE audit_log SET outcome = 'failure' WHERE id = (SELECT min(id) + 1 FROM audit_log)`); err != nil {
		t.Fatal(err)
	}
	res, err := log.Verify(ctx, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if res.FirstBadID == nil {
		t.Fatal("tampering not detected")
	}
}

func TestAuditDeletionInsideChainIsDetected(t *testing.T) {
	inst := testdb.New(t)
	ctx := context.Background()
	log := audit.New(inst.DB, nil)
	for i := 0; i < 3; i++ {
		_ = log.Record(ctx, audit.Event{Actor: audit.SystemActor("test"), Action: "test.event", Outcome: audit.Success})
	}
	conn, err := pgx.Connect(ctx, inst.SuperDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, `DELETE FROM audit_log WHERE id = (SELECT min(id) + 1 FROM audit_log)`); err != nil {
		t.Fatal(err)
	}
	res, _ := log.Verify(ctx, 0, 100)
	if res.FirstBadID == nil {
		t.Fatal("deletion not detected")
	}
}

func TestAuditWriteRollsBackWithTransaction(t *testing.T) {
	inst := testdb.New(t)
	ctx := context.Background()
	log := audit.New(inst.DB, nil)
	boom := errors.New("boom")
	err := inst.DB.InTx(ctx, database.Scope{Orgs: []uuid.UUID{uuid.New()}}, func(tx pgx.Tx) error {
		if err := log.Write(ctx, tx, audit.Event{Actor: audit.SystemActor("test"), Action: "test.event", Outcome: audit.Success}); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatal(err)
	}
	res, _ := log.Verify(ctx, 0, 100)
	if res.Checked != 0 {
		t.Fatalf("rolled-back audit record persisted: %+v", res)
	}
}

func TestAuditConcurrentWritersKeepChainIntact(t *testing.T) {
	inst := testdb.New(t)
	ctx := context.Background()
	log := audit.New(inst.DB, func() time.Time { return time.Now() })
	var wg sync.WaitGroup
	errs := make(chan error, 40)
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- log.Record(ctx, audit.Event{Actor: audit.SystemActor("load"), Action: "test.concurrent", Outcome: audit.Success, Details: map[string]any{"i": i}})
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	res, err := log.Verify(ctx, 0, 1000)
	if err != nil || res.Checked != 40 || res.FirstBadID != nil {
		t.Fatalf("verify after concurrent writes: %+v err=%v", res, err)
	}
}

func TestAuditRejectsInvalidEvents(t *testing.T) {
	inst := testdb.New(t)
	log := audit.New(inst.DB, nil)
	for _, e := range []audit.Event{
		{Actor: audit.SystemActor("x"), Action: "NoDots", Outcome: audit.Success},
		{Actor: audit.Actor{Type: "robot"}, Action: "a.b", Outcome: audit.Success},
		{Actor: audit.SystemActor("x"), Action: "a.b", Outcome: "maybe"},
	} {
		if err := log.Record(context.Background(), e); !errors.Is(err, audit.ErrInvalidEvent) {
			t.Errorf("event %+v: want ErrInvalidEvent, got %v", e, err)
		}
	}
}
