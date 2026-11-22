//go:build integration

package database_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

// One server leads at a time; when it gives up, or its connection drops,
// another takes the lead at its next try.
func TestLeader(t *testing.T) {
	inst := testdb.New(t)
	ctx := context.Background()
	const key = 4471209853399
	a, b := inst.DB.Leader(key), inst.DB.Leader(key)
	t.Cleanup(a.Close)
	t.Cleanup(b.Close)
	lead := func(l *database.Leader) bool {
		t.Helper()
		ok, err := l.Lead(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if !lead(a) || !lead(a) || lead(b) {
		t.Fatal("not one leader")
	}
	// The lock is not left on a pooled connection.
	var free bool
	if err := inst.DB.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, int64(key)).Scan(&free)
	}); err != nil || free {
		t.Fatalf("a pooled connection takes the lock: %v %v", free, err)
	}
	// Another key is another leadership.
	other := inst.DB.Leader(key + 1)
	if !lead(other) {
		t.Fatal("another key")
	}
	other.Close()

	// Given up: the other takes it.
	a.Close()
	if !lead(b) || lead(a) {
		t.Fatal("not handed over")
	}

	// The leader's connection drops: the lock goes with it.
	super, err := pgx.Connect(ctx, inst.SuperDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer super.Close(ctx)
	var ended bool
	if err := super.QueryRow(ctx, `SELECT pg_terminate_backend(pid) FROM pg_locks
		WHERE locktype = 'advisory' AND granted AND (classid::bigint << 32 | objid::bigint) = $1`, int64(key)).Scan(&ended); err != nil || !ended {
		t.Fatalf("ending the leader's connection: %v %v", ended, err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for !lead(a) {
		if time.Now().After(deadline) {
			t.Fatal("the lock outlived its connection")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if lead(b) {
		t.Fatal("the server whose connection dropped still leads")
	}

	// A canceled request does not give up the lead.
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if ok, err := a.Lead(canceled); ok || err == nil {
		t.Fatalf("canceled: %v %v", ok, err)
	}
	if !lead(a) {
		t.Fatal("the lead was lost to a canceled request")
	}
}
