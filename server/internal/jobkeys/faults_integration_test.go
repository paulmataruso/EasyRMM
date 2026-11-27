//go:build integration

package jobkeys

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// super runs SQL as the database's superuser, to break what the runtime role
// cannot.
func (f *fixture) super(sql string) {
	f.t.Helper()
	conn, err := pgx.Connect(f.ctx, f.inst.SuperDSN)
	if err != nil {
		f.t.Fatal(err)
	}
	defer conn.Close(f.ctx)
	if _, err := conn.Exec(f.ctx, sql); err != nil {
		f.t.Fatal(err)
	}
}

// A database that fails halfway fails the call, never silently: each table
// the ring writes is made unavailable in turn.
func TestDatabaseFailuresAreReturned(t *testing.T) {
	f := newFixture(t)
	dev := f.device("pc")
	k1 := f.ring.Newest()
	rogue, _, _ := ed25519.GenerateKey(rand.Reader)
	now := f.now()
	round := 0
	log := agentproto.InstructionLogReport{Acked: 9, Entries: []agentproto.LoggedInstruction{
		{Seq: 10, Kind: "job", ID: "x", Signer: k1.Fingerprint(), At: now},
	}}
	calls := map[string]func() error{
		"issue": func() error {
			return f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
				_, _, err := f.ring.Issue(f.ctx, tx, dev, "job", "r")
				return err
			})
		},
		"observe": func() error {
			return f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
				return f.ring.Observe(f.ctx, tx, Observation{Device: dev, Org: f.org, Site: f.site,
					Keys: reportOf(k1, Key{Public: rogue, Generation: 3}), SignedAt: f.now().Add(time.Hour + time.Duration(round)*time.Minute), Authorities: []string{"a"}})
			})
		},
		"refused": func() error {
			return f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
				return f.ring.RefusedStatement(f.ctx, tx, Observation{Device: dev}, agentproto.KeyRefusal{Statement: "handover", ID: "s", Reason: "r"})
			})
		},
		"log": func() error {
			return f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
				_, err := f.ring.AcceptLog(f.ctx, tx, LogDevice{ID: dev, Org: f.org, Site: f.site}, log, now)
				return err
			})
		},
		"log ahead": func() error {
			return f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
				_, err := f.ring.AcceptLog(f.ctx, tx, LogDevice{ID: dev, Org: f.org, Site: f.site}, agentproto.InstructionLogReport{Acked: 900}, now)
				return err
			})
		},
		"restore": func() error {
			_, err := RecordRestore(f.ctx, f.db, audit.New(f.db, nil), now)
			return err
		},
		"generation": func() error {
			return f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
				_, err := f.ring.NextGeneration(f.ctx, tx, now)
				return err
			})
		},
		"reload": func() error { return f.ring.Reload(f.ctx) },
		"purge":  func() error { return f.ring.Purge(f.ctx) },
		"instances": func() error {
			_, err := f.ring.Instances(f.ctx)
			return err
		},
		"for": func() error {
			return f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
				_, err := f.ring.For(f.ctx, tx, dev)
				return err
			})
		},
		"remove": func() error { return f.ring.Remove(f.ctx) },
	}
	for _, table := range []string{"issued_instructions", "device_unknown_keys", "device_instruction_log", "device_instruction_flags",
		"server_restores", "server_instances", "job_keys"} {
		f.super(`ALTER TABLE ` + table + ` RENAME TO ` + table + `_x`)
		failed := 0
		round++
		for _, call := range calls {
			if call() != nil {
				failed++
			}
		}
		f.super(`ALTER TABLE ` + table + `_x RENAME TO ` + table)
		if failed == 0 {
			t.Errorf("nothing failed without %s", table)
		}
	}
	// A canceled context fails each call at once.
	ctx, cancel := context.WithCancel(f.ctx)
	cancel()
	if err := f.ring.Reload(ctx); err == nil {
		t.Error("reload on a canceled context")
	}
	// A ring that cannot reach the database cannot open.
	f.super(`ALTER TABLE job_keys RENAME TO job_keys_x`)
	if _, err := Open(f.ctx, f.db, f.sealer, quiet(), Options{}); err == nil {
		t.Error("opened without the table")
	}
	f.super(`ALTER TABLE job_keys_x RENAME TO job_keys`)
}
