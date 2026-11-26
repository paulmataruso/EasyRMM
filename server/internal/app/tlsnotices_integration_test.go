//go:build integration

package app

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/notify"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
	"github.com/paulmataruso/easyrmm/server/internal/tlscert"
)

// The certificate service's notices in the console: one open per name, at the
// level it has now; raising the other level resolves the first, and closing
// resolves both. A database that fails returns the error.
func TestTLSNoticesPublish(t *testing.T) {
	inst := testdb.New(t)
	ctx := context.Background()
	n := notify.New(inst.DB, nil, nil, nil, nil, nil)
	pub := tlsNotices{n: n}

	type row struct {
		kind, title, detail string
		open                bool
	}
	read := func() []row {
		t.Helper()
		var out []row
		err := inst.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT kind, title, detail, resolved_at IS NULL FROM notices WHERE subject = 'tls:rmm.test' ORDER BY opened_at, kind`)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var r row
				if err := rows.Scan(&r.kind, &r.title, &r.detail, &r.open); err != nil {
					return err
				}
				out = append(out, r)
			}
			return rows.Err()
		})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	ev := tlscert.Event{Key: "tls:rmm.test", Name: "rmm.test", Open: true, Severity: tlscert.LevelWarning, Summary: "Renewal is failing.", LastError: "dial tcp: refused"}

	if err := pub.Publish(ctx, ev); err != nil {
		t.Fatal(err)
	}
	got := read()
	if len(got) != 1 || got[0].kind != noticeTLSWarning || !got[0].open || !strings.Contains(got[0].title, "needs attention: rmm.test") ||
		got[0].detail != "Renewal is failing. Last error: dial tcp: refused" {
		t.Fatalf("warning: %+v", got)
	}

	ev.Severity, ev.LastError = tlscert.LevelCritical, ""
	if err := pub.Publish(ctx, ev); err != nil {
		t.Fatal(err)
	}
	got = read()
	if len(got) != 2 || got[0].open || got[1].kind != noticeTLSCritical || !got[1].open ||
		!strings.Contains(got[1].title, "about to expire") || got[1].detail != "Renewal is failing." {
		t.Fatalf("critical: %+v", got)
	}

	if err := pub.Publish(ctx, tlscert.Event{Key: ev.Key, Name: ev.Name}); err != nil {
		t.Fatal(err)
	}
	for _, r := range read() {
		if r.open {
			t.Fatalf("still open after closing: %+v", r)
		}
	}

	inst.DB.Close()
	if err := pub.Publish(ctx, ev); err == nil {
		t.Error("opening on a closed database succeeded")
	}
	if err := pub.Publish(ctx, tlscert.Event{Key: ev.Key}); err == nil {
		t.Error("closing on a closed database succeeded")
	}
}
