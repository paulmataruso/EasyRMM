//go:build integration

package agents

import (
	"log/slog"
	"net/netip"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/modules"
)

// A heartbeat stores the roles the agent reported, answers a rescan request
// once, and one that reports none leaves the stored list alone (ADR-0073).
func TestHeartbeatStoresRolesAndAsksForARescan(t *testing.T) {
	f := newUpdates(t, "build", "v1")
	f.svc.SetRoleStore(modules.New(f.db, nil, slog.Default()))
	d, _ := f.enroll(f.hq, "dc1")
	beat := func(roles []agentproto.Role) *agentproto.HeartbeatResponse {
		t.Helper()
		resp, err := f.svc.Heartbeat(f.ctx, d, netip.MustParseAddr("192.0.2.10"), agentproto.HeartbeatRequest{
			Facts: agentproto.Facts{Hostname: "h", Platform: "windows", Arch: "amd64", AgentVersion: "v1", Roles: roles},
		})
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	stored := func() (string, bool) {
		var s *string
		var at bool
		if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
			return tx.QueryRow(f.ctx, `SELECT roles::text, roles_at IS NOT NULL FROM devices WHERE id = $1`, d.ID).Scan(&s, &at)
		}); err != nil {
			t.Fatal(err)
		}
		if s == nil {
			return "", at
		}
		return *s, at
	}
	beat(nil)
	if s, at := stored(); s != "" || at {
		t.Fatalf("a heartbeat with no roles stored %q", s)
	}
	beat([]agentproto.Role{{Name: "dns", State: "present"}, {Name: "nonsense", State: "present"}})
	if s, at := stored(); s != `[{"name": "dns", "state": "present"}]` || !at {
		t.Fatalf("stored %q", s)
	}
	beat(nil)
	if s, _ := stored(); s == "" {
		t.Error("a heartbeat with no roles cleared the list")
	}
	f.exec(`UPDATE devices SET roles_rescan = true WHERE id = $1`, d.ID)
	if !beat(nil).RescanRoles {
		t.Error("the answer did not ask for a rescan")
	}
	if beat(nil).RescanRoles {
		t.Error("the answer asked twice")
	}
}
