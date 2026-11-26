//go:build integration

package agents

import (
	"net/netip"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// A heartbeat stores the role the agent reports, and one that reports none
// leaves the stored role alone (ADR-0053: the kind of device).
func TestHeartbeatStoresTheAgentsRole(t *testing.T) {
	f := newUpdates(t, "build", "v1")
	d, _ := f.enroll(f.hq, "dc1")
	beat := func(role string) {
		t.Helper()
		if _, err := f.svc.Heartbeat(f.ctx, d, netip.MustParseAddr("192.0.2.10"), agentproto.HeartbeatRequest{
			Facts: agentproto.Facts{Hostname: "h", Platform: "windows", Arch: "amd64", AgentVersion: "v1", Role: role},
		}); err != nil {
			t.Fatal(err)
		}
	}
	stored := func() string {
		var s *string
		if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
			return tx.QueryRow(f.ctx, `SELECT agent_role FROM devices WHERE id = $1`, d.ID).Scan(&s)
		}); err != nil {
			t.Fatal(err)
		}
		if s == nil {
			return ""
		}
		return *s
	}
	beat("")
	if got := stored(); got != "" {
		t.Fatalf("stored %q", got)
	}
	beat("server")
	if got := stored(); got != "server" {
		t.Fatalf("stored %q", got)
	}
	beat("")
	if got := stored(); got != "server" {
		t.Fatalf("a heartbeat with no role cleared it: %q", got)
	}
	beat("workstation")
	if got := stored(); got != "workstation" {
		t.Fatalf("stored %q", got)
	}
}
