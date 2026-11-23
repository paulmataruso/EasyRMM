//go:build integration

package agents

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// beatWith sends a heartbeat that reports MeshAgent's state.
func (f *fixture) beatWith(d *Device, st *agentproto.MeshAgentState) {
	f.t.Helper()
	if _, err := f.svc.Heartbeat(f.ctx, d, netip.MustParseAddr("192.0.2.10"), agentproto.HeartbeatRequest{
		Facts:     agentproto.Facts{Hostname: "pc", Platform: "linux", Arch: "amd64", AgentVersion: "1"},
		MeshAgent: st,
	}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) meshState(id uuid.UUID) (state string, at *time.Time) {
	f.t.Helper()
	var s *string
	err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT meshagent_state::text, meshagent_state_at FROM devices WHERE id = $1`, id).Scan(&s, &at)
	})
	if err != nil {
		f.t.Fatal(err)
	}
	if s == nil {
		return "", at
	}
	return *s, at
}

func TestHeartbeatStoresMeshAgentState(t *testing.T) {
	f := newFixture(t)
	f.mesh.groups[f.hq] = "mesh//g1"
	f.mesh.host = "Mesh.Example.test:443"
	dev, _ := f.enroll(f.hq, "pc")
	if s, at := f.meshState(dev.ID); s != "" || at != nil {
		t.Fatalf("before any report: %q %v", s, at)
	}

	// The host in its settings is the server's (compared without case).
	f.beatWith(dev, &agentproto.MeshAgentState{Installed: true, Running: true, Host: "mesh.example.test:443", Error: "x\x00y\n"})
	s, at := f.meshState(dev.ID)
	if at == nil || !strings.Contains(s, `"hostOk": true`) || !strings.Contains(s, `"running": true`) || !strings.Contains(s, `"error": "xy"`) {
		t.Errorf("state = %s at %v", s, at)
	}

	// Another server: not the one the settings the server gives out name.
	f.beatWith(dev, &agentproto.MeshAgentState{Installed: true, Running: false, Host: "old.example.test:443"})
	if s, _ := f.meshState(dev.ID); !strings.Contains(s, `"hostOk": false`) || !strings.Contains(s, `"running": false`) {
		t.Errorf("another server: %s", s)
	}

	// A heartbeat without the report (an older agent) keeps what was stored.
	_, before := f.meshState(dev.ID)
	f.beatWith(dev, nil)
	if s, at := f.meshState(dev.ID); !strings.Contains(s, "old.example.test") || !at.Equal(*before) {
		t.Errorf("state after a heartbeat without one: %s at %v", s, at)
	}

	// Long fields are cut.
	f.beatWith(dev, &agentproto.MeshAgentState{Error: strings.Repeat("é", 1000), Host: strings.Repeat("h", 400)})
	if s, _ := f.meshState(dev.ID); len(s) > 1200 {
		t.Errorf("state is %d bytes", len(s))
	}
}

func TestMeshHostIsAskedOncePerSite(t *testing.T) {
	f := newFixture(t)
	f.mesh.groups[f.hq] = "mesh//g1"
	f.mesh.host = "mesh.example.test:443"
	a, _ := f.enroll(f.hq, "a")
	b, _ := f.enroll(f.hq, "b")
	st := &agentproto.MeshAgentState{Installed: true, Running: true, Host: "mesh.example.test:443"}
	f.beatWith(a, st)
	f.beatWith(b, st)
	f.beatWith(a, st)
	if f.mesh.settings != 1 {
		t.Errorf("settings fetched %d times", f.mesh.settings)
	}

	// A site MeshCentral has no group for: the host cannot be judged, and
	// the failure is remembered for a moment only.
	c, _ := f.enroll(f.other, "c")
	f.beatWith(c, st)
	if s, _ := f.meshState(c.ID); !strings.Contains(s, `"hostOk": null`) {
		t.Errorf("without a group: %s", s)
	}
	f.beatWith(c, st)
	if f.mesh.settings != 1 {
		t.Errorf("settings fetched %d times for a site without a group", f.mesh.settings)
	}
	f.svc.now = func() time.Time { return time.Now().Add(MeshHostRetry + time.Second) }
	f.mesh.groups[f.other] = "mesh//g2"
	f.beatWith(c, st)
	if s, _ := f.meshState(c.ID); !strings.Contains(s, `"hostOk": true`) {
		t.Errorf("after the retry time: %s", s)
	}
}
