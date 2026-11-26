//go:build integration

package agents

import (
	"net/netip"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// The heartbeat answers the interval operators set for the device, keeps it,
// and counts the device online for three of it (ADR-0058).
func TestHeartbeatAnswersAndKeepsTheDevicesInterval(t *testing.T) {
	f := newFixture(t)
	d, _ := f.enroll(f.hq, "srv")
	beat := func() *agentproto.HeartbeatResponse {
		t.Helper()
		resp, err := f.svc.Heartbeat(f.ctx, d, netip.MustParseAddr("192.0.2.10"), agentproto.HeartbeatRequest{
			Facts: agentproto.Facts{Hostname: "h", Platform: "linux", Arch: "amd64", AgentVersion: "v1"},
		})
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	state := func() (secs int, window time.Duration, updated time.Time) {
		t.Helper()
		if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
			var seen, until time.Time
			if err := tx.QueryRow(f.ctx, `SELECT agent_heartbeat_seconds, agent_last_seen_at, agent_online_until, updated_at FROM devices WHERE id = $1`, d.ID).
				Scan(&secs, &seen, &until, &updated); err != nil {
				return err
			}
			window = until.Sub(seen)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return secs, window, updated
	}

	if got := beat().HeartbeatSeconds; got != 60 {
		t.Fatalf("nothing set: answered %d", got)
	}
	secs, window, updated := state()
	if secs != 60 || window != 3*time.Minute {
		t.Fatalf("at 60 seconds: kept %d, online for %s", secs, window)
	}

	// A site's value, then the device's own, and the platform's minimum.
	f.exec(`INSERT INTO agent_settings (key, scope, organization_id, site_id, value) VALUES ('agent.heartbeat_seconds', 'site', $1, $2, '300')`, f.org, f.hq)
	if got := beat().HeartbeatSeconds; got != 300 {
		t.Fatalf("site set to 300: answered %d", got)
	}
	secs, window, afterSecs := state()
	if secs != 300 || window != 15*time.Minute {
		t.Fatalf("at 300 seconds: kept %d, online for %s", secs, window)
	}
	// Neither new column, nor the last-seen time, moves updated_at.
	if !afterSecs.Equal(updated) {
		t.Fatalf("updated_at moved from %s to %s", updated, afterSecs)
	}
	f.exec(`INSERT INTO agent_settings (key, scope, organization_id, site_id, device_id, value) VALUES ('agent.heartbeat_seconds', 'device', $1, $2, $3, '30')`, f.org, f.hq, d.ID)
	if got := beat().HeartbeatSeconds; got != 30 {
		t.Fatalf("device set to 30: answered %d", got)
	}
	f.exec(`INSERT INTO settings (key, value) VALUES ('agent_settings.limits', '{"minHeartbeatSeconds": 90}')`)
	if got := beat().HeartbeatSeconds; got != 90 {
		t.Fatalf("under a minimum of 90: answered %d", got)
	}
	if secs, window, _ = state(); secs != 90 || window != 270*time.Second {
		t.Fatalf("under a minimum: kept %d, online for %s", secs, window)
	}
	// A damaged limits setting means the defaults, and never a refused
	// heartbeat.
	f.exec(`UPDATE settings SET value = '{"minHeartbeatSeconds": "x"}' WHERE key = 'agent_settings.limits'`)
	if got := beat().HeartbeatSeconds; got != 30 {
		t.Fatalf("damaged limits: answered %d", got)
	}

	// The channel's settings push carries the same interval.
	cs, err := f.svc.ChannelSettings(f.ctx, d.ID)
	if err != nil || cs == nil || cs.HeartbeatSeconds != 30 {
		t.Fatalf("channel settings: %+v %v", cs, err)
	}

	// Anything else that writes the last-seen time gets the window from the
	// database, from the interval kept.
	f.exec(`UPDATE devices SET agent_last_seen_at = now() - interval '1 hour' WHERE id = $1`, d.ID)
	if secs, window, _ = state(); secs != 30 || window != 90*time.Second {
		t.Fatalf("a direct write: kept %d, online for %s", secs, window)
	}
	f.exec(`UPDATE devices SET agent_online_until = now() + interval '1 day' WHERE id = $1`, d.ID)
	var until time.Time
	_ = f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT agent_online_until FROM devices WHERE id = $1`, d.ID).Scan(&until)
	})
	if time.Until(until) < 23*time.Hour {
		t.Fatalf("a writer that sets the time itself was overridden: %s", until)
	}
}
