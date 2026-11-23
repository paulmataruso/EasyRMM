//go:build integration

package remote

import (
	"context"
	"crypto/rand"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/meshcentral"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

// nodesMesh stands in for MeshCentral's node list, the one call a device
// sync makes of it.
type nodesMesh struct {
	Mesh
	nodes []meshcentral.Node
}

func (m *nodesMesh) Nodes(context.Context) ([]meshcentral.Node, error) { return m.nodes, nil }

// A node an enrolled device reported that sits in another site's group is
// unlinked, the device says so, and it clears once the node is in the
// device's own site; remote_changed_at follows the connection.
func TestSyncFlagsANodeInAnotherSitesGroup(t *testing.T) {
	inst := testdb.New(t)
	ctx := context.Background()
	db := inst.DB
	one := func(sql string, args ...any) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := db.InTx(ctx, database.System, func(tx pgx.Tx) error { return tx.QueryRow(ctx, sql, args...).Scan(&id) }); err != nil {
			t.Fatal(err)
		}
		return id
	}
	org := one(`INSERT INTO organizations (name) VALUES ('Acme') RETURNING id`)
	hq := one(`INSERT INTO sites (organization_id, name) VALUES ($1, 'HQ') RETURNING id`, org)
	branch := one(`INSERT INTO sites (organization_id, name) VALUES ($1, 'Branch') RETURNING id`, org)
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	const node = "node//abc"
	dev := one(`INSERT INTO devices (organization_id, site_id, name, hostname, platform, agent_public_key, enrolled_at, mesh_node_id)
		VALUES ($1, $2, 'pc', 'pc', 'linux', $3, now(), $4) RETURNING id`, org, hq, key, node)
	type row struct {
		linked, wrong, online bool
		changed               bool
	}
	read := func() row {
		t.Helper()
		var r row
		if err := db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT mesh_node_id IS NOT NULL, mesh_wrong_group, remote_online, remote_changed_at IS NOT NULL
				FROM devices WHERE id = $1`, dev).Scan(&r.linked, &r.wrong, &r.online, &r.changed)
		}); err != nil {
			t.Fatal(err)
		}
		return r
	}
	relink := func() {
		t.Helper()
		// The sync recorded the node as a discovered device of the other
		// site; a heartbeat's link is refused while that stands, so it is
		// taken away here, as the console's merge would.
		if err := db.InTx(ctx, database.System, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `DELETE FROM devices WHERE agent_public_key IS NULL`); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `UPDATE devices SET mesh_node_id = $2 WHERE id = $1`, dev, node)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	mesh := &nodesMesh{nodes: []meshcentral.Node{{ID: node, MeshID: "mesh//branch", Conn: 1}}}
	svc := New(db, audit.New(db, nil), mesh, Config{DiscoveryGrace: time.Hour}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	known := map[string]uuid.UUID{"mesh//hq": hq, "mesh//branch": branch}

	if err := svc.syncDevices(ctx, known); err != nil {
		t.Fatal(err)
	}
	if r := read(); r.linked || !r.wrong || r.online {
		t.Fatalf("node in another group: %+v", r)
	}
	// The agent reports the node again with its next heartbeat; the flag
	// stays until a sync finds the node in the device's own site.
	relink()
	if err := svc.syncDevices(ctx, known); err != nil {
		t.Fatal(err)
	}
	if r := read(); r.linked || !r.wrong {
		t.Fatalf("reported again: %+v", r)
	}
	// The node is moved to the device's group, connected.
	mesh.nodes[0].MeshID = "mesh//hq"
	relink()
	if err := svc.syncDevices(ctx, known); err != nil {
		t.Fatal(err)
	}
	if r := read(); !r.linked || r.wrong || !r.online || !r.changed {
		t.Fatalf("in its own group: %+v", r)
	}
}
