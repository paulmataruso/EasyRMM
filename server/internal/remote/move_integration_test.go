//go:build integration

package remote

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/meshcentral"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

// groupMesh is a MeshCentral with two device groups and the nodes in them;
// only what the device sync uses is implemented.
type groupMesh struct {
	Mesh
	nodes   []meshcentral.Node
	moved   []string
	moveErr error
}

func (m *groupMesh) Nodes(context.Context) ([]meshcentral.Node, error) { return m.nodes, nil }

func (m *groupMesh) MoveDevice(_ context.Context, node, mesh string) error {
	if m.moveErr != nil {
		return m.moveErr
	}
	m.moved = append(m.moved, node+" -> "+mesh)
	for i := range m.nodes {
		if m.nodes[i].ID == node {
			m.nodes[i].MeshID = mesh
		}
	}
	return nil
}

// A device moved to another site keeps its remote-access link while its node
// is still in the old site's device group; the sync moves the node to the new
// group and then settles the device (ADR-0069). Any other node in another
// site's group is still refused.
func TestSyncMovesNodeOfMovedDevice(t *testing.T) {
	inst := testdb.New(t)
	ctx := context.Background()
	db := inst.DB
	scalar := func(sql string, args ...any) (id uuid.UUID) {
		t.Helper()
		if err := db.InTx(ctx, database.System, func(tx pgx.Tx) error { return tx.QueryRow(ctx, sql, args...).Scan(&id) }); err != nil {
			t.Fatal(err)
		}
		return id
	}
	exec := func(sql string, args ...any) {
		t.Helper()
		if err := db.InTx(ctx, database.System, func(tx pgx.Tx) error { _, err := tx.Exec(ctx, sql, args...); return err }); err != nil {
			t.Fatal(err)
		}
	}
	org := scalar(`INSERT INTO organizations (name) VALUES ('Acme') RETURNING id`)
	a := scalar(`INSERT INTO sites (organization_id, name) VALUES ($1, 'A') RETURNING id`, org)
	b := scalar(`INSERT INTO sites (organization_id, name) VALUES ($1, 'B') RETURNING id`, org)
	device := func(name string, site uuid.UUID, node string) uuid.UUID {
		return scalar(`INSERT INTO devices (organization_id, site_id, name, platform, mesh_node_id, agent_public_key, enrolled_at)
			VALUES ($1, $2, $3, 'linux', $4, sha256($3::text::bytea), now()) RETURNING id`, org, site, name, node)
	}
	moved := device("moved", b, "node-moved")
	exec(`UPDATE devices SET mesh_from_site_id = $2, mesh_settings_pending = true WHERE id = $1`, moved, a)
	stray := device("stray", b, "node-stray") // its node is in A's group, and nobody moved it
	known := map[string]uuid.UUID{"mesh-a": a, "mesh-b": b}
	mesh := &groupMesh{nodes: []meshcentral.Node{{ID: "node-moved", MeshID: "mesh-a"}, {ID: "node-stray", MeshID: "mesh-a"}}}
	s := New(db, audit.New(db, nil), mesh, Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	node := func(id uuid.UUID) (n *string, from *uuid.UUID, pending bool) {
		t.Helper()
		if err := db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT mesh_node_id, mesh_from_site_id, mesh_settings_pending FROM devices WHERE id = $1`, id).Scan(&n, &from, &pending)
		}); err != nil {
			t.Fatal(err)
		}
		return
	}

	// A node that cannot be moved now stays pending, and the link stays.
	mesh.moveErr = errors.New("MeshCentral is busy")
	if err := s.syncDevices(ctx, known); err != nil {
		t.Fatal(err)
	}
	if n, from, _ := node(moved); n == nil || from == nil || *from != a {
		t.Errorf("a failed move lost the device's link or its pending state: node %v from %v", n, from)
	}

	mesh.moveErr = nil
	if err := s.syncDevices(ctx, known); err != nil {
		t.Fatal(err)
	}
	if len(mesh.moved) != 1 || mesh.moved[0] != "node-moved -> mesh-b" {
		t.Fatalf("moved nodes: %v", mesh.moved)
	}
	// The device that nobody moved lost its link to a node of another site's group.
	if n, _, _ := node(stray); n != nil {
		t.Errorf("a node in another site's group stayed linked: %v", *n)
	}
	// The next sync finds the node in the new group and settles the device.
	if err := s.syncDevices(ctx, known); err != nil {
		t.Fatal(err)
	}
	n, from, pending := node(moved)
	if n == nil || *n != "node-moved" || from != nil {
		t.Errorf("after the move: node %v from %v", n, from)
	}
	if !pending {
		t.Error("the agent's settings instruction ended before the agent applied them")
	}
	if len(mesh.moved) != 1 {
		t.Errorf("the node moved again: %v", mesh.moved)
	}
}
