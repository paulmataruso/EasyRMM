//go:build integration

package remote

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devices"
	"github.com/paulmataruso/easyrmm/server/internal/meshcentral"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

var errBoom = errors.New("injected MeshCentral failure")

// flakyMesh passes calls to the real client, except those told to fail, and
// can stand in fake devices for the node list.
type flakyMesh struct {
	Mesh
	mu    sync.Mutex
	fail  map[string]bool
	nodes []meshcentral.Node
}

func (f *flakyMesh) failing(m string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fail[m]
}

func (f *flakyMesh) set(methods ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail = map[string]bool{}
	for _, m := range methods {
		f.fail[m] = true
	}
}

func (f *flakyMesh) Meshes(ctx context.Context) ([]meshcentral.Mesh, error) {
	if f.failing("Meshes") {
		return nil, errBoom
	}
	return f.Mesh.Meshes(ctx)
}

func (f *flakyMesh) CreateMesh(ctx context.Context, name, desc string) (string, error) {
	if f.failing("CreateMesh") {
		return "", errBoom
	}
	return f.Mesh.CreateMesh(ctx, name, desc)
}

func (f *flakyMesh) EditMesh(ctx context.Context, id, name, desc string) error {
	if f.failing("EditMesh") {
		return errBoom
	}
	return f.Mesh.EditMesh(ctx, id, name, desc)
}

func (f *flakyMesh) DeleteMesh(ctx context.Context, id string) error {
	if f.failing("DeleteMesh") {
		return errBoom
	}
	return f.Mesh.DeleteMesh(ctx, id)
}

func (f *flakyMesh) Users(ctx context.Context) ([]meshcentral.User, error) {
	if f.failing("Users") {
		return nil, errBoom
	}
	return f.Mesh.Users(ctx)
}

func (f *flakyMesh) AddUser(ctx context.Context, name, real string, rights uint32) error {
	if f.failing("AddUser") {
		return errBoom
	}
	return f.Mesh.AddUser(ctx, name, real, rights)
}

func (f *flakyMesh) EditUser(ctx context.Context, id, real string, rights uint32) error {
	if f.failing("EditUser") {
		return errBoom
	}
	return f.Mesh.EditUser(ctx, id, real, rights)
}

func (f *flakyMesh) DeleteUser(ctx context.Context, id string) error {
	if f.failing("DeleteUser") {
		return errBoom
	}
	return f.Mesh.DeleteUser(ctx, id)
}

func (f *flakyMesh) SetMeshRights(ctx context.Context, mesh, user string, rights uint32) error {
	if f.failing("SetMeshRights") {
		return errBoom
	}
	return f.Mesh.SetMeshRights(ctx, mesh, user, rights)
}

func (f *flakyMesh) RemoveMeshUser(ctx context.Context, mesh, user string) error {
	if f.failing("RemoveMeshUser") {
		return errBoom
	}
	return f.Mesh.RemoveMeshUser(ctx, mesh, user)
}

func (f *flakyMesh) Nodes(ctx context.Context) ([]meshcentral.Node, error) {
	if f.failing("Nodes") {
		return nil, errBoom
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.nodes != nil {
		return f.nodes, nil
	}
	return f.Mesh.Nodes(ctx)
}

func wantErrs(t *testing.T, err error, parts ...string) {
	t.Helper()
	if !errors.Is(err, errBoom) {
		t.Fatalf("error = %v, want the injected failure", err)
	}
	for _, p := range parts {
		if !strings.Contains(err.Error(), p) {
			t.Errorf("error %q does not mention %q", err, p)
		}
	}
}

// TestReconcileContinuesPastFailures checks that one failing MeshCentral
// command does not stop the rest of a reconciliation, and that every
// failure is reported.
func TestReconcileContinuesPastFailures(t *testing.T) {
	r := newRig(t)
	acme := r.org("Acme")
	hq, branch, gone := r.site(acme.ID, "HQ"), r.site(acme.ID, "Branch"), r.site(acme.ID, "Closing")
	stay, _ := r.user("Stan Stays", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: acme.ID})
	narrowed, _ := r.user("Nell Narrowed", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: acme.ID})
	leaving, _ := r.user("Lee Leaving", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: acme.ID})
	r.reconcile()

	f := &flakyMesh{Mesh: r.mesh}
	svc := New(r.db, r.audit, f, r.svc.cfg, r.log)

	// Creating groups fails; accounts are still handled.
	newSite := r.site(acme.ID, "New")
	f.set("CreateMesh")
	wantErrs(t, svc.Reconcile(r.ctx), "creating group for site "+newSite.ID.String())
	if st := svc.Status(r.ctx); st.LastError == "" || st.LastErrorAt == nil {
		t.Errorf("status after a failed pass = %+v", st)
	}
	f.set()
	if err := svc.Reconcile(r.ctx); err != nil {
		t.Fatal(err)
	}
	if st := svc.Status(r.ctx); st.LastError != "" || st.LastSyncAt == nil {
		t.Errorf("status after a good pass = %+v", st)
	}

	// Every kind of change needed at once, with every command failing.
	if _, err := r.ten.UpdateOrganization(r.ctx, r.sys, acme.ID, tenancyName("Acme Corp")); err != nil {
		t.Fatal(err)
	}
	r.exec(`DELETE FROM sites WHERE id = $1`, gone.ID)
	r.exec(`UPDATE users SET display_name = 'Stan Renamed' WHERE id = $1`, stay)
	r.exec(`DELETE FROM role_assignments WHERE user_id = $1`, narrowed)
	r.exec(`INSERT INTO role_assignments (user_id, role, organization_id, site_id) VALUES ($1, 'technician', $2, $3)`, narrowed, acme.ID, hq.ID)
	r.exec(`DELETE FROM role_assignments WHERE user_id = $1`, leaving)
	newcomer, _ := r.user("Nia Newcomer", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: acme.ID, SiteID: branch.ID})
	f.set("EditMesh", "DeleteMesh", "AddUser", "EditUser", "DeleteUser", "SetMeshRights", "RemoveMeshUser")
	wantErrs(t, svc.Reconcile(r.ctx), "renaming group", "deleting group", "creating account for user "+newcomer.String(),
		"updating account for user "+stay.String(), "deleting account "+accountID(leaving), "setting rights of "+accountID(narrowed))

	// Listing failures stop the pass where they occur.
	for method, msg := range map[string]string{"Meshes": "listing device groups", "Users": "listing accounts", "Nodes": "listing devices"} {
		f.set(method)
		wantErrs(t, svc.Reconcile(r.ctx), msg)
	}
	f.set("Nodes")
	wantErrs(t, svc.SyncDevices(r.ctx), "listing devices")

	// With MeshCentral healthy again, everything converges.
	f.set()
	if err := svc.Reconcile(r.ctx); err != nil {
		t.Fatal(err)
	}
	acc := r.accounts()
	if acc[accountID(stay)].RealName != "Stan Renamed" {
		t.Errorf("renamed account = %+v", acc[accountID(stay)])
	}
	if _, ok := acc[accountID(leaving)]; ok {
		t.Error("departed user's account remains")
	}
	if m := r.meshes()[r.meshOfSite(branch.ID)]; m.Links[accountID(narrowed)].Rights != 0 || m.Links[accountID(newcomer)].Rights != fullAccess.Rights() {
		t.Errorf("branch links = %+v", m.Links)
	}
}

func TestSessionLaunchDependsOnMeshCentral(t *testing.T) {
	r := newRig(t)
	acme := r.org("Acme")
	hq := r.site(acme.ID, "HQ")
	techID, tech := r.user("Tess Tech", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: acme.ID, SiteID: hq.ID})
	r.reconcile()
	meshID := r.meshOfSite(hq.ID)

	// Devices as MeshCentral reports them, including unnamed ones.
	f := &flakyMesh{Mesh: r.mesh, nodes: []meshcentral.Node{
		{ID: "node//fault-a", MeshID: meshID, Name: "web-01", OSDesc: "Ubuntu 26.04", Agent: meshcentral.AgentInfo{Type: 6}, Conn: 1},
		{ID: "node//fault-b", MeshID: meshID, OSName: "kiosk-7", Agent: meshcentral.AgentInfo{Type: 4}},
		{ID: "node//fault-c", MeshID: meshID},
		{ID: "node//elsewhere", MeshID: "mesh//not-ours", Name: "ignored"},
	}}
	svc := New(r.db, r.audit, f, r.svc.cfg, r.log)
	if err := svc.SyncDevices(r.ctx); err != nil {
		t.Fatal(err)
	}
	list, err := r.dev.List(r.ctx, tech, devices.Query{})
	if err != nil || len(list) != 3 {
		t.Fatalf("devices = %d, %v", len(list), err)
	}
	names := []string{list[0].Name + "/" + list[0].Platform, list[1].Name + "/" + list[1].Platform, list[2].Name + "/" + list[2].Platform}
	if strings.Join(names, ",") != "kiosk-7/windows,Unnamed device/other,web-01/linux" {
		t.Errorf("devices = %v", names)
	}
	web := list[2]
	if !web.RemoteOnline || web.OSDescription != "Ubuntu 26.04" || web.LastSeenAt == nil {
		t.Errorf("web-01 = %+v", web)
	}
	// A second sync with nothing changed leaves rows alone.
	before := web.UpdatedAt
	if err := svc.SyncDevices(r.ctx); err != nil {
		t.Fatal(err)
	}
	if d, _ := r.dev.Get(r.ctx, tech, web.ID); !d.UpdatedAt.Equal(before) {
		t.Error("an unchanged device was rewritten")
	}

	sess := r.session(techID)
	// A lost group mapping is repaired on the spot.
	r.exec(`DELETE FROM mesh_sites WHERE site_id = $1`, hq.ID)
	if _, err := svc.StartSession(r.ctx, tech, sess, web.ID, KindDesktop); err != nil {
		t.Fatalf("launch with a lost mapping: %v", err)
	}
	if r.meshOfSite(hq.ID) != meshID {
		t.Error("mapping not restored to the existing group")
	}
	// MeshCentral refusing the account or the rights makes the launch fail
	// as unavailable, not as a server error.
	for _, m := range []string{"AddUser", "SetMeshRights"} {
		f.set(m)
		if _, err := svc.StartSession(r.ctx, tech, sess, web.ID, KindDesktop); !errors.Is(err, ErrUnavailable) {
			t.Errorf("launch with %s failing = %v", m, err)
		}
	}
	// No group and no way to make one.
	r.exec(`DELETE FROM mesh_sites WHERE site_id = $1`, hq.ID)
	f.set("Meshes")
	if _, err := svc.StartSession(r.ctx, tech, sess, web.ID, KindDesktop); !errors.Is(err, ErrUnavailable) {
		t.Errorf("launch without a group = %v", err)
	}
	f.set()
	if valid, err := svc.SessionsValid(r.ctx, []uuid.UUID{sess, uuid.New()}); err != nil || !valid[sess] || len(valid) != 1 {
		t.Errorf("SessionsValid = %v %v", valid, err)
	}
}

// TestSyncKeepsEnrolledDevices checks how MeshCentral's device list treats
// devices the EasyRMM agent enrolled: their facts stay the agent's, a
// vanished node only unlinks them, and a node in another site's group is
// never kept linked.
func TestSyncKeepsEnrolledDevices(t *testing.T) {
	r := newRig(t)
	acme := r.org("Acme")
	hq := r.site(acme.ID, "HQ")
	branch := r.site(acme.ID, "Branch")
	_, tech := r.user("Tess Tech", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: acme.ID})
	r.reconcile()
	hqMesh, branchMesh := r.meshOfSite(hq.ID), r.meshOfSite(branch.ID)

	enrolled := func(name, node string) uuid.UUID {
		var id uuid.UUID
		err := r.db.InTx(r.ctx, database.System, func(tx pgx.Tx) error {
			return tx.QueryRow(r.ctx, `INSERT INTO devices (organization_id, site_id, name, hostname, os_description, platform,
					mesh_node_id, agent_public_key, enrolled_at, agent_last_seen_at)
				VALUES ($1, $2, $3, $3, 'Agent OS', 'linux', $4, $5, now(), now()) RETURNING id`,
				acme.ID, hq.ID, name, node, []byte(uuid.NewString()[:32])).Scan(&id)
		})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	kept := enrolled("agent-name", "node//enrolled-a")
	gone := enrolled("gone", "node//enrolled-b")
	moved := enrolled("moved", "node//enrolled-c")

	f := &flakyMesh{Mesh: r.mesh, nodes: []meshcentral.Node{
		{ID: "node//enrolled-a", MeshID: hqMesh, Name: "mesh-name", OSDesc: "Mesh OS", Agent: meshcentral.AgentInfo{Type: 4}, Conn: 1},
		{ID: "node//enrolled-c", MeshID: branchMesh, Name: "elsewhere", Agent: meshcentral.AgentInfo{Type: 6}, Conn: 1},
	}}
	svc := New(r.db, r.audit, f, r.svc.cfg, r.log)
	if err := svc.SyncDevices(r.ctx); err != nil {
		t.Fatal(err)
	}
	d, err := r.dev.Get(r.ctx, tech, kept)
	if err != nil || d.Name != "agent-name" || d.OSDescription != "Agent OS" || d.Platform != "linux" || !d.RemoteOnline || !d.CanDesktop {
		t.Errorf("enrolled device after sync = %+v, %v", d, err)
	}
	if d, err := r.dev.Get(r.ctx, tech, gone); err != nil || d.RemoteAgent || d.RemoteOnline || d.Agent == nil {
		t.Errorf("enrolled device whose node vanished = %+v, %v", d, err)
	}
	if d, err := r.dev.Get(r.ctx, tech, moved); err != nil || d.RemoteAgent || d.SiteID != hq.ID {
		t.Errorf("enrolled device claiming another site's node = %+v, %v", d, err)
	}
	// The other site's node is a discovered device of its own there.
	list, _ := r.dev.List(r.ctx, tech, devices.Query{SiteID: branch.ID})
	if len(list) != 1 || list[0].Name != "elsewhere" || list[0].Agent != nil || !list[0].RemoteAgent {
		t.Errorf("branch devices = %+v", list)
	}

	// Disconnecting updates the enrolled device's connection only.
	f.nodes[0].Conn = 0
	if err := svc.SyncDevices(r.ctx); err != nil {
		t.Fatal(err)
	}
	if d, _ := r.dev.Get(r.ctx, tech, kept); d.RemoteOnline || !d.RemoteAgent || !d.Online {
		t.Errorf("after MeshAgent disconnects: %+v", d)
	}
}
