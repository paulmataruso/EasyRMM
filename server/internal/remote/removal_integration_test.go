//go:build integration

package remote

import (
	"net/url"
	"os"
	"os/exec"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/agents"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devices"
	"github.com/paulmataruso/easyrmm/server/internal/meshcentral"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// retiredState is what EasyRMM recorded about a removed device's node.
type retiredState struct {
	attemptAt  *time.Time
	uninstalls int
	removed    bool
	err        string
}

func (r *rig) retired(device uuid.UUID) retiredState {
	r.t.Helper()
	var st retiredState
	err := r.db.ReadTx(r.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(r.ctx, `SELECT mesh_attempt_at, mesh_uninstalls, mesh_removed_at IS NOT NULL, mesh_error
			FROM retired_devices WHERE device_id = $1`, device).Scan(&st.attemptAt, &st.uninstalls, &st.removed, &st.err)
	})
	if err != nil {
		r.t.Fatal(err)
	}
	return st
}

func (r *rig) hasNode(id string) bool {
	r.t.Helper()
	nodes, err := r.mesh.Nodes(r.ctx)
	if err != nil {
		r.t.Fatal(err)
	}
	return slices.ContainsFunc(nodes, func(n meshcentral.Node) bool { return n.ID == id })
}

// TestRemovedDeviceNode removes a device that has a MeshAgent only, the real
// one in a container, and has MeshCentral forget its node (ADR-0050). This
// MeshAgent runs in connect mode, not as the service MeshCentral installs,
// so it ignores the request to uninstall itself, as one EasyRMM's agent
// runs does: its node is removed after RetiredUninstalls requests, comes
// back when it reconnects, and is removed again only after RetiredReturnGap.
// EasyRMM lists none of it.
func TestRemovedDeviceNode(t *testing.T) {
	image := os.Getenv("EASYRMM_TEST_AGENT_IMAGE")
	if image == "" {
		t.Fatal("EASYRMM_TEST_AGENT_IMAGE is not set (a glibc Linux image for the test agent; see the Makefile)")
	}
	r := newRig(t)
	acme := r.org("Acme")
	hq := r.site(acme.ID, "HQ")
	_, tech := r.user("Tess Tech", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: acme.ID, SiteID: hq.ID})
	r.reconcile()
	upstream, _ := url.Parse(r.env.URL)
	g, err := NewGateway(r.svc, GatewayConfig{Upstream: upstream, Secure: true, CacheTTL: 200 * time.Millisecond}, r.log)
	if err != nil {
		t.Fatal(err)
	}
	r.serveGateway(g)

	// The device sync runs when the test says, on a clock it moves.
	svc := New(r.db, r.audit, r.mesh, r.svc.cfg, r.log)
	clock := time.Now()
	svc.now = func() time.Time { return clock }
	syncNow := func() {
		t.Helper()
		if err := svc.SyncDevices(r.ctx); err != nil {
			t.Fatal(err)
		}
	}
	listed := func() []*devices.Device {
		t.Helper()
		list, err := r.dev.List(r.ctx, tech, devices.Query{})
		if err != nil {
			t.Fatal(err)
		}
		return list
	}

	dir := r.agentFiles(r.meshOfSite(hq.ID))
	name := "easyrmm-testremoved-" + uuid.NewString()[:8]
	docker(t, "run", "-d", "--name", name, "--network", "host",
		"--add-host", r.env.Hostname+":127.0.0.1",
		"--user", "65534:65534", "--read-only", "--tmpfs", "/tmp", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges", "-v", dir+":/agent", "-w", "/agent",
		image, "./meshagent", "connect")
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("agent output:\n%s", docker(t, "logs", "--tail", "50", name))
		}
		_, _ = exec.Command("docker", "rm", "-f", name).CombinedOutput()
	})

	// The MeshAgent connects and is listed as a device with no EasyRMM agent.
	var dev *devices.Device
	deadline := time.Now().Add(2 * time.Minute)
	for dev == nil {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for the MeshAgent's device")
		}
		time.Sleep(2 * time.Second)
		syncNow()
		if list := listed(); len(list) == 1 && list[0].RemoteOnline {
			dev = list[0]
		}
	}

	// Removed from the console: at once, as it has no EasyRMM agent.
	as := agents.New(r.db, r.audit, NewMeshAgents(svc, nil), r.log)
	if st, err := as.RequestRemoval(r.ctx, r.sys, dev.ID); err != nil || st != agents.RemovalDone {
		t.Fatalf("removal: %q %v", st, err)
	}
	if len(listed()) != 0 {
		t.Fatal("device still listed")
	}

	// MeshCentral asks the connected MeshAgent to uninstall itself, once a
	// minute, three times; then it removes the node.
	syncNow()
	if st := r.retired(dev.ID); st.uninstalls != 1 || st.err != "" || st.removed || st.attemptAt == nil {
		t.Fatalf("after the first sync: %+v", st)
	}
	syncNow()
	if st := r.retired(dev.ID); st.uninstalls != 1 {
		t.Errorf("asked again within a minute: %+v", st)
	}
	for range RetiredUninstalls - 1 {
		clock = clock.Add(RetiredAttemptGap)
		syncNow()
	}
	if st := r.retired(dev.ID); st.uninstalls != RetiredUninstalls || st.removed {
		t.Fatalf("after %d requests: %+v", RetiredUninstalls, st)
	}
	// Paused, the MeshAgent stays connected but cannot reconnect once
	// MeshCentral drops it with its node.
	docker(t, "pause", name)
	clock = clock.Add(RetiredAttemptGap)
	syncNow()
	st := r.retired(dev.ID)
	if !st.removed || st.err != "" || st.uninstalls != 0 {
		t.Fatalf("not removed: %+v", st)
	}
	if r.hasNode(dev.MeshNodeID) {
		t.Error("MeshCentral still has the node")
	}
	if len(listed()) != 0 {
		t.Error("the node became a device again")
	}
	if n := r.count(`SELECT count(*) FROM audit_log WHERE action = 'device.remove' AND device_id = $1 AND details->>'agent' = 'false'`, dev.ID); n != 1 {
		t.Errorf("removal audit records = %d", n)
	}

	// The MeshAgent reconnects, and MeshCentral makes its node again. It is
	// left alone for RetiredReturnGap, not listed, then removed without
	// asking.
	docker(t, "unpause", name)
	r.waitFor(2*time.Minute, "the MeshAgent to reconnect", func() bool {
		time.Sleep(time.Second)
		return r.hasNode(dev.MeshNodeID)
	})
	removedAt := *st.attemptAt
	clock = clock.Add(RetiredAttemptGap)
	syncNow()
	if st := r.retired(dev.ID); !st.attemptAt.Equal(removedAt) || len(listed()) != 0 {
		t.Errorf("the returned node within the gap: %+v, %d devices", st, len(listed()))
	}
	clock = clock.Add(RetiredReturnGap)
	syncNow()
	if st := r.retired(dev.ID); st.attemptAt.Equal(removedAt) || st.uninstalls != 0 || st.err != "" || !st.removed {
		t.Errorf("the returned node after the gap: %+v", st)
	}
	if len(listed()) != 0 {
		t.Error("the returned node became a device")
	}
}
