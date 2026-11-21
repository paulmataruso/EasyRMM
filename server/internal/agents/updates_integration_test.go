//go:build integration

package agents

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devices"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

func sum(b string) string {
	s := sha256.Sum256([]byte(b))
	return hex.EncodeToString(s[:])
}

// oldSHA is the build the test devices run.
var oldSHA = sum("old build")

// updates is a fixture with agent builds and a clock.
type updates struct {
	*fixture
	pub   ed25519.PublicKey
	priv  ed25519.PrivateKey
	clock time.Time
	build Build
}

func newUpdates(t *testing.T, body, version string) *updates {
	f := &updates{fixture: newFixture(t), clock: time.Now().UTC().Truncate(time.Second)}
	f.pub, f.priv, _ = ed25519.GenerateKey(nil)
	f.svc.now = func() time.Time { return f.clock }
	f.serve(body, version)
	return f
}

// serve makes the server serve a Linux amd64 build.
func (f *updates) serve(body, version string) {
	f.t.Helper()
	dir := f.t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "easyrmm-agent-linux-amd64"), []byte(body), 0o644); err != nil {
		f.t.Fatal(err)
	}
	if version != "" {
		if err := os.WriteFile(filepath.Join(dir, VersionFile), []byte(version+"\n"), 0o644); err != nil {
			f.t.Fatal(err)
		}
	}
	b, err := LoadBuilds(dir)
	if err != nil {
		f.t.Fatal(err)
	}
	f.svc.SetUpdates(b, f.priv)
	f.build, _ = b.For("linux", "amd64")
}

// heartbeat reports that d runs the build with sha and returns the update
// instruction, verified, or nil.
func (f *updates) heartbeat(d *Device, sha string, report *agentproto.UpdateReport) *agentproto.UpdatePayload {
	f.t.Helper()
	resp, err := f.svc.Heartbeat(f.ctx, d, netip.MustParseAddr("192.0.2.10"), agentproto.HeartbeatRequest{
		Facts:  agentproto.Facts{Hostname: "h", Platform: "linux", Arch: "amd64", AgentVersion: "v1", AgentSHA256: sha},
		Update: report,
	})
	if err != nil {
		f.t.Fatal(err)
	}
	if resp.Update == nil {
		return nil
	}
	p, err := agentproto.VerifyUpdate(f.pub, *resp.Update, d.ID.String(), f.clock)
	if err != nil {
		f.t.Fatalf("instruction: %v", err)
	}
	return &p
}

func (f *updates) state(d *Device) (state string, attempts int, errText string) {
	f.t.Helper()
	if f.count(`SELECT count(*) FROM agent_updates WHERE device_id = $1`, d.ID) == 0 {
		return "", 0, ""
	}
	_ = f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT state, attempts, error FROM agent_updates WHERE device_id = $1`, d.ID).
			Scan(&state, &attempts, &errText)
	})
	return state, attempts, errText
}

func (f *updates) user(email string, as ...rbac.Assignment) access.Caller {
	f.t.Helper()
	id := f.uuid(`INSERT INTO users (email, display_name) VALUES ($1, $1) RETURNING id`, email)
	for _, a := range as {
		var org, site *uuid.UUID
		if a.OrganizationID != uuid.Nil {
			org = &a.OrganizationID
		}
		if a.SiteID != uuid.Nil {
			site = &a.SiteID
		}
		f.exec(`INSERT INTO role_assignments (user_id, role, organization_id, site_id) VALUES ($1, $2, $3, $4)`, id, string(a.Role), org, site)
	}
	p, err := rbac.NewPrincipal(id, as)
	if err != nil {
		f.t.Fatal(err)
	}
	return access.User(p, auth.DataScope(p), audit.Actor{Type: audit.ActorUser, ID: id, Label: email})
}

func TestAgentUpdateRollout(t *testing.T) {
	f := newUpdates(t, "new build", "v2")
	if _, err := f.svc.SetUpdatePolicy(f.ctx, f.sys, UpdatePolicy{Mode: UpdateAutomatic, MaxConcurrent: 2}); err != nil {
		t.Fatal(err)
	}
	d1, _ := f.enroll(f.hq, "pc-1")
	d2, _ := f.enroll(f.hq, "pc-2")
	d3, _ := f.enroll(f.hq, "pc-3")
	old, _ := f.enroll(f.hq, "pc-old")

	// An agent that does not report its build cannot update itself.
	if p := f.heartbeat(old, "", nil); p != nil {
		t.Fatal("an old agent was told to update")
	}
	// Two devices update at once; the third waits its turn.
	p1 := f.heartbeat(d1, oldSHA, nil)
	p2 := f.heartbeat(d2, oldSHA, nil)
	if p1 == nil || p2 == nil {
		t.Fatal("no instructions")
	}
	if p1.File != "easyrmm-agent-linux-amd64" || p1.SHA256 != sum("new build") || p1.Size != 9 || p1.Version != "v2" ||
		!p1.ExpiresAt.Equal(f.clock.Add(updateValidity)) || p1.ID == p2.ID {
		t.Errorf("instruction %+v", p1)
	}
	if p := f.heartbeat(d3, oldSHA, nil); p != nil {
		t.Fatal("over the limit")
	}
	if st, _, _ := f.state(d3); st != "queued" {
		t.Errorf("d3 %s", st)
	}
	// While in flight, the instruction is repeated with the same attempt.
	if p := f.heartbeat(d1, oldSHA, nil); p == nil || p.ID != p1.ID {
		t.Errorf("repeat %+v", p)
	}
	// d1 comes back with the new build: done, and d3 gets the free slot.
	if p := f.heartbeat(d1, sum("new build"), nil); p != nil {
		t.Error("told to update again")
	}
	if st, _, _ := f.state(d1); st != "" {
		t.Errorf("d1 still %s", st)
	}
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'device.agent_update' AND outcome = 'success' AND device_id = $1`, d1.ID); n != 1 {
		t.Errorf("success audited %d times", n)
	}
	p3 := f.heartbeat(d3, oldSHA, nil)
	if p3 == nil {
		t.Fatal("d3 still waits")
	}

	// d2 reports a failure: it waits, then gets another attempt.
	if p := f.heartbeat(d2, oldSHA, &agentproto.UpdateReport{ID: "someone else's", Error: "x"}); p == nil || p.ID != p2.ID {
		t.Fatal("a report of another attempt counted")
	}
	if p := f.heartbeat(d2, oldSHA, &agentproto.UpdateReport{ID: p2.ID, Error: "checksum\x00 mismatch"}); p != nil {
		t.Fatal("retried at once")
	}
	if st, n, e := f.state(d2); st != "queued" || n != 1 || e != "checksum mismatch" {
		t.Errorf("d2 %s %d %q", st, n, e)
	}
	f.clock = f.clock.Add(updateBackoff(1) + time.Minute)
	// d3 did not come back in time: its attempt failed too, and waits.
	if p := f.heartbeat(d3, oldSHA, nil); p != nil {
		t.Fatal("d3: a new attempt without waiting")
	}
	if st, n, e := f.state(d3); st != "queued" || n != 1 || !strings.Contains(e, "did not come back with the new build within 15 minutes") {
		t.Errorf("d3 %s %d %q", st, n, e)
	}
	p2b := f.heartbeat(d2, oldSHA, &agentproto.UpdateReport{ID: p2.ID, Error: "checksum mismatch"})
	if p2b == nil || p2b.ID == p2.ID {
		t.Fatal("d2: no second attempt")
	}
	// Two more failures: given up, and audited.
	f.heartbeat(d2, oldSHA, &agentproto.UpdateReport{ID: p2b.ID, Error: "again"})
	f.clock = f.clock.Add(2 * time.Hour)
	p2c := f.heartbeat(d2, oldSHA, nil)
	if p2c == nil {
		t.Fatal("d2: no third attempt")
	}
	if p := f.heartbeat(d2, oldSHA, &agentproto.UpdateReport{ID: p2c.ID, Error: "and again"}); p != nil {
		t.Fatal("a fourth attempt")
	}
	if st, n, _ := f.state(d2); st != "failed" || n != 3 {
		t.Errorf("d2 %s %d", st, n)
	}
	f.clock = f.clock.Add(24 * time.Hour)
	if p := f.heartbeat(d2, oldSHA, nil); p != nil {
		t.Fatal("a failed update went out again by itself")
	}
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'device.agent_update' AND outcome = 'failure' AND device_id = $1`, d2.ID); n != 1 {
		t.Errorf("failure audited %d times", n)
	}

	// Asking again starts over.
	if err := f.svc.RequestUpdate(f.ctx, f.sys, d2.ID); err != nil {
		t.Fatal(err)
	}
	if st, n, e := f.state(d2); st != "queued" || n != 0 || e != "" {
		t.Errorf("d2 after the request %s %d %q", st, n, e)
	}
	if p := f.heartbeat(d2, oldSHA, nil); p == nil {
		t.Fatal("the request did not go out")
	}

	// A new build replaces the target of updates in flight.
	f.serve("newer build", "v3")
	p := f.heartbeat(d2, oldSHA, nil)
	if p == nil || p.SHA256 != sum("newer build") || p.Version != "v3" {
		t.Fatalf("not retargeted: %+v", p)
	}
	// A device that came back with the previous target goes on to the new one.
	if p := f.heartbeat(d1, sum("new build"), nil); p == nil || p.SHA256 != sum("newer build") {
		t.Errorf("d1 not moved on: %+v", p)
	}
}

func TestAgentUpdateModes(t *testing.T) {
	f := newUpdates(t, "new build", "")
	d1, _ := f.enroll(f.hq, "pc-1")
	d2, _ := f.enroll(f.hq, "pc-2")

	if _, err := f.svc.SetUpdatePolicy(f.ctx, f.sys, UpdatePolicy{Mode: UpdateManual, MaxConcurrent: 5}); err != nil {
		t.Fatal(err)
	}
	if p := f.heartbeat(d1, oldSHA, nil); p != nil {
		t.Fatal("manual mode updated a device nobody asked for")
	}
	f.heartbeat(d2, oldSHA, nil)
	if st, _, _ := f.state(d1); st != "" {
		t.Errorf("row in manual mode: %s", st)
	}
	if err := f.svc.RequestUpdate(f.ctx, f.sys, d1.ID); err != nil {
		t.Fatal(err)
	}
	if p := f.heartbeat(d1, oldSHA, nil); p == nil || p.Version != "" {
		t.Fatalf("the request did not go out: %+v", p)
	}

	// Off: nothing starts, but an update in flight goes on.
	if _, err := f.svc.SetUpdatePolicy(f.ctx, f.sys, UpdatePolicy{Mode: UpdateOff, MaxConcurrent: 5}); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.RequestUpdate(f.ctx, f.sys, d2.ID); err != nil {
		t.Fatal(err)
	}
	if p := f.heartbeat(d2, oldSHA, nil); p != nil {
		t.Error("off mode started an update")
	}
	if p := f.heartbeat(d1, oldSHA, nil); p == nil {
		t.Error("off mode dropped the update in flight")
	}

	// Asking for an update in flight keeps it in flight.
	before := f.heartbeat(d1, oldSHA, nil)
	if err := f.svc.RequestUpdate(f.ctx, f.sys, d1.ID); err != nil {
		t.Fatal(err)
	}
	if p := f.heartbeat(d1, oldSHA, nil); p == nil || p.ID != before.ID {
		t.Error("asking again restarted the update in flight")
	}

	// The update's audit trail.
	for action, want := range map[string]int{"agent_updates.update": 2, "device.agent_update_request": 3} {
		if n := f.count(`SELECT count(*) FROM audit_log WHERE action = $1`, action); n != want {
			t.Errorf("%s audited %d times, want %d", action, n, want)
		}
	}
	// A heartbeat keeps working when the stored setting is damaged.
	f.exec(`UPDATE settings SET value = '{"mode":"sometimes"}' WHERE key = $1`, updatePolicyKey)
	if p := f.heartbeat(d2, oldSHA, nil); p != nil {
		t.Error("an update went out under a damaged setting")
	}
	if _, err := f.svc.UpdateSettings(f.ctx, f.sys); err == nil {
		t.Error("a damaged setting was read")
	}
}

func TestAgentUpdateSettingsAndAccess(t *testing.T) {
	f := newUpdates(t, "new build", "v2")
	d1, _ := f.enroll(f.hq, "pc-1")
	d2, _ := f.enroll(f.hq, "pc-2")
	d3, _ := f.enroll(f.hq, "pc-3")
	old, _ := f.enroll(f.hq, "pc-old")
	f.heartbeat(old, "", nil)
	f.heartbeat(d3, f.build.SHA256, nil)
	if _, err := f.svc.SetUpdatePolicy(f.ctx, f.sys, UpdatePolicy{Mode: UpdateManual, MaxConcurrent: 1}); err != nil {
		t.Fatal(err)
	}
	f.heartbeat(d1, oldSHA, nil)
	f.heartbeat(d2, oldSHA, nil)

	s, err := f.svc.UpdateSettings(f.ctx, f.sys)
	if err != nil {
		t.Fatal(err)
	}
	if s.Mode != UpdateManual || s.MaxConcurrent != 1 || !s.Stored || s.UpdatedAt == nil || s.Version != "v2" || len(s.Builds) != 1 {
		t.Errorf("settings %+v", s)
	}
	if s.Fleet[devices.UpdateAvailable] != 2 || s.Fleet[devices.UpdateCurrent] != 1 || s.Fleet[devices.UpdateUnsupported] != 1 {
		t.Errorf("fleet %v", s.Fleet)
	}
	// Ask for every outdated agent: both go out one at a time.
	n, err := f.svc.RequestAll(f.ctx, f.sys)
	if err != nil || n != 2 {
		t.Fatalf("RequestAll = %d, %v", n, err)
	}
	if f.heartbeat(d1, oldSHA, nil) == nil || f.heartbeat(d2, oldSHA, nil) != nil {
		t.Error("the limit of one was not kept")
	}
	s, _ = f.svc.UpdateSettings(f.ctx, f.sys)
	if s.Fleet[devices.UpdateUpdating] != 1 || s.Fleet[devices.UpdateQueued] != 1 {
		t.Errorf("fleet %v", s.Fleet)
	}
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'agent_updates.request_all'`); n != 1 {
		t.Errorf("request_all audited %d times", n)
	}

	// The device list shows each agent's status.
	devs := devices.New(f.db, false)
	devs.SetBuilds(f.svc.BuildLookup)
	for d, want := range map[uuid.UUID]string{d1.ID: devices.UpdateUpdating, d2.ID: devices.UpdateQueued,
		d3.ID: devices.UpdateCurrent, old.ID: devices.UpdateUnsupported} {
		got, err := devs.Get(f.ctx, f.sys, d)
		if err != nil {
			t.Fatal(err)
		}
		if got.Agent.Update == nil || got.Agent.Update.Status != want || got.Agent.Update.Version != "v2" {
			t.Errorf("%s: %+v, want %s", d, got.Agent.Update, want)
		}
	}
	devs.SetBuilds(nil)
	if got, _ := devs.Get(f.ctx, f.sys, d1.ID); got.Agent.Update != nil {
		t.Error("an update status without builds")
	}

	// Who may do what.
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.org})
	viewer := f.user("ro@example.com", rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: f.org})
	f.exec(`INSERT INTO organizations (name) VALUES ('Other')`)
	stranger := f.user("x@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin,
		OrganizationID: f.uuid(`SELECT id FROM organizations WHERE name = 'Other'`)})
	if err := f.svc.RequestUpdate(f.ctx, tech, d2.ID); err != nil {
		t.Errorf("technician: %v", err)
	}
	if err := f.svc.RequestUpdate(f.ctx, viewer, d2.ID); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("read-only: %v", err)
	}
	if err := f.svc.RequestUpdate(f.ctx, stranger, d2.ID); !errors.Is(err, apperr.ErrNotFound) {
		t.Errorf("another organization: %v", err)
	}
	for name, c := range map[string]access.Caller{"technician": tech, "org admin": stranger} {
		if _, err := f.svc.UpdateSettings(f.ctx, c); !errors.Is(err, apperr.ErrForbidden) {
			t.Errorf("%s read the settings: %v", name, err)
		}
		if _, err := f.svc.SetUpdatePolicy(f.ctx, c, DefaultUpdatePolicy); !errors.Is(err, apperr.ErrForbidden) {
			t.Errorf("%s changed the settings: %v", name, err)
		}
		if _, err := f.svc.RequestAll(f.ctx, c); !errors.Is(err, apperr.ErrForbidden) {
			t.Errorf("%s asked for all: %v", name, err)
		}
	}
	// What cannot be updated.
	for d, code := range map[uuid.UUID]string{d3.ID: "agent_current", old.ID: "agent_too_old"} {
		var ae *apperr.Error
		if err := f.svc.RequestUpdate(f.ctx, f.sys, d); !errors.As(err, &ae) || ae.Code != code {
			t.Errorf("%s: %v, want %s", d, err, code)
		}
	}
	for _, p := range []UpdatePolicy{{Mode: "sometimes", MaxConcurrent: 1}, {Mode: UpdateManual}, {Mode: UpdateManual, MaxConcurrent: MaxConcurrentUpdates + 1}} {
		if _, err := f.svc.SetUpdatePolicy(f.ctx, f.sys, p); !errors.Is(err, apperr.ErrInvalid) {
			t.Errorf("%+v accepted: %v", p, err)
		}
	}
	// Without builds, nothing is offered; without the key, no download is
	// signed.
	f.svc.SetUpdates(nil, nil)
	if sig := f.svc.SignDownload(&SignedRequest{}, agentproto.PathMeshSettings, []byte("MeshID=0x1")); sig != "" {
		t.Errorf("signed without a key: %q", sig)
	}
	var ae *apperr.Error
	if err := f.svc.RequestUpdate(f.ctx, f.sys, d2.ID); !errors.As(err, &ae) || ae.Code != "no_build" {
		t.Errorf("no builds: %v", err)
	}
	if n, err := f.svc.RequestAll(f.ctx, f.sys); n != 0 || err != nil {
		t.Errorf("RequestAll without builds = %d, %v", n, err)
	}
	if p := f.heartbeat(d2, oldSHA, nil); p != nil {
		t.Error("an instruction without builds")
	}
}
