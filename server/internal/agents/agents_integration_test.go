//go:build integration

package agents

import (
	"bytes"
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/meshcentral"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

// fakeMesh stands in for MeshCentral.
type fakeMesh struct {
	groups   map[uuid.UUID]string
	groupErr error
	binErr   error
	setErr   error
	linked   int
	// bin is MeshAgent's binary ("ELF" when empty); length overrides the
	// length MeshCentral states; huge sends more than any MeshAgent is.
	bin     string
	length  int64
	huge    bool
	fetches int
	// host, when set, is the MeshServer host in the settings; settings counts
	// the settings fetched.
	host     string
	settings int
}

func (f *fakeMesh) Group(_ context.Context, site uuid.UUID) (string, error) {
	return f.groups[site], f.groupErr
}

func (f *fakeMesh) Binary(context.Context, int) (*meshcentral.Download, error) {
	f.fetches++
	if f.binErr != nil {
		return nil, f.binErr
	}
	if f.huge {
		return &meshcentral.Download{Body: io.NopCloser(io.LimitReader(zeros{}, agentproto.MaxMeshAgentBytes+1)), Length: -1}, nil
	}
	bin := cmp.Or(f.bin, "ELF")
	return &meshcentral.Download{Body: io.NopCloser(strings.NewReader(bin)), Length: cmp.Or(f.length, int64(len(bin)))}, nil
}

// zeros reads as an endless run of zero bytes.
type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func (f *fakeMesh) Settings(_ context.Context, mesh string) ([]byte, error) {
	f.settings++
	out := "MeshID=" + mesh
	if f.host != "" {
		out += "\nMeshServer=wss://" + f.host + "/agent.ashx\n"
	}
	return []byte(out), f.setErr
}

func (f *fakeMesh) Linked() { f.linked++ }

type fixture struct {
	t     *testing.T
	ctx   context.Context
	db    *database.DB
	svc   *Service
	mesh  *fakeMesh
	sys   access.Caller
	org   uuid.UUID
	hq    uuid.UUID
	other uuid.UUID
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	inst := testdb.New(t)
	f := &fixture{t: t, ctx: context.Background(), db: inst.DB, sys: access.System("test")}
	f.mesh = &fakeMesh{groups: map[uuid.UUID]string{}}
	f.svc = New(inst.DB, audit.New(inst.DB, nil), f.mesh, slog.New(slog.NewTextHandler(io.Discard, nil)))
	f.exec(`INSERT INTO organizations (name) VALUES ('Acme') RETURNING id`)
	f.org = f.uuid(`SELECT id FROM organizations WHERE name = 'Acme'`)
	f.hq = f.uuid(`INSERT INTO sites (organization_id, name) VALUES ($1, 'HQ') RETURNING id`, f.org)
	f.other = f.uuid(`INSERT INTO sites (organization_id, name) VALUES ($1, 'Branch') RETURNING id`, f.org)
	return f
}

func (f *fixture) exec(sql string, args ...any) {
	f.t.Helper()
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(f.ctx, sql, args...)
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) uuid(sql string, args ...any) uuid.UUID {
	f.t.Helper()
	var id uuid.UUID
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, sql, args...).Scan(&id)
	}); err != nil {
		f.t.Fatal(err)
	}
	return id
}

func (f *fixture) count(sql string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, sql, args...).Scan(&n)
	}); err != nil {
		f.t.Fatal(err)
	}
	return n
}

// enroll creates an enrolled device in site and returns it, authenticated.
func (f *fixture) enroll(site uuid.UUID, host string) (*Device, ed25519.PrivateKey) {
	f.t.Helper()
	tok, err := f.svc.CreateToken(f.ctx, f.sys, site, TokenInput{Name: "t", ExpiresInDays: 1})
	if err != nil {
		f.t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	resp, err := f.svc.Enroll(f.ctx, netip.MustParseAddr("192.0.2.10"), agentproto.EnrollRequest{
		Token: tok.Secret, PublicKey: base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)),
		Facts: agentproto.Facts{Hostname: host, Platform: "linux", Arch: "amd64", AgentVersion: "1"},
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return f.auth(resp.DeviceID, key), key
}

func (f *fixture) auth(device string, key ed25519.PrivateKey) *Device {
	f.t.Helper()
	body := []byte(`{}`)
	h, _ := agentproto.Sign(key, device, "POST", agentproto.PathHeartbeat, body, time.Now())
	d, err := f.svc.Authenticate(f.ctx, h, "POST", agentproto.PathHeartbeat, body)
	if err != nil {
		f.t.Fatal(err)
	}
	return d
}

// nodeHex returns a random MeshAgent node id as -nodeid prints it.
func nodeHex() string {
	b := make([]byte, 48)
	_, _ = rand.Read(b)
	return strings.ToUpper(hex.EncodeToString(b))
}

func (f *fixture) beat(d *Device, host, node string) {
	f.t.Helper()
	if _, err := f.svc.Heartbeat(f.ctx, d, netip.MustParseAddr("192.0.2.10"), agentproto.HeartbeatRequest{Facts: agentproto.Facts{
		Hostname: host, Platform: "linux", Arch: "amd64", AgentVersion: "1", MeshNodeID: node,
	}}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) nodeOf(id uuid.UUID) string {
	f.t.Helper()
	var n *string
	_ = f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT mesh_node_id FROM devices WHERE id = $1`, id).Scan(&n)
	})
	if n == nil {
		return ""
	}
	return *n
}

func TestMeshAgentLinking(t *testing.T) {
	f := newFixture(t)
	dev, key := f.enroll(f.hq, "web-01")

	// A node MeshCentral has not reported yet is linked provisionally.
	first := nodeHex()
	firstKey, _ := agentproto.MeshNodeKey(first)
	f.beat(dev, "web-01", first)
	if f.nodeOf(dev.ID) != firstKey || f.mesh.linked != 1 {
		t.Fatalf("provisional link: %q, linked %d", f.nodeOf(dev.ID), f.mesh.linked)
	}

	// MeshCentral discovered the node in this site first: the discovered
	// device and its session grants merge into the enrolled one.
	second := nodeHex()
	secondKey, _ := agentproto.MeshNodeKey(second)
	discovered := f.uuid(`INSERT INTO devices (organization_id, site_id, name, mesh_node_id, mesh_agent_type, remote_online, last_seen_at)
		VALUES ($1, $2, 'web-01 (mesh)', $3, 6, true, now()) RETURNING id`, f.org, f.hq, secondKey)
	user := f.uuid(`INSERT INTO users (email, display_name) VALUES ('u@x.example', 'U') RETURNING id`)
	sess := f.uuid(`INSERT INTO sessions (token_hash, user_id, state, idle_expires_at, expires_at)
		VALUES ($1, $2, 'active', now() + interval '1 hour', now() + interval '1 hour') RETURNING id`, bytes.Repeat([]byte{7}, 32), user)
	f.exec(`INSERT INTO remote_grants (launch_hash, session_id, user_id, device_id, organization_id, site_id, kind, launch_expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, 'desktop', now() + interval '1 minute')`, bytes.Repeat([]byte{9}, 32), sess, user, discovered, f.org, f.hq)
	dev = f.auth(dev.ID.String(), key)
	f.beat(dev, "web-01", second)
	if f.nodeOf(dev.ID) != secondKey || f.count(`SELECT count(*) FROM devices WHERE id = $1`, discovered) != 0 {
		t.Fatal("discovered device not merged")
	}
	if f.count(`SELECT count(*) FROM devices WHERE id = $1 AND remote_online AND mesh_agent_type = 6`, dev.ID) != 1 {
		t.Error("connection state not taken over from the discovered device")
	}
	if f.count(`SELECT count(*) FROM remote_grants WHERE device_id = $1`, dev.ID) != 1 {
		t.Error("session grant not moved to the enrolled device")
	}
	if f.count(`SELECT count(*) FROM audit_log WHERE action = 'device.remote_link' AND details->>'mergedDeviceId' = $1`, discovered.String()) != 1 {
		t.Error("merge not audited")
	}

	// The same report again changes nothing.
	dev = f.auth(dev.ID.String(), key)
	f.beat(dev, "web-01", second)
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'device.remote_link'`); n != 1 {
		t.Errorf("link audit records = %d", n)
	}

	// The machine enrolled again: the new enrollment takes the node over.
	again, _ := f.enroll(f.hq, "web-01")
	f.beat(again, "web-01", second)
	if f.nodeOf(again.ID) != secondKey || f.nodeOf(dev.ID) != "" {
		t.Errorf("re-enrolled machine: new %q, old %q", f.nodeOf(again.ID), f.nodeOf(dev.ID))
	}

	// A node known in another site is never claimed.
	foreign := nodeHex()
	foreignKey, _ := agentproto.MeshNodeKey(foreign)
	victim := f.uuid(`INSERT INTO devices (organization_id, site_id, name, mesh_node_id, remote_online)
		VALUES ($1, $2, 'branch-pc', $3, true) RETURNING id`, f.org, f.other, foreignKey)
	f.beat(again, "web-01", foreign)
	if f.nodeOf(victim) != foreignKey || f.nodeOf(again.ID) != secondKey {
		t.Errorf("cross-site claim: victim %q, claimant %q", f.nodeOf(victim), f.nodeOf(again.ID))
	}

	// A malformed node id is refused.
	_, err := f.svc.Heartbeat(f.ctx, again, netip.Addr{}, agentproto.HeartbeatRequest{Facts: agentproto.Facts{Hostname: "x", MeshNodeID: "zz"}})
	if err == nil {
		t.Error("malformed node id accepted")
	}
}

func TestHeartbeatRenamesOnlyUnrenamedDevices(t *testing.T) {
	f := newFixture(t)
	dev, _ := f.enroll(f.hq, "pc-1")
	f.exec(`UPDATE devices SET name = 'Reception PC' WHERE id = $1`, dev.ID)
	f.beat(dev, "pc-1-renamed", "")
	if f.count(`SELECT count(*) FROM devices WHERE id = $1 AND name = 'Reception PC' AND hostname = 'pc-1-renamed'`, dev.ID) != 1 {
		t.Error("a chosen name was overwritten by the hostname")
	}
	// Heartbeats are not edits.
	var before, after time.Time
	_ = f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT updated_at FROM devices WHERE id = $1`, dev.ID).Scan(&before)
	})
	f.beat(dev, "pc-1-renamed", "")
	_ = f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT updated_at FROM devices WHERE id = $1`, dev.ID).Scan(&after)
	})
	if !after.Equal(before) {
		t.Error("a heartbeat with unchanged facts moved updated_at")
	}
	// A removed device's agent is told so.
	f.exec(`DELETE FROM devices WHERE id = $1`, dev.ID)
	if _, err := f.svc.Heartbeat(f.ctx, dev, netip.Addr{}, agentproto.HeartbeatRequest{Facts: agentproto.Facts{Hostname: "x"}}); !errors.Is(err, ErrUnknownDevice) {
		t.Errorf("heartbeat of a removed device: %v", err)
	}
}

func TestNonceCleanup(t *testing.T) {
	f := newFixture(t)
	dev, _ := f.enroll(f.hq, "pc")
	f.exec(`INSERT INTO agent_nonces (device_id, nonce, expires_at) VALUES ($1, 'AAAAAAAAAAAAAAAAAAAAAAAA', now() - interval '1 second')`, dev.ID)
	if f.count(`SELECT count(*) FROM agent_nonces`) != 2 {
		t.Fatal("expected the authentication nonce and the expired one")
	}
	if err := f.svc.PruneNonces(f.ctx); err != nil {
		t.Fatal(err)
	}
	if f.count(`SELECT count(*) FROM agent_nonces`) != 1 {
		t.Error("expired nonce kept or live nonce removed")
	}
	// The hourly cleanup removes them too.
	f.exec(`INSERT INTO agent_nonces (device_id, nonce, expires_at) VALUES ($1, 'BBBBBBBBBBBBBBBBBBBBBBBB', now() - interval '1 second')`, dev.ID)
	if err := f.svc.Cleanup(f.ctx); err != nil {
		t.Fatal(err)
	}
	if f.count(`SELECT count(*) FROM agent_nonces`) != 1 {
		t.Error("expired nonce kept or live nonce removed by the hourly cleanup")
	}
	// Run returns when its context ends.
	ctx, cancel := context.WithCancel(f.ctx)
	cancel()
	f.svc.Run(ctx)
}

func TestMeshAgentDelivery(t *testing.T) {
	f := newFixture(t)
	dev, _ := f.enroll(f.hq, "pc")

	if _, err := f.svc.MeshAgentSettings(f.ctx, dev); !errors.Is(err, ErrMeshUnavailable) {
		t.Errorf("settings before the site has a group: %v", err)
	}
	f.mesh.groups[f.hq] = "mesh//group"
	b, err := f.svc.MeshAgentSettings(f.ctx, dev)
	if err != nil || string(b) != "MeshID=mesh//group" {
		t.Errorf("settings = %q, %v", b, err)
	}
	// The server keeps each platform's MeshAgent for MeshAgentCacheFor, so
	// that it can sign it whole and a fleet installing at once costs
	// MeshCentral one download.
	clock := time.Now()
	f.svc.now = func() time.Time { return clock }
	bin, err := f.svc.MeshAgentBinary(f.ctx, "linux", "amd64")
	if err != nil || string(bin) != "ELF" || f.mesh.fetches != 1 {
		t.Fatalf("binary = %q, %v, %d fetches", bin, err, f.mesh.fetches)
	}
	f.mesh.bin = "ELF2"
	if bin, err := f.svc.MeshAgentBinary(f.ctx, "linux", "amd64"); err != nil || string(bin) != "ELF" || f.mesh.fetches != 1 {
		t.Errorf("kept binary = %q, %v, %d fetches", bin, err, f.mesh.fetches)
	}
	if bin, err := f.svc.MeshAgentBinary(f.ctx, "linux", "arm64"); err != nil || string(bin) != "ELF2" || f.mesh.fetches != 2 {
		t.Errorf("another platform's binary = %q, %v, %d fetches", bin, err, f.mesh.fetches)
	}
	clock = clock.Add(MeshAgentCacheFor)
	if bin, err := f.svc.MeshAgentBinary(f.ctx, "linux", "amd64"); err != nil || string(bin) != "ELF2" || f.mesh.fetches != 3 {
		t.Errorf("binary after the cache's time = %q, %v, %d fetches", bin, err, f.mesh.fetches)
	}
	if _, err := f.svc.MeshAgentBinary(f.ctx, "plan9", "amd64"); err == nil {
		t.Error("binary for an unknown platform")
	}
	for name, prepare := range map[string]func(){
		"missing binary":         func() { f.mesh.binErr = meshcentral.ErrNoFile },
		"MeshCentral down":       func() { f.mesh.binErr = errors.New("down") },
		"a download cut short":   func() { f.mesh.length = 10 },
		"a binary far too large": func() { f.mesh.huge = true },
	} {
		clock = clock.Add(MeshAgentCacheFor)
		f.mesh.binErr, f.mesh.length, f.mesh.huge = nil, 0, false
		prepare()
		if _, err := f.svc.MeshAgentBinary(f.ctx, "linux", "amd64"); !errors.Is(err, ErrMeshUnavailable) {
			t.Errorf("%s: %v", name, err)
		}
	}
	f.mesh.binErr, f.mesh.setErr = errors.New("down"), errors.New("down")
	if _, err := f.svc.MeshAgentSettings(f.ctx, dev); !errors.Is(err, ErrMeshUnavailable) {
		t.Errorf("MeshCentral down (settings): %v", err)
	}
	f.mesh.groupErr = errors.New("db down")
	if _, err := f.svc.MeshAgentSettings(f.ctx, dev); err == nil {
		t.Error("group lookup failure hidden")
	}
	// A heartbeat still succeeds; MeshAgent is just not offered.
	f.mesh.groupErr = errors.New("db down")
	resp, err := f.svc.Heartbeat(f.ctx, dev, netip.Addr{}, agentproto.HeartbeatRequest{Facts: agentproto.Facts{Hostname: "pc"}})
	if err != nil || resp.MeshAgent.Available {
		t.Errorf("heartbeat while the group lookup fails: %+v, %v", resp, err)
	}

	// Without remote access nothing is offered.
	none := New(f.db, audit.New(f.db, nil), nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if _, err := none.MeshAgentBinary(f.ctx, "linux", "amd64"); !errors.Is(err, ErrMeshUnavailable) {
		t.Error(err)
	}
	if _, err := none.MeshAgentSettings(f.ctx, dev); !errors.Is(err, ErrMeshUnavailable) {
		t.Error(err)
	}
}

func TestEnrollmentLimits(t *testing.T) {
	f := newFixture(t)
	ip := netip.MustParseAddr("198.51.100.7")
	var limited bool
	for range 200 {
		_, err := f.svc.Enroll(f.ctx, ip, agentproto.EnrollRequest{Token: "nope"})
		if errors.Is(err, ErrRateLimited) {
			limited = true
			break
		}
		if !errors.Is(err, ErrTokenInvalid) {
			t.Fatalf("unexpected: %v", err)
		}
	}
	if !limited {
		t.Error("enrollment from one address is not rate limited")
	}
	if _, err := f.svc.Enroll(f.ctx, netip.MustParseAddr("198.51.100.8"), agentproto.EnrollRequest{Token: agentproto.TokenPrefix + "x", PublicKey: "!"}); err == nil {
		t.Error("bad public key accepted")
	}
}

// A device moved to another site (ADR-0069): its node, still in the old
// site's group, is accepted while the move is pending, and the heartbeat
// carries the new site's settings until the agent reports applying them.
func TestMovedDeviceHeartbeat(t *testing.T) {
	f := newFixture(t)
	f.mesh.groups[f.hq], f.mesh.groups[f.other] = "mesh//hq", "mesh//branch"
	dev, _ := f.enroll(f.hq, "web-01")
	node := nodeHex()
	nodeKey, _ := agentproto.MeshNodeKey(node)
	// MeshCentral lists the node in HQ's group, as a discovered device.
	f.exec(`INSERT INTO devices (organization_id, site_id, name, mesh_node_id) VALUES ($1, $2, 'web-01 (mesh)', $3)`, f.org, f.hq, nodeKey)
	f.exec(`UPDATE devices SET site_id = $2, mesh_from_site_id = $3, mesh_settings_pending = true WHERE id = $1`, dev.ID, f.other, f.hq)
	dev.SiteID = f.other

	beat := func(applied string) *agentproto.HeartbeatResponse {
		t.Helper()
		resp, err := f.svc.Heartbeat(f.ctx, dev, netip.MustParseAddr("192.0.2.10"), agentproto.HeartbeatRequest{Facts: agentproto.Facts{
			Hostname: "web-01", Platform: "linux", Arch: "amd64", AgentVersion: "1", MeshNodeID: node, MeshSettingsSHA256: applied,
		}})
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	sum := sha256.Sum256([]byte("MeshID=mesh//branch"))
	want := hex.EncodeToString(sum[:])

	// The node of the old site is the device's: it is linked, and the new
	// site's settings are announced.
	if resp := beat(""); resp.MeshAgent.SettingsSHA256 != want {
		t.Fatalf("announced %q, want %q", resp.MeshAgent.SettingsSHA256, want)
	}
	if f.nodeOf(dev.ID) != nodeKey {
		t.Fatalf("a pending move's node was refused: %q", f.nodeOf(dev.ID))
	}
	// Announced until the agent reports what it applied; then the instruction ends.
	if resp := beat("old"); resp.MeshAgent.SettingsSHA256 != want {
		t.Errorf("announced after another hash: %q", resp.MeshAgent.SettingsSHA256)
	}
	if resp := beat(want); resp.MeshAgent.SettingsSHA256 != "" {
		t.Errorf("announced after it was applied: %q", resp.MeshAgent.SettingsSHA256)
	}
	if f.count(`SELECT count(*) FROM devices WHERE id = $1 AND NOT mesh_settings_pending`, dev.ID) != 1 {
		t.Error("the pending flag stayed")
	}
	if resp := beat(""); resp.MeshAgent.SettingsSHA256 != "" {
		t.Errorf("announced with nothing pending: %q", resp.MeshAgent.SettingsSHA256)
	}
}

// Without a pending move, a node known in another site is never claimed
// (the exception above is for the site a device came from only).
func TestMovedDeviceDoesNotClaimOtherNodes(t *testing.T) {
	f := newFixture(t)
	dev, _ := f.enroll(f.hq, "web-01")
	third := f.uuid(`INSERT INTO sites (organization_id, name) VALUES ($1, 'Third') RETURNING id`, f.org)
	foreign := nodeHex()
	foreignKey, _ := agentproto.MeshNodeKey(foreign)
	victim := f.uuid(`INSERT INTO devices (organization_id, site_id, name, mesh_node_id) VALUES ($1, $2, 'third-pc', $3) RETURNING id`, f.org, third, foreignKey)
	f.exec(`UPDATE devices SET site_id = $2, mesh_from_site_id = $3 WHERE id = $1`, dev.ID, f.other, f.hq)
	dev.SiteID = f.other
	f.beat(dev, "web-01", foreign)
	if f.nodeOf(victim) != foreignKey || f.nodeOf(dev.ID) != "" {
		t.Errorf("a node of another site was claimed: victim %q, claimant %q", f.nodeOf(victim), f.nodeOf(dev.ID))
	}
}
