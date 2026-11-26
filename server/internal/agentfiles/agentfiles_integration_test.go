//go:build integration

package agentfiles

import (
	"bytes"
	"context"
	"crypto/md5" //nolint:gosec // the test checks the list's MD5
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/agents"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/easypatch"
	"github.com/paulmataruso/easyrmm/server/internal/meshcentral"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

func sums(b string) (md, sh string) {
	m, s := md5.Sum([]byte(b)), sha256.Sum256([]byte(b)) //nolint:gosec // see the import
	return hex.EncodeToString(m[:]), hex.EncodeToString(s[:])
}

type fakeMesh struct {
	body string
	err  error
}

func (f *fakeMesh) Binary(context.Context, int) (*meshcentral.Download, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &meshcentral.Download{Body: io.NopCloser(strings.NewReader(f.body)), Length: int64(len(f.body))}, nil
}

type fakePatch struct {
	pkgs   []easypatch.AgentPackage
	body   string
	opened int
	err    error
}

func (f *fakePatch) PackageList(context.Context) ([]easypatch.AgentPackage, error) {
	return f.pkgs, f.err
}
func (f *fakePatch) OpenPackage(context.Context, easypatch.AgentPackage) (io.ReadCloser, error) {
	f.opened++
	return io.NopCloser(bytes.NewReader([]byte(f.body))), nil
}

type fixture struct {
	t     *testing.T
	ctx   context.Context
	db    *database.DB
	svc   *Service
	mesh  *fakeMesh
	patch *fakePatch
	org   uuid.UUID
	site  uuid.UUID
	build agents.Build
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	inst := testdb.New(t)
	dir := t.TempDir()
	for name, body := range map[string]string{"easyrmm-agent-windows-amd64.exe": "agent v7", "easyrmm-agent-linux-amd64": "linux agent"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, agents.VersionFile), []byte("v7\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	builds, err := agents.LoadBuilds(dir)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, ctx: context.Background(), db: inst.DB, mesh: &fakeMesh{body: "mesh build"}, patch: &fakePatch{body: "msi bytes"}}
	f.svc = New(inst.DB, slog.New(slog.NewTextHandler(io.Discard, nil)), builds, f.mesh, f.patch)
	f.build, _ = builds.For("windows", "amd64")
	f.org = f.id(`INSERT INTO organizations (name) VALUES ('Acme') RETURNING id`)
	f.site = f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'HQ') RETURNING id`, f.org)
	return f
}

func (f *fixture) id(sql string, args ...any) uuid.UUID {
	f.t.Helper()
	var id uuid.UUID
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error { return tx.QueryRow(f.ctx, sql, args...).Scan(&id) }); err != nil {
		f.t.Fatal(err)
	}
	return id
}

func (f *fixture) user(email string, as ...rbac.Assignment) access.Caller {
	f.t.Helper()
	id := f.id(`INSERT INTO users (email, display_name) VALUES ($1, $1) RETURNING id`, email)
	p, err := rbac.NewPrincipal(id, as)
	if err != nil {
		f.t.Fatal(err)
	}
	return access.User(p, auth.DataScope(p), audit.Actor{Type: audit.ActorUser, ID: id, Label: email})
}

func (f *fixture) entries() map[string]Entry {
	f.t.Helper()
	list, err := f.svc.entries(f.ctx)
	if err != nil {
		f.t.Fatal(err)
	}
	out := map[string]Entry{}
	for _, e := range list {
		out[e.Source+"/"+e.Name] = e
	}
	return out
}

func TestRefreshListsEverythingWithBothHashes(t *testing.T) {
	f := newFixture(t)
	f.patch.pkgs = []easypatch.AgentPackage{{FileName: "EasyPatch-1.2.msi", Version: "1.2", Architecture: "x64", Format: "msi", SHA256: strings.ToUpper(mustSHA("msi bytes")), DownloadURL: "/downloads/agent/EasyPatch-1.2.msi"}}
	if err := f.svc.Refresh(f.ctx); err != nil {
		t.Fatal(err)
	}
	got := f.entries()
	md, sh := sums("agent v7")
	if e := got["server/easyrmm-agent-windows-amd64.exe"]; e.MD5 != md || e.SHA256 != sh || e.Version != "v7" || e.Size != 8 || e.Platform != "windows" {
		t.Fatalf("server entry = %+v", e)
	}
	md, sh = sums("mesh build")
	if e := got["meshcentral/meshagent-windows-amd64.exe"]; e.MD5 != md || e.SHA256 != sh || e.Stale {
		t.Fatalf("mesh entry = %+v", e)
	}
	md, sh = sums("msi bytes")
	if e := got["patching/EasyPatch-1.2.msi"]; e.MD5 != md || e.SHA256 != sh || e.Platform != "windows" {
		t.Fatalf("patching entry = %+v", e)
	}
	// A package already hashed is not fetched again.
	f.patch.opened = 0
	if err := f.svc.Refresh(f.ctx); err != nil || f.patch.opened != 0 {
		t.Fatalf("refetched %d times, err %v", f.patch.opened, err)
	}
}

func mustSHA(s string) string { _, sh := sums(s); return sh }

func TestUnreadableSourceKeepsItsValuesMarkedStale(t *testing.T) {
	f := newFixture(t)
	f.patch.pkgs = []easypatch.AgentPackage{{FileName: "p.msi", Version: "1", Architecture: "x64", Format: "msi", SHA256: mustSHA("msi bytes"), DownloadURL: "/downloads/agent/p.msi"}}
	if err := f.svc.Refresh(f.ctx); err != nil {
		t.Fatal(err)
	}
	f.mesh.err = errors.New("MeshCentral is down")
	f.patch.err = errors.New("engine is down")
	if err := f.svc.Refresh(f.ctx); err == nil {
		t.Fatal("no error was reported")
	}
	got := f.entries()
	for _, k := range []string{"meshcentral/meshagent-windows-amd64.exe", "patching/p.msi"} {
		if e, ok := got[k]; !ok || !e.Stale || e.StaleReason == "" || e.SHA256 == "" {
			t.Fatalf("%s = %+v (%v)", k, e, ok)
		}
	}
	if e := got["server/easyrmm-agent-windows-amd64.exe"]; e.Stale {
		t.Fatal("the server's own builds are never stale")
	}
	// It recovers.
	f.mesh.err, f.patch.err = nil, nil
	if err := f.svc.Refresh(f.ctx); err != nil {
		t.Fatal(err)
	}
	if e := f.entries()["meshcentral/meshagent-windows-amd64.exe"]; e.Stale {
		t.Fatal("still stale after it was read again")
	}
}

func TestAPackageThatIsNotWhatTheEngineListsIsNotTrusted(t *testing.T) {
	f := newFixture(t)
	f.patch.pkgs = []easypatch.AgentPackage{{FileName: "p.msi", Version: "1", Architecture: "x64", Format: "msi", SHA256: mustSHA("something else"), DownloadURL: "/downloads/agent/p.msi"}}
	if err := f.svc.Refresh(f.ctx); err == nil {
		t.Fatal("a package whose SHA-256 differs from the engine's was listed")
	}
	if _, ok := f.entries()["patching/p.msi"]; ok {
		t.Fatal("it was listed")
	}
}

func TestListNeedsOrgViewAndRefreshNeedsSettingsManage(t *testing.T) {
	f := newFixture(t)
	if err := f.svc.Refresh(f.ctx); err != nil {
		t.Fatal(err)
	}
	nobody := f.user("nobody@example.test")
	if _, err := f.svc.List(f.ctx, nobody); err == nil {
		t.Fatal("a user with no role read the list")
	}
	ro := f.user("ro@example.test", rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: f.org})
	list, err := f.svc.List(f.ctx, ro)
	if err != nil || len(list) == 0 {
		t.Fatalf("read-only: %d %v", len(list), err)
	}
	if _, err := f.svc.RefreshNow(f.ctx, ro); err == nil {
		t.Fatal("read-only refreshed the list")
	}
	super := f.user("su@example.test", rbac.Assignment{Role: rbac.RoleSuperAdmin})
	if _, err := f.svc.RefreshNow(f.ctx, super); err != nil {
		t.Fatalf("super admin: %v", err)
	}
}

func (f *fixture) device(site uuid.UUID, arch string, defender, installed string) uuid.UUID {
	f.t.Helper()
	return f.id(`INSERT INTO devices (organization_id, site_id, name, hostname, platform, agent_arch, agent_public_key, enrolled_at, defender, defender_at, installed_files, installed_files_at)
		VALUES ($1, $2, 'w', 'w', 'windows', $3, sha256(gen_random_uuid()::text::bytea), now(), $4::jsonb, now(), $5::jsonb, now()) RETURNING id`, f.org, site, arch, defender, installed)
}

func TestDeviceViewComparesReportedHashesWithTheList(t *testing.T) {
	f := newFixture(t)
	if err := f.svc.Refresh(f.ctx); err != nil {
		t.Fatal(err)
	}
	_, agentSha := sums("agent v7")
	_, meshSha := sums("mesh build")
	_, other := sums("tampered")
	md := "d41d8cd98f00b204e9800998ecf8427e"
	files := func(agentHash, meshHash string) string {
		return `{"agentVersion":"v7","files":[
			{"program":"easyrmm-agent","name":"easyrmm-agent.exe","size":8,"md5":"` + md + `","sha256":"` + agentHash + `"},
			{"program":"meshagent","name":"meshagent.exe","size":1,"md5":"` + md + `","sha256":"` + meshHash + `"},
			{"program":"easypatch-agent","name":"EasyPatch.Agent.exe","size":1,"md5":"` + md + `","sha256":"` + other + `"}]}`
	}
	def := `{"state":"effective","kinds":[{"kind":"path","state":"effective"}],"folders":[{"path":"C:\\x","listed":true,"ours":true}]}`
	good := f.device(f.site, "amd64", def, files(agentSha, meshSha))
	bad := f.device(f.site, "amd64", def, files(other, other))
	old := f.device(f.site, "amd64", def, strings.Replace(files(agentSha, meshSha), `"v7"`, `"v1"`, 1))
	viewer := f.user("v@example.test", rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: f.org})

	status := func(id uuid.UUID) map[string]string {
		v, err := f.svc.ForDevice(f.ctx, viewer, id)
		if err != nil {
			t.Fatal(err)
		}
		if v.Defender == nil || v.Defender.State != "effective" || v.Installed == nil || v.Installed.Source != "reported by the device" {
			t.Fatalf("view = %+v", v)
		}
		out := map[string]string{}
		for _, x := range v.Installed.Files {
			out[x.Program] = x.Status
		}
		return out
	}
	if s := status(good); s["easyrmm-agent"] != StatusMatch || s["meshagent"] != StatusMatch || s["easypatch-agent"] != StatusNoExpected {
		t.Fatalf("good = %v", s)
	}
	if s := status(bad); s["easyrmm-agent"] != StatusMismatch || s["meshagent"] != StatusNotCurrent {
		t.Fatalf("bad = %v (MeshAgent updates itself: not a mismatch)", s)
	}
	if s := status(old); s["easyrmm-agent"] != StatusNoExpected {
		t.Fatalf("a version the list lacks = %v", s)
	}
	// Someone without device.view on it learns nothing.
	if _, err := f.svc.ForDevice(f.ctx, f.user("x@example.test"), good); err == nil {
		t.Fatal("a user with no access saw the device")
	}
	if _, err := f.svc.ForDevice(f.ctx, viewer, uuid.New()); err == nil {
		t.Fatal("a device that does not exist")
	}
}

func TestAVersionTheListLacksIsLookedUpOncePerWhile(t *testing.T) {
	f := newFixture(t)
	if err := f.svc.Refresh(f.ctx); err != nil {
		t.Fatal(err)
	}
	f.svc.VersionReported("v7") // known: nothing to do
	before := f.entries()["server/easyrmm-agent-windows-amd64.exe"].ComputedAt
	f.svc.VersionReported("v9") // unknown: the list is computed again
	after := f.entries()["server/easyrmm-agent-windows-amd64.exe"].ComputedAt
	if !after.After(before) {
		t.Fatal("an unknown version did not recompute the list")
	}
	f.svc.VersionReported("v9")
	if again := f.entries()["server/easyrmm-agent-windows-amd64.exe"].ComputedAt; !again.Equal(after) {
		t.Fatal("the same unknown version recomputed the list twice within ten minutes")
	}
}
