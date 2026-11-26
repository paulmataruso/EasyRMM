//go:build integration

package agents

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
)

// stableBuilds loads a stable set whose Linux amd64 build is the one the
// test devices run (oldSHA).
// ancientSHA is a build older than both sets.
var ancientSHA = sum("ancient build")

func (f *updates) stableBuilds() *Builds {
	f.t.Helper()
	dir := f.t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "easyrmm-agent-linux-amd64"), []byte("old build"), 0o644); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, VersionFile), []byte("v1\n"), 0o644); err != nil {
		f.t.Fatal(err)
	}
	b, err := LoadBuilds(dir)
	if err != nil {
		f.t.Fatal(err)
	}
	return b
}

// TestDevScopeOffers has two organizations, one in the dev scope and one
// outside it. The server's build is new; the stable one is what the devices
// run now.
func TestDevScopeOffers(t *testing.T) {
	f := newUpdates(t, "new build", "v2")
	if _, err := f.svc.SetUpdatePolicy(f.ctx, f.sys, UpdatePolicy{Mode: UpdateAutomatic, MaxConcurrent: 10}); err != nil {
		t.Fatal(err)
	}
	outOrg := f.uuid(`INSERT INTO organizations (name) VALUES ('Outside') RETURNING id`)
	outSite := f.uuid(`INSERT INTO sites (organization_id, name) VALUES ($1, 'HQ') RETURNING id`, outOrg)
	in, _ := f.enroll(f.hq, "pc-in")
	out, _ := f.enroll(outSite, "pc-out")
	in2, _ := f.enroll(f.hq, "pc-in2")
	out2, _ := f.enroll(outSite, "pc-out2")
	newSHA, stableSHA := sum("new build"), sum("old build")

	// No scope: as before, every device is offered the server's build.
	if p := f.heartbeat(out, ancientSHA, nil); p == nil || p.SHA256 != newSHA {
		t.Fatalf("no scope: out-of-scope device offered %+v, want the new build", p)
	}
	if lb, ok := f.svc.BuildLookup(outOrg, "linux", "amd64"); !ok || lb.SHA256 != newSHA {
		t.Errorf("no scope: BuildLookup = %+v", lb)
	}
	if h := f.svc.ReleaseHashes(outOrg, "linux", "amd64"); len(h) != 1 || h[0] != newSHA {
		t.Errorf("no scope: ReleaseHashes = %v", h)
	}
	f.exec(`DELETE FROM agent_updates`)

	f.svc.SetStable(f.stableBuilds())
	if f.svc.BuildsFor(outOrg) != f.svc.builds {
		t.Fatal("with no scope, stable builds must stay unused")
	}
	t.Cleanup(devscope.Set(f.org))

	// The device outside the scope is offered the stable build and its hash;
	// the one inside gets the new build.
	if p := f.heartbeat(out, ancientSHA, nil); p == nil || p.SHA256 != stableSHA || p.Version != "v1" {
		t.Fatalf("out-of-scope device offered %+v, want the stable build", p)
	}
	if p := f.heartbeat(in, ancientSHA, nil); p == nil || p.SHA256 != newSHA || p.Version != "v2" {
		t.Fatalf("in-scope device offered %+v, want the new build", p)
	}
	// A device outside the scope on the stable build has nothing to update;
	// one inside the scope on it is offered the new build.
	if p := f.heartbeat(out2, oldSHA, nil); p != nil {
		t.Errorf("out-of-scope device on the stable build was offered %+v", p)
	}
	if p := f.heartbeat(in2, oldSHA, nil); p == nil || p.SHA256 != newSHA {
		t.Errorf("in-scope device on the stable build was offered %+v", p)
	}
	if n := f.count(`SELECT count(*) FROM agent_updates WHERE device_id = $1`, out2.ID); n != 0 {
		t.Errorf("an update was recorded for the device that needs none")
	}

	// What devices see, and what recovery accepts, follows the organization.
	if lb, _ := f.svc.BuildLookup(outOrg, "linux", "amd64"); lb.SHA256 != stableSHA {
		t.Errorf("BuildLookup outside = %+v", lb)
	}
	if lb, _ := f.svc.BuildLookup(f.org, "linux", "amd64"); lb.SHA256 != newSHA {
		t.Errorf("BuildLookup inside = %+v", lb)
	}
	if lb, _ := f.svc.BuildLookup(uuid.Nil, "linux", "amd64"); lb.SHA256 != stableSHA {
		t.Errorf("BuildLookup for no organization = %+v", lb)
	}
	if h := f.svc.ReleaseHashes(outOrg, "linux", "amd64"); len(h) != 1 || h[0] != stableSHA {
		t.Errorf("ReleaseHashes outside = %v", h)
	}
	if h := f.svc.ReleaseHashes(f.org, "linux", "amd64"); len(h) != 1 || h[0] != newSHA {
		t.Errorf("ReleaseHashes inside = %v", h)
	}

	// An administrator's request for the outside device still works, and
	// asks for the stable build, never the new one. "Update all" does the
	// same for each organization.
	f.exec(`DELETE FROM agent_updates`)
	f.exec(`UPDATE devices SET agent_sha256 = $2 WHERE id = ANY ($1)`, []uuid.UUID{in.ID, out.ID, in2.ID, out2.ID}, ancientSHA)
	if err := f.svc.RequestUpdate(f.ctx, f.sys, out.ID); err != nil {
		t.Fatal(err)
	}
	target := func(d *Device) string {
		var sha string
		if f.count(`SELECT count(*) FROM agent_updates WHERE device_id = $1`, d.ID) == 0 {
			return ""
		}
		_ = f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
			return tx.QueryRow(f.ctx, `SELECT target_sha256 FROM agent_updates WHERE device_id = $1`, d.ID).Scan(&sha)
		})
		return sha
	}
	if got := target(out); got != stableSHA {
		t.Errorf("manual request outside the scope targets %q, want the stable build", got)
	}
	f.exec(`DELETE FROM agent_updates`)
	if _, err := f.svc.RequestAll(f.ctx, f.sys); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		d    *Device
		want string
	}{{in, newSHA}, {in2, newSHA}, {out, stableSHA}, {out2, stableSHA}} {
		if got := target(c.d); got != c.want {
			t.Errorf("update all: %s targets %q, want %q", c.d.ID, got, c.want)
		}
	}

	// Without stable builds loaded, nothing is offered outside the scope.
	f.exec(`DELETE FROM agent_updates`)
	f.svc.SetStable(nil)
	if p := f.heartbeat(out, ancientSHA, nil); p != nil {
		t.Errorf("no stable builds, offered %+v", p)
	}
	if p := f.heartbeat(in, ancientSHA, nil); p == nil || p.SHA256 != newSHA {
		t.Errorf("in-scope device without stable builds loaded: %+v", p)
	}
}

// Signed Windows builds made from a release under test never join the stable
// set, which takes the ones made from its own release.
func TestDevScopeSignedBuildsStayWithTheirRelease(t *testing.T) {
	f := newUpdates(t, "new build", "v2")
	fresh := f.windowsBuilds("v2", append(testProgram(t, "tiny.exe"), []byte("new")...))
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "easyrmm-agent-windows-amd64.exe"), []byte("stable windows"), 0o644); err != nil {
		t.Fatal(err)
	}
	stable, err := LoadBuilds(dir)
	if err != nil {
		t.Fatal(err)
	}
	f.svc.SetStable(stable)
	outOrg := f.uuid(`INSERT INTO organizations (name) VALUES ('Outside') RETURNING id`)
	t.Cleanup(devscope.Set(f.org))

	newRel, _ := fresh.For("windows", "amd64")
	oldRel, _ := stable.For("windows", "amd64")
	insert := func(version, sha, release string) {
		f.exec(`INSERT INTO signed_agent_builds (id, arch, version, sha256, release_sha256, content, signer_subject, signer_issuer,
				thumbprint, not_before, not_after, timestamped)
			VALUES ($1, 'amd64', $2, $3, $4, $5, 's', 'i', $6, now(), now(), false)`,
			uuid.New(), version, sum(sha), release, []byte(sha), strings.Repeat("0", 40))
	}
	insert("v2", "signed new", newRel.SHA256)
	if _, err := f.svc.SetUpdatePolicy(f.ctx, f.sys, UpdatePolicy{Mode: UpdateAutomatic, MaxConcurrent: 5, SignedOnly: true}); err != nil {
		t.Fatal(err)
	}
	// Signed only, and nothing signed from the stable release: the stable
	// build is withheld, and the signed build of the release under test is
	// not offered in its place.
	if lb, ok := f.svc.BuildLookup(outOrg, "windows", "amd64"); lb.SHA256 == sum("signed new") || (ok && lb.SHA256 != "") {
		t.Errorf("outside the scope: %+v %v", lb, ok)
	}
	if lb, _ := f.svc.BuildLookup(f.org, "windows", "amd64"); lb.SHA256 != sum("signed new") {
		t.Errorf("inside the scope: %+v", lb)
	}
	// Signed from the stable release, it is the stable set's.
	insert("v1", "signed stable", oldRel.SHA256)
	if err := f.svc.LoadSignedBuilds(f.ctx); err != nil {
		t.Fatal(err)
	}
	if lb, _ := f.svc.BuildLookup(outOrg, "windows", "amd64"); lb.SHA256 != sum("signed stable") {
		t.Errorf("outside the scope, signed from the stable release: %+v", lb)
	}
	if lb, _ := f.svc.BuildLookup(f.org, "windows", "amd64"); lb.SHA256 != sum("signed new") {
		t.Errorf("inside the scope: %+v", lb)
	}
}
