//go:build integration

package agents

import (
	"crypto/sha1" //nolint:gosec // the thumbprint Windows shows
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/agents/authenticode"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/devices"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// The Windows builds here are the Authenticode reader's test programs
// (authenticode/testdata/README.md): tiny.exe stands for the server's
// Windows amd64 build, and its signed copies for what an operator uploads.

func testProgram(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("authenticode", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func shaOf(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// windowsBuilds makes the server serve Windows builds of a version: amd64
// as given, arm64 a program no test file was signed from, and a Linux build.
func (f *updates) windowsBuilds(version string, amd64 []byte) *Builds {
	f.t.Helper()
	dir := f.t.TempDir()
	arm64 := append(append([]byte{}, testProgram(f.t, "tiny.exe")...), []byte("ARM64...")...)
	for name, body := range map[string][]byte{
		"easyrmm-agent-windows-amd64.exe": amd64,
		"easyrmm-agent-windows-arm64.exe": arm64,
		"easyrmm-agent-linux-amd64":       []byte("linux build"),
		VersionFile:                       []byte(version + "\n"),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o644); err != nil {
			f.t.Fatal(err)
		}
	}
	b, err := LoadBuilds(dir)
	if err != nil {
		f.t.Fatal(err)
	}
	f.svc.SetUpdates(b, f.priv)
	if err := f.svc.LoadSignedBuilds(f.ctx); err != nil {
		f.t.Fatal(err)
	}
	return b
}

// windowsBeat is a heartbeat from a Windows amd64 agent running sha; it
// returns the update instruction, verified, or nil.
func (f *updates) windowsBeat(d *Device, sha string) *agentproto.UpdatePayload {
	f.t.Helper()
	resp, err := f.svc.Heartbeat(f.ctx, d, netip.MustParseAddr("192.0.2.10"), agentproto.HeartbeatRequest{
		Facts: agentproto.Facts{Hostname: "w", Platform: "windows", Arch: "amd64", AgentVersion: "v1", AgentSHA256: sha},
	})
	if err != nil {
		f.t.Fatal(err)
	}
	if resp.Update == nil {
		return nil
	}
	p, err := agentproto.VerifyUpdate(f.pub, *resp.Update, d.ID.String(), f.clock)
	if err != nil {
		f.t.Fatal(err)
	}
	return &p
}

func wantInvalid(t *testing.T, err error, text string) {
	t.Helper()
	var e *apperr.Error
	if !errors.As(err, &e) || e.Kind != apperr.KindInvalid || !strings.Contains(e.Fields["file"], text) {
		t.Errorf("got %v (%+v), want a refusal saying %q", err, e, text)
	}
}

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	var e *apperr.Error
	if !errors.As(err, &e) || e.Code != code {
		t.Errorf("got %v, want %s", err, code)
	}
}

func TestSignedBuilds(t *testing.T) {
	f := newUpdates(t, "linux build", "v1")
	tiny := testProgram(t, "tiny.exe")
	rsa, ecdsa := testProgram(t, "tiny-rsa.exe"), testProgram(t, "tiny-ecdsa.exe")
	b := f.windowsBuilds("v1.2.0", tiny)
	admin := f.user("admin@example.com", rbac.Assignment{Role: rbac.RoleSuperAdmin})
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.org})

	// Only Super Administrators sign builds.
	if _, err := f.svc.UploadSignedBuild(f.ctx, tech, rsa); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("technician upload: %v", err)
	}
	if _, _, err := f.svc.ReleaseBuild(f.ctx, tech, "easyrmm-agent-windows-amd64.exe"); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("technician download: %v", err)
	}

	// The file to sign is the release's build.
	rf, rb, err := f.svc.ReleaseBuild(f.ctx, admin, "easyrmm-agent-windows-amd64.exe")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(rf)
	_ = rf.Close()
	if shaOf(got) != shaOf(tiny) || rb.Version != "v1.2.0" || rb.Signed != nil {
		t.Errorf("release build %+v", rb)
	}
	for _, file := range []string{"easyrmm-agent-linux-amd64", "VERSION", "../x"} {
		if _, _, err := f.svc.ReleaseBuild(f.ctx, admin, file); !errors.Is(err, apperr.ErrNotFound) {
			t.Errorf("release %q: %v", file, err)
		}
	}

	// Refused: not a program, unsigned, signed for another use, damaged, or
	// signed but not this server's build.
	wantInvalid(t, uploadErr(f, admin, []byte("not a program")), "not a Windows program")
	wantInvalid(t, uploadErr(f, admin, tiny), "no Authenticode signature")
	wantInvalid(t, uploadErr(f, admin, testProgram(t, "tiny-noeku.exe")), "not for code signing")
	changed := append([]byte{}, rsa...)
	changed[0x400] ^= 0xff
	wantInvalid(t, uploadErr(f, admin, changed), "changed after it was signed")
	if _, err := f.svc.UploadSignedBuild(f.ctx, admin, make([]byte, MaxSignedBuildSize+1)); err == nil {
		t.Error("a file over the limit was taken")
	}
	if n := f.count(`SELECT count(*) FROM signed_agent_builds`); n != 0 {
		t.Fatalf("%d builds kept after refusals", n)
	}

	// Taken: it is the server's amd64 build, signed. It is served in its
	// place, under the same name.
	sb, err := f.svc.UploadSignedBuild(f.ctx, admin, rsa)
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := authenticode.Verify(rsa)
	thumb := sha1.Sum(sig.Signer.Raw) //nolint:gosec // see the import
	if sb.Arch != "amd64" || sb.Version != "v1.2.0" || sb.SHA256 != shaOf(rsa) || sb.ReleaseSHA256 != shaOf(tiny) ||
		sb.Size != int64(len(rsa)) || !sb.Served || sb.UploadedBy != "admin@example.com" ||
		!strings.Contains(sb.Signer.Subject, "EasyRMM test signer (rsa)") || sb.Signer.Thumbprint != hex.EncodeToString(thumb[:]) ||
		sb.Signer.Timestamped || !sb.Signer.NotAfter.Equal(sig.Signer.NotAfter) {
		t.Errorf("signed build %+v", sb)
	}
	served, ok := b.For("windows", "amd64")
	if !ok || served.SHA256 != shaOf(rsa) || served.File != "easyrmm-agent-windows-amd64.exe" || served.Signed == nil || served.Version != "v1.2.0" {
		t.Errorf("served %+v", served)
	}
	rc, ob, err := b.Open("easyrmm-agent-windows-amd64.exe")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(rc)
	_ = rc.Close()
	if shaOf(body) != shaOf(rsa) || ob.SHA256 != shaOf(rsa) {
		t.Error("the download is not the signed build")
	}
	if sums := b.Checksums(); !strings.Contains(sums, shaOf(rsa)+"  easyrmm-agent-windows-amd64.exe\n") || strings.Contains(sums, shaOf(tiny)) {
		t.Errorf("checksums %q", sums)
	}
	if arm, _ := b.For("windows", "arm64"); arm.Signed != nil {
		t.Error("arm64 is served signed")
	}
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'agent_updates.signed_upload' AND details->>'replaced' = 'false'
		AND details->>'thumbprint' = $1`, sb.Signer.Thumbprint); n != 1 {
		t.Errorf("upload audited %d times", n)
	}

	// An agent on the release's build updates to the signed one; one on the
	// signed build is current.
	w1, _ := f.enroll(f.hq, "win-1")
	if p := f.windowsBeat(w1, shaOf(tiny)); p == nil || p.SHA256 != shaOf(rsa) || p.File != "easyrmm-agent-windows-amd64.exe" {
		t.Fatalf("instruction %+v", p)
	}
	if p := f.windowsBeat(w1, shaOf(rsa)); p != nil {
		t.Errorf("told to update from the signed build: %+v", p)
	}
	if lb, ok := f.svc.BuildLookup("windows", "amd64"); !ok || lb.SHA256 != shaOf(rsa) || lb.WaitingFor != "" {
		t.Errorf("lookup %+v", lb)
	}

	// Signed again, with another certificate: it replaces the first.
	if _, err := f.svc.UploadSignedBuild(f.ctx, admin, ecdsa); err != nil {
		t.Fatal(err)
	}
	if n := f.count(`SELECT count(*) FROM signed_agent_builds`); n != 1 {
		t.Errorf("%d builds kept", n)
	}
	if s, _ := b.For("windows", "amd64"); s.SHA256 != shaOf(ecdsa) {
		t.Error("the new signature is not served")
	}
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'agent_updates.signed_upload' AND details->>'replaced' = 'true'`); n != 1 {
		t.Errorf("replacement audited %d times", n)
	}
	// A nested signature is taken too.
	if _, err := f.svc.UploadSignedBuild(f.ctx, admin, testProgram(t, "tiny-nested.exe")); err != nil {
		t.Errorf("nested: %v", err)
	}
	sb2, err := f.svc.UploadSignedBuild(f.ctx, admin, ecdsa)
	if err != nil {
		t.Fatal(err)
	}

	// The settings list the release's builds, the signed build and what is
	// served.
	st, err := f.svc.UpdateSettings(f.ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Release) != 3 || len(st.Builds) != 3 || len(st.Signed) != 1 || st.Signed[0].ID != sb2.ID || !st.Signed[0].Served ||
		len(st.Withheld) != 0 || st.SignedOnly {
		t.Errorf("settings %+v", st)
	}

	// Only signed builds: arm64 has none, so none is handed out for it.
	if _, err := f.svc.SetUpdatePolicy(f.ctx, admin, UpdatePolicy{Mode: UpdateAutomatic, MaxConcurrent: 5, SignedOnly: true}); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.For("windows", "arm64"); ok || !b.Withheld("windows", "arm64") {
		t.Error("arm64's unsigned build is still served")
	}
	if lb, ok := f.svc.BuildLookup("windows", "arm64"); !ok || lb.SHA256 != "" || lb.WaitingFor != "v1.2.0" {
		t.Errorf("arm64 lookup %+v %v", lb, ok)
	}
	if st, _ := f.svc.UpdateSettings(f.ctx, admin); len(st.Withheld) != 1 || st.Withheld[0] != "arm64" || len(st.Builds) != 2 {
		t.Errorf("withheld %+v", st)
	}
	devs := devices.New(f.db, false)
	devs.SetBuilds(f.svc.BuildLookup)
	f.exec(`UPDATE devices SET agent_arch = 'arm64', agent_sha256 = $2 WHERE id = $1`, w1.ID, shaOf(tiny))
	if d, err := devs.Get(f.ctx, admin, w1.ID); err != nil || d.Agent.Update == nil || d.Agent.Update.Status != devices.UpdateWaiting ||
		d.Agent.Update.WaitingFor != "v1.2.0" {
		t.Errorf("device %+v %v", d.Agent, err)
	}
	f.exec(`UPDATE devices SET agent_arch = 'amd64' WHERE id = $1`, w1.ID)

	// The server is upgraded: its amd64 build is another program now. The
	// signed build was made from the old one, so the release's build is
	// served, or, with only signed builds, still the old signed one.
	newer := append(append([]byte{}, tiny...), []byte("v1.3....")...)
	b = f.windowsBuilds("v1.3.0", newer)
	if s, _ := b.For("windows", "amd64"); s.SHA256 != shaOf(ecdsa) || s.Version != "v1.2.0" {
		t.Errorf("with only signed builds after the upgrade: %+v", s)
	}
	if lb, _ := f.svc.BuildLookup("windows", "amd64"); lb.SHA256 != shaOf(ecdsa) || lb.WaitingFor != "v1.3.0" {
		t.Errorf("lookup after the upgrade %+v", lb)
	}
	if d, _ := devs.Get(f.ctx, admin, w1.ID); d.Agent.Update == nil || d.Agent.Update.WaitingFor != "v1.3.0" {
		t.Errorf("device after the upgrade %+v", d.Agent.Update)
	}
	wantInvalid(t, uploadErr(f, admin, rsa), "not one of this server's Windows agent builds")
	if _, err := f.svc.SetUpdatePolicy(f.ctx, admin, UpdatePolicy{Mode: UpdateAutomatic, MaxConcurrent: 5}); err != nil {
		t.Fatal(err)
	}
	if s, _ := b.For("windows", "amd64"); s.SHA256 != shaOf(newer) || s.Signed != nil {
		t.Errorf("the release's build after the upgrade: %+v", s)
	}
	if lb, _ := f.svc.BuildLookup("windows", "amd64"); lb.WaitingFor != "" {
		t.Errorf("waiting without only signed builds: %+v", lb)
	}

	// Of the older builds, only the newest stays.
	for i, v := range []string{"v1.0.0", "v1.1.0"} {
		f.exec(`INSERT INTO signed_agent_builds (id, arch, version, sha256, release_sha256, content, signer_subject,
				signer_issuer, thumbprint, not_before, not_after, timestamped, uploaded_at)
			VALUES (gen_random_uuid(), 'amd64', $1, $2, $2, '\x00', 's', 'i', $3, now(), now(), false, $4)`,
			v, strings.Repeat("ab", 32), strings.Repeat("0", 40), time.Now().Add(time.Duration(i-10)*time.Hour))
	}
	b = f.windowsBuilds("v1.2.0", tiny)
	if _, err := f.svc.UploadSignedBuild(f.ctx, admin, rsa); err != nil {
		t.Fatal(err)
	}
	if n := f.count(`SELECT count(*) FROM signed_agent_builds WHERE version = 'v1.1.0'`); n != 1 {
		t.Error("the newest older build was not kept")
	}
	if n := f.count(`SELECT count(*) FROM signed_agent_builds`); n != 2 {
		t.Errorf("%d builds kept, want this version's and the newest older one", n)
	}
	f.exec(`DELETE FROM signed_agent_builds WHERE version <> 'v1.2.0'`)

	// Removing: the last one cannot go while only signed builds are handed
	// out; then it can, and the release's build is served again.
	cur, _ := b.For("windows", "amd64")
	id := mustSignedID(t, f, cur.SHA256)
	if _, err := f.svc.SetUpdatePolicy(f.ctx, admin, UpdatePolicy{Mode: UpdateAutomatic, MaxConcurrent: 5, SignedOnly: true}); err != nil {
		t.Fatal(err)
	}
	wantCode(t, f.svc.RemoveSignedBuild(f.ctx, admin, id), "last_signed_build")
	if err := f.svc.RemoveSignedBuild(f.ctx, tech, id); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("technician removal: %v", err)
	}
	if _, err := f.svc.SetUpdatePolicy(f.ctx, admin, UpdatePolicy{Mode: UpdateAutomatic, MaxConcurrent: 5}); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.RemoveSignedBuild(f.ctx, admin, id); err != nil {
		t.Fatal(err)
	}
	if s, _ := b.For("windows", "amd64"); s.SHA256 != shaOf(tiny) || s.Signed != nil {
		t.Errorf("after removal %+v", s)
	}
	if err := f.svc.RemoveSignedBuild(f.ctx, admin, id); !errors.Is(err, apperr.ErrNotFound) {
		t.Errorf("removed twice: %v", err)
	}
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'agent_updates.signed_remove'`); n != 1 {
		t.Errorf("removal audited %d times", n)
	}
	// With none, only signed builds cannot be turned on.
	_, err = f.svc.SetUpdatePolicy(f.ctx, admin, UpdatePolicy{Mode: UpdateAutomatic, MaxConcurrent: 5, SignedOnly: true})
	wantCode(t, err, "no_signed_builds")
}

func TestSignedBuildsWithoutWindows(t *testing.T) {
	f := newUpdates(t, "linux build", "v1")
	wantCode(t, uploadErr(f, f.sys, testProgram(t, "tiny-rsa.exe")), "no_windows_build")
	if _, _, err := f.svc.ReleaseBuild(f.ctx, f.sys, "easyrmm-agent-windows-amd64.exe"); !errors.Is(err, apperr.ErrNotFound) {
		t.Errorf("release: %v", err)
	}
	// Without builds at all, loading does nothing.
	if err := (&Service{db: f.db}).LoadSignedBuilds(f.ctx); err != nil {
		t.Error(err)
	}
	// A kept build whose file does not match its SHA-256 stops the server.
	f.windowsBuilds("v1.2.0", testProgram(t, "tiny.exe"))
	f.exec(`INSERT INTO signed_agent_builds (id, arch, version, sha256, release_sha256, content, signer_subject,
			signer_issuer, thumbprint, not_before, not_after, timestamped)
		VALUES (gen_random_uuid(), 'amd64', 'v1.2.0', $1, $2, '\x00', 's', 'i', $3, now(), now(), false)`,
		strings.Repeat("ab", 32), shaOf(testProgram(t, "tiny.exe")), strings.Repeat("0", 40))
	if err := f.svc.LoadSignedBuilds(f.ctx); err == nil || !strings.Contains(err.Error(), "does not match its SHA-256") {
		t.Errorf("load: %v", err)
	}
}

func uploadErr(f *updates, c access.Caller, data []byte) error {
	_, err := f.svc.UploadSignedBuild(f.ctx, c, data)
	return err
}

func mustSignedID(t *testing.T, f *updates, sha string) uuid.UUID {
	t.Helper()
	return f.uuid(`SELECT id FROM signed_agent_builds WHERE sha256 = $1`, sha)
}
