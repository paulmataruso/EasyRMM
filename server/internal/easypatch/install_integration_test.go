//go:build integration

package easypatch

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/easypatch/eptest"
)

// installFixture adds devices with EasyRMM agents to the patching fixture.
type installFixture struct {
	*patchingFixture
	pub          ed25519.PublicKey
	epHQ         uuid.UUID
	lin, win     uuid.UUID
	has, noInv   uuid.UUID
	mac, x86     uuid.UUID
	discovered   uuid.UUID
	globexDevice uuid.UUID
}

func (f *installFixture) agentDevice(org, site uuid.UUID, name, platform, arch string) uuid.UUID {
	f.t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		f.t.Fatal(err)
	}
	return f.id(`INSERT INTO devices (organization_id, site_id, name, hostname, platform, agent_public_key, agent_arch, enrolled_at)
		VALUES ($1, $2, $3, lower($3), $4, $5, $6, now()) RETURNING id`, org, site, name, platform, key, arch)
}

func newInstall(t *testing.T) *installFixture {
	f := &installFixture{patchingFixture: newPatching(t)}
	pub, priv, _ := ed25519.GenerateKey(nil)
	f.pub = pub
	f.svc.SetSigner(priv)
	f.epHQ = f.ep.Site(f.epAcme, "hq") // matched to HQ whatever the case
	f.ep.Site(f.epAcme, "Warehouse")
	f.lin = f.agentDevice(f.acme, f.hq, "lin-01", "linux", "amd64")
	f.report(f.lin, "", nil)
	f.win = f.agentDevice(f.acme, f.branch, "win-01", "windows", "amd64")
	f.report(f.win, "", &agentproto.EasyPatchAgent{Version: "1.9.0", Status: notEnrolled})
	f.has = f.agentDevice(f.acme, f.hq, "has-01", "linux", "amd64")
	f.report(f.has, "", &agentproto.EasyPatchAgent{Version: "1.9.0", Status: "Active", ServerURL: "https://other.example.com"})
	f.noInv = f.agentDevice(f.acme, f.hq, "new-01", "linux", "amd64")
	f.mac = f.agentDevice(f.acme, f.hq, "mac-01", "macos", "arm64")
	f.report(f.mac, "", nil)
	f.x86 = f.agentDevice(f.acme, f.hq, "old-01", "linux", "386")
	f.report(f.x86, "", nil)
	f.discovered = f.device(f.acme, f.hq, "disc-01")
	f.report(f.discovered, "", nil)
	f.globexDevice = f.agentDevice(f.globex, f.plant, "plc-02", "windows", "amd64")
	f.report(f.globexDevice, "", nil)
	return f
}

type installRow struct {
	state, errText, note string
	automatic            bool
	attempts             int
	attempt, token       *uuid.UUID
}

func (f *installFixture) install(device uuid.UUID) (r installRow) {
	f.t.Helper()
	err := f.fixture.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT state, error, note, automatic, attempts, attempt_id, token_id FROM easypatch_installs WHERE device_id = $1`,
			device).Scan(&r.state, &r.errText, &r.note, &r.automatic, &r.attempts, &r.attempt, &r.token)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return installRow{}
	}
	if err != nil {
		f.t.Fatal(err)
	}
	return r
}

// beat is a heartbeat from a device's agent; it returns the verified
// instruction, nil for none.
func (f *installFixture) beat(device uuid.UUID, st *agentproto.EasyPatchInstallStatus) *agentproto.EasyPatchInstallPayload {
	f.t.Helper()
	s := f.svc.AgentHeartbeat(f.ctx, device, st)
	if s == nil {
		return nil
	}
	p, err := agentproto.VerifyEasyPatchInstall(f.pub, *s, device.String(), time.Now())
	if err != nil {
		f.t.Fatalf("the agent would refuse the instruction: %v", err)
	}
	return &p
}

func (f *installFixture) token(id uuid.UUID) eptest.Token {
	f.t.Helper()
	for _, t := range f.ep.Tokens() {
		if t.ID == id {
			return t
		}
	}
	f.t.Fatalf("EasyPatch has no token %s", id)
	return eptest.Token{}
}

func TestInstallRequests(t *testing.T) {
	f := newInstall(t)
	ctx := f.ctx
	all := []uuid.UUID{f.lin, f.win, f.has, f.noInv, f.mac, f.x86, f.discovered, f.lin}

	_, err := f.svc.InstallAgent(ctx, f.admin, ActionInput{})
	wantField(t, err, "deviceIds", "from 1 to 1000")
	_, err = f.svc.InstallAgent(ctx, f.admin, ActionInput{DeviceIDs: all, UpdateIDs: []uuid.UUID{uuid.New()}})
	wantField(t, err, "deviceIds", "devices only")
	_, err = f.svc.InstallAgent(ctx, f.viewer, ActionInput{DeviceIDs: []uuid.UUID{f.lin}})
	wantErr(t, err, apperr.KindForbidden, "")
	_, err = f.svc.InstallAgent(ctx, f.tech, ActionInput{DeviceIDs: []uuid.UUID{f.lin, f.win}})
	wantErr(t, err, apperr.KindNotFound, "") // win-01 is at Branch
	_, err = f.svc.InstallAgent(ctx, f.outsider, ActionInput{DeviceIDs: []uuid.UUID{f.lin}})
	wantErr(t, err, apperr.KindNotFound, "")

	res, err := f.svc.InstallAgent(ctx, f.admin, ActionInput{DeviceIDs: append(all, f.globexDevice)})
	if err != nil || res.Succeeded != 2 || res.Failed != 6 {
		t.Fatalf("install: %+v %v", res, err)
	}
	want := map[uuid.UUID]string{
		f.has: "already has an EasyPatch agent (Active)", f.noInv: "has not reported its inventory yet",
		f.mac: "Windows and Linux only", f.x86: "no agent for 386 processors", f.discovered: "no EasyRMM agent",
		f.globexDevice: "has no patching organization yet",
	}
	for _, r := range res.Results {
		if w, ok := want[r.DeviceID]; ok && (r.OK || !strings.Contains(r.Message, w)) {
			t.Errorf("%s: %+v", r.DeviceName, r)
		}
	}
	if got := f.audits("patch.agent_install"); len(got) != 2 || got[0].Label != "ada@example.com" || got[0].Details["device"] != "lin-01" {
		t.Fatalf("audit: %+v", got)
	}
	if r := f.install(f.lin); r.state != InstallWaiting || r.automatic || r.attempts != 0 {
		t.Fatalf("lin-01: %+v", r)
	}
	// An EasyPatch agent that does not say its status is left alone too.
	f.report(f.has, "", &agentproto.EasyPatchAgent{Error: "status --json failed"})
	if res, _ := f.svc.InstallAgent(ctx, f.admin, ActionInput{DeviceIDs: []uuid.UUID{f.has}}); res.Failed != 1 ||
		!strings.Contains(res.Results[0].Message, "(status unknown)") {
		t.Fatalf("status unknown: %+v", res)
	}
	// Asking again changes nothing, nor does asking while it installs.
	res, err = f.svc.InstallAgent(ctx, f.tech, ActionInput{DeviceIDs: []uuid.UUID{f.lin}})
	if err != nil || res.Succeeded != 1 || res.Results[0].Message != "Already waiting for the device." || len(f.audits("patch.agent_install")) != 2 {
		t.Fatalf("again: %+v %v", res, err)
	}
	if f.beat(f.lin, &agentproto.EasyPatchInstallStatus{}) == nil {
		t.Fatal("no instruction")
	}
	res, err = f.svc.InstallAgent(ctx, f.tech, ActionInput{DeviceIDs: []uuid.UUID{f.lin}})
	if err != nil || res.Failed != 1 || res.Results[0].Message != "The device is installing the EasyPatch agent now." {
		t.Fatalf("while installing: %+v %v", res, err)
	}
	f.exec(`UPDATE easypatch_installs SET state = 'waiting', attempt_id = NULL, sent_at = NULL WHERE device_id = $1`, f.lin)

	// The device and the list show the install.
	d, err := f.svc.Device(ctx, f.tech, f.lin)
	if err != nil || d.Install == nil || d.Install.State != InstallWaiting || d.Install.RequestedBy != "ada@example.com" || d.Link != LinkNone {
		t.Fatalf("device: %+v %v", d.Install, err)
	}
	fleet, err := f.svc.Fleet(ctx, f.admin, FleetQuery{})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range fleet.Devices {
		if (d.DeviceID == f.lin || d.DeviceID == f.win) != (d.Install != nil) {
			t.Errorf("%s in the list: %+v", d.Name, d.Install)
		}
	}

	// Without a job key nothing can be signed.
	f.svc.SetSigner(nil)
	_, err = f.svc.InstallAgent(ctx, f.admin, ActionInput{DeviceIDs: []uuid.UUID{f.lin}})
	wantErr(t, err, apperr.KindUnavailable, "easypatch_no_signer")
	if f.beat(f.lin, &agentproto.EasyPatchInstallStatus{}) != nil {
		t.Error("sent without a signer")
	}
}

func TestInstallHeartbeats(t *testing.T) {
	f := newInstall(t)
	ctx := f.ctx
	if _, err := f.svc.InstallAgent(ctx, f.admin, ActionInput{DeviceIDs: []uuid.UUID{f.lin, f.win}}); err != nil {
		t.Fatal(err)
	}
	// Devices without an install, and agents too old to install, get none;
	// the old agent's install says why it waits.
	if f.beat(f.has, &agentproto.EasyPatchInstallStatus{}) != nil || f.beat(uuid.New(), nil) != nil {
		t.Fatal("sent to a device without an install")
	}
	if f.beat(f.lin, nil) != nil || f.install(f.lin).note != noteOldAgent {
		t.Fatalf("old agent: %+v", f.install(f.lin))
	}
	if f.beat(f.lin, nil) != nil {
		t.Fatal("sent to an old agent")
	}
	if d, _ := f.svc.Device(ctx, f.admin, f.lin); d.Install.Note != noteOldAgent {
		t.Errorf("note: %+v", d.Install)
	}
	// An agent busy with another install waits.
	if f.beat(f.lin, &agentproto.EasyPatchInstallStatus{Busy: "other"}) != nil {
		t.Fatal("sent to a busy agent")
	}

	// Linux: deb and rpm for its architecture, to EasyPatch's HQ site.
	p := f.beat(f.lin, &agentproto.EasyPatchInstallStatus{})
	if p == nil {
		t.Fatal("no instruction")
	}
	row := f.install(f.lin)
	if row.state != InstallSent || row.attempts != 1 || row.note != "" || row.attempt == nil || row.attempt.String() != p.ID || row.token == nil {
		t.Fatalf("sent: %+v", row)
	}
	if p.ServerURL != "https://patch.example.com" || p.CACert != "" || len(p.Packages) != 2 ||
		p.Packages[0].FileName != "EasyPatchAgent-1.9.0-x64.deb" || p.Packages[1].Format != agentproto.EasyPatchRPM ||
		p.Packages[0].URL != "https://patch.example.com/downloads/agent/EasyPatchAgent-1.9.0-x64.deb" ||
		p.Packages[0].SHA256 != strings.ToLower(p.Packages[0].SHA256) || p.ExpiresAt.Sub(p.IssuedAt) != installValidFor {
		t.Fatalf("instruction: %+v", p)
	}
	tok := f.token(*row.token)
	if tok.Secret != p.Token || tok.Org != f.epAcme || tok.Site == nil || *tok.Site != f.epHQ || tok.MaxUses != 1 || tok.ExpiresIn != 1 ||
		tok.Description != "EasyRMM install on lin-01" {
		t.Fatalf("token: %+v", tok)
	}
	if reqs := f.ep.RequestsTo("POST", "/api/v1/enrollment-tokens"); len(reqs) != 1 || reqs[0].Statement.Name != "ada@example.com" {
		t.Fatalf("token request: %+v", reqs)
	}
	// Sent once: the agent installing, or reporting for another attempt,
	// changes nothing.
	if f.beat(f.lin, &agentproto.EasyPatchInstallStatus{Busy: p.ID}) != nil ||
		f.beat(f.lin, &agentproto.EasyPatchInstallStatus{Last: &agentproto.EasyPatchInstallReport{ID: "older", OK: true}}) != nil ||
		f.beat(f.lin, nil) != nil || f.install(f.lin).state != InstallSent {
		t.Fatalf("while installing: %+v", f.install(f.lin))
	}
	// It succeeded.
	f.beat(f.lin, &agentproto.EasyPatchInstallStatus{Last: &agentproto.EasyPatchInstallReport{ID: p.ID, OK: true}})
	if r := f.install(f.lin); r.state != InstallSucceeded || r.errText != "" || f.token(*row.token).Revoked {
		t.Fatalf("succeeded: %+v", r)
	}
	if f.beat(f.lin, &agentproto.EasyPatchInstallStatus{}) != nil {
		t.Fatal("sent after it succeeded")
	}

	// Windows: the MSI only, and no site, as EasyPatch has no Branch site.
	w := f.beat(f.win, &agentproto.EasyPatchInstallStatus{})
	if w == nil || len(w.Packages) != 1 || w.Packages[0].FileName != "EasyPatchAgent-1.9.0-x64.msi" {
		t.Fatalf("windows: %+v", w)
	}
	wrow := f.install(f.win)
	if tok := f.token(*wrow.token); tok.Site != nil {
		t.Fatalf("windows token: %+v", tok)
	}
	// It failed: the reason is kept and the token revoked, or left to
	// expire when EasyPatch cannot be reached.
	f.ep.Set(func() { f.ep.Down = true })
	f.beat(f.win, &agentproto.EasyPatchInstallStatus{Last: &agentproto.EasyPatchInstallReport{ID: w.ID, Error: " Installer failed (msiexec exit code 1603) "}})
	f.ep.Set(func() { f.ep.Down = false })
	if r := f.install(f.win); r.state != InstallFailed || r.errText != "Installer failed (msiexec exit code 1603)" || f.token(*wrow.token).Revoked {
		t.Fatalf("failed: %+v", r)
	}
	if reqs := f.ep.RequestsTo("POST", "/api/v1/enrollment-tokens/"+wrow.token.String()+"/revoke"); len(reqs) != 1 {
		t.Fatalf("revoke: %+v", reqs)
	}
	// Asked again, a new attempt; one the agent never mentions is lost after
	// a few minutes.
	if _, err := f.svc.InstallAgent(ctx, f.admin, ActionInput{DeviceIDs: []uuid.UUID{f.win}}); err != nil {
		t.Fatal(err)
	}
	w2 := f.beat(f.win, &agentproto.EasyPatchInstallStatus{})
	if w2 == nil || w2.ID == w.ID || f.install(f.win).attempts != 1 {
		t.Fatalf("again: %+v %+v", w2, f.install(f.win))
	}
	if f.beat(f.win, &agentproto.EasyPatchInstallStatus{}); f.install(f.win).state != InstallSent {
		t.Fatal("lost too soon")
	}
	f.exec(`UPDATE easypatch_installs SET sent_at = now() - interval '4 minutes' WHERE device_id = $1`, f.win)
	f.beat(f.win, &agentproto.EasyPatchInstallStatus{})
	if r := f.install(f.win); r.state != InstallFailed || !strings.Contains(r.errText, "did not get the instruction") || !f.token(*r.token).Revoked {
		t.Fatalf("lost: %+v", r)
	}
	// A failure without a reason still says something.
	if _, err := f.svc.InstallAgent(ctx, f.admin, ActionInput{DeviceIDs: []uuid.UUID{f.win}}); err != nil {
		t.Fatal(err)
	}
	w3 := f.beat(f.win, &agentproto.EasyPatchInstallStatus{})
	f.beat(f.win, &agentproto.EasyPatchInstallStatus{Last: &agentproto.EasyPatchInstallReport{ID: w3.ID}})
	if r := f.install(f.win); r.errText != "The agent did not say why." {
		t.Fatalf("no reason: %+v", r)
	}
}

func TestInstallPreparationFails(t *testing.T) {
	f := newInstall(t)
	ctx := f.ctx
	request := func(d uuid.UUID) {
		t.Helper()
		if res, err := f.svc.InstallAgent(ctx, f.admin, ActionInput{DeviceIDs: []uuid.UUID{d}}); err != nil || res.Succeeded != 1 {
			t.Fatalf("request: %+v %v", res, err)
		}
	}
	fails := func(d uuid.UUID, want string) installRow {
		t.Helper()
		if p := f.beat(d, &agentproto.EasyPatchInstallStatus{}); p != nil {
			t.Fatalf("sent: %+v", p)
		}
		r := f.install(d)
		if r.state != InstallFailed || !strings.Contains(r.errText, want) {
			t.Fatalf("want %q: %+v", want, r)
		}
		return r
	}
	tokens := len(f.ep.Tokens())

	// EasyPatch has no package for the device.
	request(f.lin)
	var packages []map[string]any
	f.ep.Set(func() {
		packages = f.ep.Packages
		var keep []map[string]any
		for _, p := range f.ep.Packages {
			if p["architecture"] != "x64" {
				keep = append(keep, p)
			}
		}
		f.ep.Packages = keep
	})
	fails(f.lin, "EasyPatch has no agent package for Linux x64")
	request(f.win)
	fails(f.win, "EasyPatch has no agent package for Windows x64")
	f.ep.Set(func() { f.ep.Packages = packages })
	// EasyPatch cannot be reached.
	request(f.lin)
	f.ep.Set(func() { f.ep.Down = true })
	fails(f.lin, "EasyPatch could not list its agent packages")
	f.ep.Set(func() { f.ep.Down = false })
	// The device got an EasyPatch agent meanwhile.
	request(f.win)
	f.report(f.win, "", &agentproto.EasyPatchAgent{Status: "Active"})
	fails(f.win, "already has an EasyPatch agent")
	f.report(f.win, "", nil)
	// The engine refuses the token.
	request(f.win)
	f.ep.Set(func() { f.ep.ReadOnly = true })
	fails(f.win, "EasyPatch did not create an enrollment token")
	f.ep.Set(func() { f.ep.ReadOnly = false })
	if len(f.ep.Tokens()) != tokens {
		t.Fatal("a token was created for a failed preparation")
	}
	// An address the agent would refuse: the token is revoked at once.
	request(f.win)
	f.ep.Set(func() { f.ep.PublicURL = "http://patch.example.com" })
	if _, err := f.svc.CheckConnection(ctx); err != nil {
		t.Fatal(err)
	}
	r := fails(f.win, "not in a form the agent accepts")
	if list := f.ep.Tokens(); len(list) != tokens+1 || !list[len(list)-1].Revoked {
		t.Fatalf("token: %+v %+v", list, r)
	}
	// Without a public address, never the engine's loopback one.
	f.ep.Set(func() { f.ep.PublicURL = "" })
	if _, err := f.svc.CheckConnection(ctx); err != nil {
		t.Fatal(err)
	}
	request(f.win)
	fails(f.win, "no public address for agents to enroll with")
	f.ep.Set(func() { f.ep.PublicURL = "https://patch.example.com" })
	if _, err := f.svc.CheckConnection(ctx); err != nil {
		t.Fatal(err)
	}
	// The organization has no patching organization (yet).
	f.exec(`DELETE FROM easypatch_organizations WHERE organization_id = $1`, f.acme)
	f.exec(`UPDATE easypatch_installs SET state = 'waiting', error = '', attempt_id = NULL, sent_at = NULL WHERE device_id = $1`, f.lin)
	fails(f.lin, "has no patching organization yet")
}

func TestInstallSweeps(t *testing.T) {
	f := newInstall(t)
	ctx := f.ctx
	sweep := func() int {
		t.Helper()
		n, err := f.svc.SweepInstalls(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	// An attempt never reported fails after 30 minutes.
	if _, err := f.svc.InstallAgent(ctx, f.admin, ActionInput{DeviceIDs: []uuid.UUID{f.lin}}); err != nil {
		t.Fatal(err)
	}
	f.beat(f.lin, &agentproto.EasyPatchInstallStatus{})
	if sweep() != 0 || f.install(f.lin).state != InstallSent {
		t.Fatal("timed out too soon")
	}
	f.exec(`UPDATE easypatch_installs SET sent_at = now() - interval '31 minutes' WHERE device_id = $1`, f.lin)
	sweep()
	if r := f.install(f.lin); r.state != InstallFailed || !strings.Contains(r.errText, "within 30 minutes") || !f.token(*r.token).Revoked {
		t.Fatalf("timed out: %+v", r)
	}

	// Automatic installs.
	err := f.svc.SetAutoInstall(ctx, f.admin.Actor, f.globex, true)
	wantErr(t, err, apperr.KindNotFound, "")
	if err := f.svc.SetAutoInstall(ctx, f.admin.Actor, f.acme, true); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.SetAutoInstall(ctx, f.admin.Actor, f.acme, true); err != nil {
		t.Fatal(err)
	}
	if got := f.audits("easypatch.organization_update"); len(got) != 1 || got[0].Details["autoInstall"] != true {
		t.Fatalf("audit: %+v", got)
	}
	orgs, err := f.svc.Organizations(ctx)
	if err != nil || len(orgs.Links) != 1 || !orgs.Links[0].AutoInstall {
		t.Fatalf("organizations: %+v %v", orgs.Links, err)
	}
	// win-01 qualifies (its EasyPatch agent is not enrolled); lin-01 already
	// has an install; the others do not qualify, nor does Globex's device.
	if n := sweep(); n != 1 {
		t.Fatalf("sweep: %d", n)
	}
	if r := f.install(f.win); r.state != InstallWaiting || !r.automatic {
		t.Fatalf("win-01: %+v", r)
	}
	for _, d := range []uuid.UUID{f.has, f.noInv, f.mac, f.x86, f.discovered, f.globexDevice} {
		if r := f.install(d); r.state != "" {
			t.Errorf("%s: %+v", d, r)
		}
	}
	if f.install(f.lin).automatic {
		t.Error("lin-01's request became automatic")
	}
	// A failed automatic install is tried again an hour later, three times
	// in all.
	p := f.beat(f.win, &agentproto.EasyPatchInstallStatus{})
	f.beat(f.win, &agentproto.EasyPatchInstallStatus{Last: &agentproto.EasyPatchInstallReport{ID: p.ID, Error: "no systemd"}})
	if sweep() != 0 {
		t.Fatal("retried at once")
	}
	for attempt := 2; attempt <= 3; attempt++ {
		f.exec(`UPDATE easypatch_installs SET finished_at = now() - interval '61 minutes' WHERE device_id = $1`, f.win)
		if sweep() != 1 || f.install(f.win).state != InstallWaiting {
			t.Fatalf("attempt %d not retried: %+v", attempt, f.install(f.win))
		}
		p := f.beat(f.win, &agentproto.EasyPatchInstallStatus{})
		f.beat(f.win, &agentproto.EasyPatchInstallStatus{Last: &agentproto.EasyPatchInstallReport{ID: p.ID, Error: "no systemd"}})
		if r := f.install(f.win); r.attempts != attempt || r.state != InstallFailed {
			t.Fatalf("attempt %d: %+v", attempt, r)
		}
	}
	f.exec(`UPDATE easypatch_installs SET finished_at = now() - interval '61 minutes' WHERE device_id = $1`, f.win)
	if sweep() != 0 {
		t.Fatal("tried a fourth time")
	}
	// Requested installs are not retried.
	f.exec(`UPDATE easypatch_installs SET finished_at = now() - interval '61 minutes' WHERE device_id = $1`, f.lin)
	if sweep() != 0 || f.install(f.lin).state != InstallFailed {
		t.Fatal("retried a requested install")
	}
	// Turned off, nothing new waits.
	if err := f.svc.SetAutoInstall(ctx, f.admin.Actor, f.acme, false); err != nil {
		t.Fatal(err)
	}
	f.report(f.noInv, "", nil)
	if sweep() != 0 {
		t.Fatal("swept with automatic installs off")
	}
}

func TestCAForAgent(t *testing.T) {
	ca := string(testAuthority(t))
	if caForAgent("") != "" || caForAgent("junk") != "" {
		t.Error("no certificate")
	}
	if got := caForAgent(ca); got != ca {
		t.Errorf("one certificate: %q", got)
	}
	// The authority is self-signed, so it is the root of any bundle it is
	// in.
	bundle := "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n" + ca
	if got := caForAgent(bundle); got != ca {
		t.Errorf("bundle: %q", got)
	}
}

// TestBundledInstall: with the engine in this deployment, an install goes to
// the organization and site EasyRMM keeps there (ADR-0040), and, when
// EasyRMM is addressed by IP with its own certificate authority, carries
// that authority for the EasyPatch agent to trust (one-product plan, B7).
func TestBundledInstall(t *testing.T) {
	f := newFixture(t)
	engine := eptest.NewEngine(t, reconcileKey)
	caPEM := testAuthority(t)
	start := func(opts ...EngineOption) ed25519.PublicKey {
		signer, err := NewSigner(reconcileKey)
		if err != nil {
			t.Fatal(err)
		}
		client, err := NewEngineClient(engine.URL(), signer, "1.0.0")
		if err != nil {
			t.Fatal(err)
		}
		f.svc = New(f.db, audit.New(f.db, nil), "1.0.0", slog.New(slog.NewTextHandler(io.Discard, nil)))
		if err := f.svc.UseEngine(client, opts...); err != nil {
			t.Fatal(err)
		}
		pub, priv, _ := ed25519.GenerateKey(nil)
		f.svc.SetSigner(priv)
		return pub
	}
	instruction := func(pub ed25519.PublicKey, device uuid.UUID) agentproto.EasyPatchInstallPayload {
		t.Helper()
		if res, err := f.svc.InstallAgent(f.ctx, f.admin, ActionInput{DeviceIDs: []uuid.UUID{device}}); err != nil || res.Succeeded != 1 {
			t.Fatalf("install: %+v, %v", res, err)
		}
		s := f.svc.AgentHeartbeat(f.ctx, device, &agentproto.EasyPatchInstallStatus{})
		if s == nil {
			t.Fatal("no instruction")
		}
		p, err := agentproto.VerifyEasyPatchInstall(pub, *s, device.String(), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	agentDevice := func(name, platform string) uuid.UUID {
		d := f.id(`INSERT INTO devices (organization_id, site_id, name, hostname, platform, agent_public_key, agent_arch, enrolled_at)
			VALUES ($1, $2, $3, lower($3), $4, $5, 'amd64', now()) RETURNING id`, f.acme, f.hq, name, platform, bytes.Repeat([]byte(name[:1]), 32))
		f.report(d, "", nil)
		return d
	}

	pub := start(AgentCA(func() []byte { return caPEM }))
	f.reconcile()
	lin := agentDevice("lin-01", "linux")
	p := instruction(pub, lin)
	if p.CACert != string(caPEM) || p.ServerURL != "https://patch.example.com" || len(p.Packages) != 2 {
		t.Fatalf("instruction: %+v", p)
	}
	var tok *eptest.Token
	for _, x := range engine.Tokens() {
		if x.Org == f.engineOrg(f.acme) {
			tok = &x
		}
	}
	if tok == nil || tok.Site == nil || *tok.Site != f.engineSite(f.hq) {
		t.Fatalf("enrollment token: %+v", tok)
	}

	// Addressed by name: nothing to trust beyond the system's.
	pub = start()
	win := agentDevice("win-01", "windows")
	if p := instruction(pub, win); p.CACert != "" || p.Packages[0].Format != agentproto.EasyPatchMSI {
		t.Fatalf("by name: %+v", p)
	}
}

// testAuthority is a certificate authority's certificate (PEM).
func testAuthority(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "EasyRMM test authority"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
