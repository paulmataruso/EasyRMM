//go:build integration

package app_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/agent/escrow"
	"github.com/paulmataruso/easyrmm/agent/host"
	"github.com/paulmataruso/easyrmm/agent/state"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/config"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/keystore"
	"github.com/paulmataruso/easyrmm/server/internal/keystored"
)

const escrowTestPassword = "123456-234567-345678-456789-567890-678901-789012-890123"

// stubBitLocker stands in for WMI, which the test machine does not have.
type stubBitLocker struct{ vol, prot string }

func (s stubBitLocker) Volumes(context.Context) ([]escrow.Volume, error) {
	return []escrow.Volume{{ID: s.vol, Mount: "C:", Status: "encrypted", Protectors: []string{s.prot}}}, nil
}

func (s stubBitLocker) RecoveryPassword(context.Context, string, string) ([]byte, error) {
	return []byte(escrowTestPassword), nil
}

// TestRecoveryKeyEscrowEndToEnd is ADR-0081 slice 1 through the real server:
// a real keystore on a real socket, the real agent client and escrow code with
// a stub for WMI, the signed instruction and routes, the verification inside
// the keystore, and the console's per-volume state.
// escrowKeystore starts a keystore, in the opt-in file mode so that no person or TPM is needed, on a real socket
// and returns the socket's path.
func escrowKeystore(t *testing.T) string {
	t.Helper()
	// The keystore, in the opt-in file mode so that no person or TPM is needed.
	dir, err := os.MkdirTemp("", "ks-app")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	ks, err := keystored.Open(keystored.Options{Dir: filepath.Join(dir, "state"), Mode: keystore.ModeFile})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ks.Close)
	code, bundle, err := ks.Init("", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ks.VerifyRecovery(bundle, code); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "ks.sock")
	ln, err := keystored.Listen(sock, 0o660)
	if err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Getuid()) //nolint:gosec // a uid
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	srv := &keystored.Server{KS: ks, ServiceUIDs: []uint32{uid}, AdminUID: uid}
	go func() { _ = srv.Serve(ctx, ln, nil); close(done) }()
	t.Cleanup(func() { stop(); <-done })
	return sock
}

func TestRecoveryKeyEscrowEndToEnd(t *testing.T) {
	sock := escrowKeystore(t)
	ctx := context.Background()
	h := newHarnessWith(t, false, func(c *config.Config) { c.KeystoreSocket = sock })
	admin, adminTOTP := setUp(t, h)
	acme := orgID(t, admin, "Acme")
	var hq idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/sites", map[string]string{"name": "HQ", "timezone": "UTC"}, &hq)
	var token struct {
		Secret string `json:"secret"`
	}
	admin.expect(http.StatusCreated, "POST", "/api/v1/sites/"+hq.ID+"/enrollment-tokens", map[string]any{"name": "Windows", "expiresInDays": 1}, &token)

	ac := h.agentClient()
	key := newKey(t)
	enr, err := ac.Enroll(ctx, token.Secret, key.Public().(ed25519.PublicKey), windowsFacts("ws-03", "1.2.3-test"))
	if err != nil {
		t.Fatal(err)
	}
	ac.SetIdentity(enr.DeviceID, key)
	jobKey, err := agentproto.DecodeKey(enr.JobKey)
	if err != nil {
		t.Fatal(err)
	}

	// An agent that does not announce the capability gets no key; one that
	// does gets the organization's, signed with the job key.
	plain, err := ac.Heartbeat(ctx, agentproto.HeartbeatRequest{Facts: windowsFacts("ws-03", "1.2.3-test")})
	if err != nil || plain.Escrow != nil {
		t.Fatalf("a heartbeat without the capability: %+v %v", plain.Escrow, err)
	}
	resp, err := ac.Heartbeat(ctx, agentproto.HeartbeatRequest{Facts: windowsFacts("ws-03", "1.2.3-test"), Caps: []string{agentproto.CapEscrow}})
	if err != nil || resp.Escrow == nil {
		t.Fatalf("heartbeat with the capability: %+v %v", resp.Escrow, err)
	}
	if _, _, err := agentproto.VerifyEscrowKey(jobKey, *resp.Escrow, enr.DeviceID, time.Now()); err != nil {
		t.Fatalf("the instruction does not verify: %v", err)
	}

	// The real escrow code, with a stub in place of WMI.
	store, _, err := state.Open(host.Paths{Root: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(store.Dir(), 0o700); err != nil {
		t.Fatal(err)
	}
	vol, prot := `\\?\Volume{33333333-3333-3333-3333-333333333333}\`, "{CCCCCCCC-0000-0000-0000-000000000003}"
	agent := &escrow.Agent{DeviceID: enr.DeviceID, Key: func() ed25519.PublicKey { return jobKey }, Reader: stubBitLocker{vol, prot},
		Server: ac, Store: store, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	agent.Answered(resp.Escrow)

	var before struct {
		Applicable bool `json:"applicable"`
		Volumes    []struct {
			State string `json:"state"`
		} `json:"volumes"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/devices/"+enr.DeviceID+"/escrow", nil, &before)
	if !before.Applicable || len(before.Volumes) != 0 {
		t.Fatalf("before the agent reports: %+v", before)
	}
	agent.Sync(ctx)

	var after struct {
		Keystore struct {
			State            string `json:"state"`
			RecoveryVerified bool   `json:"recoveryVerified"`
		} `json:"keystore"`
		Volumes []struct {
			ID         string `json:"id"`
			State      string `json:"state"`
			Protectors []struct {
				ID    string `json:"id"`
				State string `json:"state"`
			} `json:"protectors"`
		} `json:"volumes"`
	}
	r := admin.do("GET", "/api/v1/devices/"+enr.DeviceID+"/escrow", nil)
	admin.expect(http.StatusOK, "GET", "/api/v1/devices/"+enr.DeviceID+"/escrow", nil, &after)
	if after.Keystore.State != "unsealed" || !after.Keystore.RecoveryVerified {
		t.Errorf("keystore: %+v", after.Keystore)
	}
	if len(after.Volumes) != 1 || after.Volumes[0].State != "verified" || after.Volumes[0].Protectors[0].ID != prot || after.Volumes[0].Protectors[0].State != "verified" {
		t.Fatalf("volumes after escrow: %+v", after.Volumes)
	}
	// Nothing of the key is in what the console returns.
	if strings.Contains(string(r.body), "123456") || strings.Contains(string(r.body), "ciphertext") {
		t.Errorf("the console response holds key material: %s", r.body)
	}
	// And the keystore's own status is the platform administrator's.
	var ksStatus struct {
		State string `json:"state"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/keystore", nil, &ksStatus)
	if ksStatus.State != "unsealed" {
		t.Errorf("keystore status = %s", ksStatus.State)
	}

	// Another organization's technician cannot see the device's escrow, nor
	// the keystore's platform status.
	var globex idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations", map[string]string{"name": "Globex"}, &globex)
	invite(t, h, admin, "gil@globex.example", []map[string]any{{"role": "technician", "organizationId": globex.ID}})
	other := h.client()
	other.signIn("gil@globex.example", "a long and unusual passphrase", "")
	wantStatus(t, other.do("GET", "/api/v1/devices/"+enr.DeviceID+"/escrow", nil), http.StatusNotFound, "")
	wantStatus(t, other.do("GET", "/api/v1/keystore", nil), http.StatusForbidden, "")

	readRecoveryKey(t, h, admin, adminTOTP, acme, enr.DeviceID, vol, prot)

	// The agent route is signed, limited and bound to the device: a record
	// for a protector the device never reported is refused with 409.
	_, err = ac.EscrowUpload(ctx, agentproto.EscrowRecord{VolumeID: vol, ProtectorID: "{DDDD}", Kind: agentproto.EscrowBitLocker, KeyID: "00000000-0000-0000-0000-000000000000",
		Enc: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Ciphertext: "AAAA", Fingerprint: strings.Repeat("0", 32)})
	if err == nil {
		t.Error("an unreported protector was accepted")
	}
}

// readRecoveryKey is ADR-0081 slice 2 over HTTP: the read permission is an
// add-on no super administrator has, the read needs a reason and a step-up, the
// key is shown once with no-store, and the notice, the requests and the
// settings are the console's.
func readRecoveryKey(t *testing.T, h *harness, admin *client, adminTOTP, org, device, vol, prot string) {
	t.Helper()
	path := "/api/v1/devices/" + device + "/escrow/read"
	body := map[string]any{"volume": vol, "protector": prot, "reason": "Laptop will not boot, owner on site", "ticket": "T-9"}
	// A super administrator does not hold the permission, with or without a step-up.
	wantStatus(t, admin.do("POST", path, body), http.StatusForbidden, "")

	invite(t, h, admin, "rae@acme.example", []map[string]any{
		{"role": "technician", "organizationId": org}, {"role": "key_reader", "organizationId": org},
	})
	rae := h.client()
	secret := rae.signIn("rae@acme.example", "a long and unusual passphrase", "")
	var esc struct {
		CanRead bool `json:"canRead"`
	}
	rae.expect(http.StatusOK, "GET", "/api/v1/devices/"+device+"/escrow", nil, &esc)
	if !esc.CanRead {
		t.Fatal("the add-on role does not show the read")
	}
	// Without a step-up, with no reason, and with a key typed into it: refused.
	wantStatus(t, rae.do("POST", path, body), http.StatusUnauthorized, "step_up_required")
	rae.expect(http.StatusOK, "POST", "/api/v1/auth/step-up/totp", map[string]string{"code": code(t, secret, time.Now().Add(30*time.Second))}, nil)
	wantStatus(t, rae.do("POST", path, map[string]any{"volume": vol, "protector": prot, "reason": ""}), http.StatusUnprocessableEntity, "")
	wantStatus(t, rae.do("POST", path, map[string]any{"volume": vol, "protector": prot, "reason": "key " + escrowTestPassword}), http.StatusUnprocessableEntity, "")

	r := rae.expect(http.StatusOK, "POST", path, body, nil)
	if got := strings.TrimSpace(string(r.body)); got != `{"key":"`+escrowTestPassword+`"}` {
		t.Fatalf("the read answered %q", got)
	}
	if cc := r.header.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q", cc)
	}
	// Nowhere else: not in the notices, the requests or the alerts.
	var notices struct {
		Notices []struct{ Reason, By string } `json:"notices"`
	}
	nr := admin.expect(http.StatusOK, "GET", "/api/v1/keystore/notices", nil, &notices)
	if len(notices.Notices) != 1 || notices.Notices[0].By != "rae@acme.example" || notices.Notices[0].Reason != "Laptop will not boot, owner on site" {
		t.Fatalf("notices: %s", nr.body)
	}
	for _, p := range []string{"/api/v1/keystore/notices", "/api/v1/keystore/alerts", "/api/v1/keystore/requests", "/api/v1/devices/" + device + "/escrow"} {
		if b := rae.do("GET", p, nil).body; strings.Contains(string(b), "123456-234567") {
			t.Errorf("%s holds the key", p)
		}
	}
	// A technician without the add-on sees no notices and cannot read.
	invite(t, h, admin, "tom@acme.example", []map[string]any{{"role": "technician", "organizationId": org}})
	tom := h.client()
	tsecret := tom.signIn("tom@acme.example", "a long and unusual passphrase", "")
	tom.expect(http.StatusOK, "POST", "/api/v1/auth/step-up/totp", map[string]string{"code": code(t, tsecret, time.Now().Add(30*time.Second))}, nil)
	wantStatus(t, tom.do("POST", path, body), http.StatusForbidden, "")
	var none struct {
		Notices []any `json:"notices"`
	}
	tom.expect(http.StatusOK, "GET", "/api/v1/keystore/notices", nil, &none)
	if len(none.Notices) != 0 {
		t.Errorf("a technician sees notices: %+v", none)
	}
	var reqs struct {
		Requests []any `json:"requests"`
	}
	rae.expect(http.StatusOK, "GET", "/api/v1/keystore/requests", nil, &reqs)
	var al struct {
		Alerts []any `json:"alerts"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/keystore/alerts", nil, &al)

	// An alert is resolved by a person who may (the control of slice 3): an organization's by its
	// administrators and the platform's by whoever manages settings; another person gets a 404.
	var alertID string
	if err := h.db.DB.InTx(context.Background(), database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `INSERT INTO keystore_alerts (organization_id, kind, severity, subject, detail)
			VALUES ($1, 'escrow_conflict', 'warning', 'x', 'A different key arrived.') RETURNING id::text`, org).Scan(&alertID)
	}); err != nil {
		t.Fatal(err)
	}
	var open struct {
		Alerts []struct {
			ID   string `json:"id"`
			Kind string `json:"kind"`
		} `json:"alerts"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/keystore/alerts", nil, &open)
	if len(open.Alerts) != 1 || open.Alerts[0].ID != alertID {
		t.Fatalf("alerts: %+v", open.Alerts)
	}
	tom.expect(http.StatusOK, "GET", "/api/v1/keystore/alerts", nil, &open)
	if len(open.Alerts) != 0 {
		t.Fatalf("a technician sees alerts: %+v", open.Alerts)
	}
	wantStatus(t, tom.do("POST", "/api/v1/keystore/alerts/"+alertID+"/resolve", nil), http.StatusNotFound, "")
	wantStatus(t, admin.do("POST", "/api/v1/keystore/alerts/"+alertID+"/resolve", nil), http.StatusNoContent, "")
	wantStatus(t, admin.do("POST", "/api/v1/keystore/alerts/"+alertID+"/resolve", nil), http.StatusNotFound, "")
	admin.expect(http.StatusOK, "GET", "/api/v1/keystore/alerts", nil, &open)
	if len(open.Alerts) != 0 {
		t.Fatalf("the resolved alert is still listed: %+v", open.Alerts)
	}

	// The two-person setting: off by default, needs two approvers and a step-up, and is an
	// organization administrator's.
	sp := "/api/v1/organizations/" + org + "/keystore-settings"
	var set struct {
		TwoPerson bool `json:"twoPerson"`
		Approvers int  `json:"approvers"`
	}
	admin.expect(http.StatusOK, "GET", sp, nil, &set)
	if set.TwoPerson || set.Approvers != 0 {
		t.Fatalf("settings: %+v", set)
	}
	wantStatus(t, rae.do("PUT", sp, map[string]any{"twoPerson": true}), http.StatusForbidden, "")
	admin.expect(http.StatusOK, "POST", "/api/v1/auth/step-up/totp", map[string]string{"code": code(t, adminTOTP, time.Now().Add(30*time.Second))}, nil)
	wantStatus(t, admin.do("PUT", sp, map[string]any{"twoPerson": true}), http.StatusConflict, "need_approvers")

	// ADR-0081 slice 4. The key that was just read is due for rotation, which
	// the device's page shows; the platform status says what each KEK version
	// still wraps; an organization's escrow key is rotated by its administrator
	// with a step-up, never by a technician, and the new one is the next version.
	var dev struct {
		Volumes []struct {
			Protectors []struct {
				RotationDue bool `json:"rotationDue"`
			} `json:"protectors"`
		} `json:"volumes"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/devices/"+device+"/escrow", nil, &dev)
	if len(dev.Volumes) != 1 || len(dev.Volumes[0].Protectors) != 1 || !dev.Volumes[0].Protectors[0].RotationDue {
		t.Fatalf("a key that was read is not shown as due for rotation: %+v", dev)
	}
	var plat struct {
		KEKUsage []struct{ Version, Keys int } `json:"kekUsage"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/keystore", nil, &plat)
	if len(plat.KEKUsage) != 1 || plat.KEKUsage[0].Version != 1 || plat.KEKUsage[0].Keys < 1 {
		t.Fatalf("kek usage: %+v", plat.KEKUsage)
	}
	rk := "/api/v1/organizations/" + org + "/keystore/rotate-key"
	wantStatus(t, rae.do("POST", rk, nil), http.StatusForbidden, "")
	var rotated struct {
		Key struct{ Version, Retired int } `json:"key"`
	}
	admin.expect(http.StatusAccepted, "POST", rk, nil, &rotated)
	if rotated.Key.Version != 2 || rotated.Key.Retired != 1 {
		t.Fatalf("after the rotation: %+v", rotated)
	}

	// With two approvers it turns on, and a read then waits for one of them.
	type approver struct {
		c      *client
		secret string
	}
	var aps []approver
	for _, email := range []string{"ann@acme.example", "ben@acme.example"} {
		invite(t, h, admin, email, []map[string]any{{"role": "technician", "organizationId": org}, {"role": "key_approver", "organizationId": org}})
		c := h.client()
		aps = append(aps, approver{c, c.signIn(email, "a long and unusual passphrase", "")})
	}
	admin.expect(http.StatusOK, "PUT", sp, map[string]any{"twoPerson": true}, &set)
	if !set.TwoPerson || set.Approvers != 2 {
		t.Fatalf("turn on: %+v", set)
	}
	var pending struct {
		Pending struct {
			ID    string `json:"id"`
			State string `json:"state"`
		} `json:"pending"`
	}
	r = rae.expect(http.StatusAccepted, "POST", path, body, &pending)
	if pending.Pending.State != "pending" || strings.Contains(string(r.body), "123456") {
		t.Fatalf("the two-person read answered %s", r.body)
	}
	// The requester cannot decide it, a technician cannot, and an approver needs a step-up of their own.
	wantStatus(t, rae.do("POST", "/api/v1/keystore/requests/"+pending.Pending.ID+"/approve", nil), http.StatusForbidden, "")
	wantStatus(t, aps[0].c.do("POST", "/api/v1/keystore/requests/"+pending.Pending.ID+"/approve", nil), http.StatusUnauthorized, "step_up_required")
	aps[0].c.expect(http.StatusOK, "POST", "/api/v1/auth/step-up/totp", map[string]string{"code": code(t, aps[0].secret, time.Now().Add(30*time.Second))}, nil)
	var listed struct {
		Requests []struct {
			ID        string `json:"id"`
			CanDecide bool   `json:"canDecide"`
		} `json:"requests"`
	}
	aps[0].c.expect(http.StatusOK, "GET", "/api/v1/keystore/requests", nil, &listed)
	if len(listed.Requests) != 1 || !listed.Requests[0].CanDecide {
		t.Fatalf("approver's list: %+v", listed)
	}
	var decided struct {
		State string `json:"state"`
	}
	aps[0].c.expect(http.StatusOK, "POST", "/api/v1/keystore/requests/"+pending.Pending.ID+"/approve", nil, &decided)
	if decided.State != "approved" {
		t.Fatalf("approve: %+v", decided)
	}
	used := map[string]any{"volume": vol, "protector": prot, "requestId": pending.Pending.ID}
	r = rae.expect(http.StatusOK, "POST", path, used, nil)
	if got := strings.TrimSpace(string(r.body)); got != `{"key":"`+escrowTestPassword+`"}` {
		t.Fatalf("the approved read answered %q", got)
	}
	// Once only.
	wantStatus(t, rae.do("POST", path, used), http.StatusConflict, "")
	// A second request is refused by the other approver.
	rae.expect(http.StatusAccepted, "POST", path, body, &pending)
	aps[1].c.expect(http.StatusOK, "POST", "/api/v1/auth/step-up/totp", map[string]string{"code": code(t, aps[1].secret, time.Now().Add(30*time.Second))}, nil)
	aps[1].c.expect(http.StatusOK, "POST", "/api/v1/keystore/requests/"+pending.Pending.ID+"/deny", nil, &decided)
	if decided.State != "denied" {
		t.Fatalf("deny: %+v", decided)
	}
	wantStatus(t, rae.do("POST", path, map[string]any{"volume": vol, "protector": prot, "requestId": pending.Pending.ID}), http.StatusConflict, "")
}

// stubLUKS stands in for cryptsetup, which the real-volume tests (scripts/ci/luks-test.sh) exercise: it hands the
// agent a volume it can unlock, and keeps the passphrase the agent gave the slot so that the test can read it back
// through the console and compare.
type stubLUKS struct {
	vol  string
	slot escrow.LUKSSlot
	pass []byte
}

func (s *stubLUKS) Volumes(context.Context) ([]escrow.LUKSVolume, error) {
	v := escrow.LUKSVolume{UUID: s.vol, Mount: "/", Version: 2, State: agentproto.LUKSEscrowable}
	if s.slot.TokenID != "" {
		v.Slots = []escrow.LUKSSlot{s.slot}
	}
	return []escrow.LUKSVolume{v}, nil
}

func (s *stubLUKS) AddSlot(_ context.Context, _ string, pass []byte) (escrow.LUKSSlot, error) {
	s.pass = append([]byte(nil), pass...)
	s.slot = escrow.LUKSSlot{TokenID: "0a0a0a0a-0000-4000-8000-000000000001", Hash: strings.Repeat("ab", 32)}
	return s.slot, nil
}

func (s *stubLUKS) RemoveSlot(context.Context, string, string) error { return nil }

// TestLUKSEscrowEndToEnd is ADR-0081 slice 3 through the real server: a Linux agent gets the signed key, reports a
// LUKS volume it can unlock, escrows the passphrase it put in a key slot of its own, the keystore verifies it, the
// console shows the volume, and a person with the add-on reads the very passphrase back, once and audited.
func TestLUKSEscrowEndToEnd(t *testing.T) {
	sock := escrowKeystore(t)
	ctx := context.Background()
	h := newHarnessWith(t, false, func(c *config.Config) { c.KeystoreSocket = sock })
	admin, adminTOTP := setUp(t, h)
	acme := orgID(t, admin, "Acme")
	var hq idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/sites", map[string]string{"name": "HQ", "timezone": "UTC"}, &hq)
	var token struct {
		Secret string `json:"secret"`
	}
	admin.expect(http.StatusCreated, "POST", "/api/v1/sites/"+hq.ID+"/enrollment-tokens", map[string]any{"name": "Linux", "expiresInDays": 1}, &token)

	ac := h.agentClient()
	key := newKey(t)
	linux := agentproto.Facts{Hostname: "lx-01", OS: "Debian GNU/Linux 12", Platform: "linux", Arch: "amd64", AgentVersion: "1.2.3-test"}
	enr, err := ac.Enroll(ctx, token.Secret, key.Public().(ed25519.PublicKey), linux)
	if err != nil {
		t.Fatal(err)
	}
	ac.SetIdentity(enr.DeviceID, key)
	jobKey, err := agentproto.DecodeKey(enr.JobKey)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := ac.Heartbeat(ctx, agentproto.HeartbeatRequest{Facts: linux, Caps: []string{agentproto.CapEscrow}})
	if err != nil || resp.Escrow == nil {
		t.Fatalf("a Linux agent got no escrow key: %+v %v", resp.Escrow, err)
	}
	store, _, err := state.Open(host.Paths{Root: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(store.Dir(), 0o700); err != nil {
		t.Fatal(err)
	}
	luksVol := "6c4a9e2a-1111-4222-8333-444455556666"
	l := &stubLUKS{vol: luksVol}
	// Opt-in: with the switch off the agent reports the volume and adds nothing.
	agentOff := &escrow.Agent{DeviceID: enr.DeviceID, Key: func() ed25519.PublicKey { return jobKey }, Reader: stubNoBitLocker{}, LUKS: l,
		Server: ac, Store: store, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	agentOff.Answered(resp.Escrow)
	agentOff.Sync(ctx)
	if l.slot.TokenID != "" {
		t.Fatal("the agent added a key slot with LUKS escrow off")
	}
	admin.expect(http.StatusOK, "POST", "/api/v1/auth/step-up/totp", map[string]string{"code": code(t, adminTOTP, time.Now().Add(30*time.Second))}, nil)
	admin.expect(http.StatusOK, "PUT", "/api/v1/organizations/"+acme+"/keystore-settings", map[string]any{"luksEscrow": true}, nil)
	agent := &escrow.Agent{DeviceID: enr.DeviceID, Key: func() ed25519.PublicKey { return jobKey }, Reader: stubNoBitLocker{}, LUKS: l,
		Server: ac, Store: store, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	agent.Answered(resp.Escrow)
	agent.Sync(ctx) // reports the volume, learns it needs a key, makes the slot and escrows
	if l.slot.TokenID == "" {
		t.Fatal("the agent made no key slot")
	}

	var esc struct {
		Applicable bool `json:"applicable"`
		Volumes    []struct {
			Kind       string `json:"kind"`
			State      string `json:"state"`
			Protectors []struct {
				ID    string `json:"id"`
				State string `json:"state"`
			} `json:"protectors"`
		} `json:"volumes"`
	}
	r := admin.do("GET", "/api/v1/devices/"+enr.DeviceID+"/escrow", nil)
	admin.expect(http.StatusOK, "GET", "/api/v1/devices/"+enr.DeviceID+"/escrow", nil, &esc)
	if !esc.Applicable || len(esc.Volumes) != 1 || esc.Volumes[0].Kind != "luks" || esc.Volumes[0].State != "verified" ||
		len(esc.Volumes[0].Protectors) != 1 || esc.Volumes[0].Protectors[0].ID != l.slot.TokenID {
		t.Fatalf("console: %s", r.body)
	}
	if strings.Contains(string(r.body), string(l.pass)) {
		t.Fatal("the console response holds the passphrase")
	}

	// A person with the add-on reads it back, through the audited route.
	invite(t, h, admin, "rae@acme.example", []map[string]any{{"role": "technician", "organizationId": acme}, {"role": "key_reader", "organizationId": acme}})
	rae := h.client()
	secret := rae.signIn("rae@acme.example", "a long and unusual passphrase", "")
	rae.expect(http.StatusOK, "POST", "/api/v1/auth/step-up/totp", map[string]string{"code": code(t, secret, time.Now().Add(30*time.Second))}, nil)
	got := rae.do("POST", "/api/v1/devices/"+enr.DeviceID+"/escrow/read", map[string]any{
		"volume": luksVol, "protector": l.slot.TokenID, "reason": "The server will not boot after a kernel update"})
	wantStatus(t, got, http.StatusOK, "")
	var read struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(got.body, &read); err != nil || read.Key != string(l.pass) {
		t.Fatalf("the key read is not the passphrase the agent put in the slot: %v", err)
	}
	if cc := got.header.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q", cc)
	}
	if strings.Contains(h.logs.String(), string(l.pass)) {
		t.Fatal("the passphrase is in the server's log")
	}
	var notices struct {
		Notices []struct{ Reason string } `json:"notices"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/keystore/notices", nil, &notices)
	if len(notices.Notices) != 1 {
		t.Fatalf("notices: %+v", notices)
	}
}

// stubNoBitLocker is the BitLocker reader of a Linux computer: there is none.
type stubNoBitLocker struct{}

func (stubNoBitLocker) Volumes(context.Context) ([]escrow.Volume, error) {
	return nil, escrow.ErrUnsupported
}

func (stubNoBitLocker) RecoveryPassword(context.Context, string, string) ([]byte, error) {
	return nil, escrow.ErrUnsupported
}
