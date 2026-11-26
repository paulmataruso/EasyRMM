//go:build integration

package app_test

import (
	"context"
	"crypto/ed25519"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/agent/escrow"
	"github.com/paulmataruso/easyrmm/agent/host"
	"github.com/paulmataruso/easyrmm/agent/state"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/config"
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
func TestRecoveryKeyEscrowEndToEnd(t *testing.T) {
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

	h := newHarnessWith(t, false, func(c *config.Config) { c.KeystoreSocket = sock })
	admin, _ := setUp(t, h)
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

	// The agent route is signed, limited and bound to the device: a record
	// for a protector the device never reported is refused with 409.
	_, err = ac.EscrowUpload(ctx, agentproto.EscrowRecord{VolumeID: vol, ProtectorID: "{DDDD}", Kind: agentproto.EscrowBitLocker, KeyID: "00000000-0000-0000-0000-000000000000",
		Enc: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Ciphertext: "AAAA", Fingerprint: strings.Repeat("0", 32)})
	if err == nil {
		t.Error("an unreported protector was accepted")
	}
}
