//go:build integration

package app_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// TestInventoryAPI sends metrics and an inventory through the agent API and
// reads them through the console API (ADR-0018).
func TestInventoryAPI(t *testing.T) {
	h := newHarness(t, false)
	admin, _ := setUp(t, h)
	acme := orgID(t, admin, "Acme")
	var hq idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/sites", map[string]string{"name": "HQ", "timezone": "UTC"}, &hq)
	var token struct {
		Secret string `json:"secret"`
	}
	admin.expect(http.StatusCreated, "POST", "/api/v1/sites/"+hq.ID+"/enrollment-tokens", map[string]any{"name": "Inventory", "expiresInDays": 1}, &token)
	ctx := context.Background()
	ac := h.agentClient()
	key := newKey(t)
	enr, err := ac.Enroll(ctx, token.Secret, key.Public().(ed25519.PublicKey), facts("inv-01"))
	if err != nil {
		t.Fatal(err)
	}
	ac.SetIdentity(enr.DeviceID, key)
	device := "/api/v1/devices/" + enr.DeviceID

	// Before the agent reports anything.
	var view struct {
		Inventory *struct {
			OS           agentproto.OSInfo `json:"os"`
			PackageCount int               `json:"packageCount"`
		} `json:"inventory"`
		Metrics *struct {
			CPUPercent  float64                 `json:"cpuPercent"`
			Filesystems []agentproto.Filesystem `json:"filesystems"`
		} `json:"metrics"`
	}
	admin.expect(http.StatusOK, "GET", device+"/inventory", nil, &view)
	if view.Inventory != nil || view.Metrics != nil {
		t.Errorf("before reporting %+v", view)
	}

	// A heartbeat with metrics; the server holds no inventory yet.
	hb, err := ac.Heartbeat(ctx, agentproto.HeartbeatRequest{Facts: facts("inv-01"), Metrics: &agentproto.Metrics{
		CPUPercent: 42, MemoryTotal: 8 << 30, MemoryUsed: 2 << 30,
		Filesystems: []agentproto.Filesystem{{Mount: "/", Device: "/dev/sda1", Type: "ext4", TotalBytes: 100 << 30, UsedBytes: 91 << 30}},
	}})
	if err != nil || hb.InventoryHash != "" {
		t.Fatalf("heartbeat %+v %v", hb, err)
	}
	inv := agentproto.Inventory{
		OS:             agentproto.OSInfo{Name: "Debian GNU/Linux 13 (trixie)", Kernel: "6.12.0"},
		PackageManager: "dpkg",
		Packages:       []agentproto.Package{{Name: "openssl", Version: "3.5.1", Arch: "amd64"}, {Name: "bash", Version: "5.2.37", Arch: "amd64"}},
	}
	body, _ := json.Marshal(inv)
	hash, err := ac.Inventory(ctx, body)
	if err != nil || hash != inv.Hash() {
		t.Fatalf("upload %q %v", hash, err)
	}
	if hb, err := ac.Heartbeat(ctx, agentproto.HeartbeatRequest{Facts: facts("inv-01")}); err != nil || hb.InventoryHash != inv.Hash() {
		t.Errorf("hash after upload %+v %v", hb, err)
	}

	admin.expect(http.StatusOK, "GET", device+"/inventory", nil, &view)
	if view.Inventory == nil || view.Inventory.OS.Kernel != "6.12.0" || view.Inventory.PackageCount != 2 ||
		view.Metrics == nil || view.Metrics.CPUPercent != 42 || len(view.Metrics.Filesystems) != 1 {
		t.Errorf("inventory %+v %+v", view.Inventory, view.Metrics)
	}
	var sw struct{ Items []agentproto.Package }
	admin.expect(http.StatusOK, "GET", device+"/software", nil, &sw)
	if len(sw.Items) != 2 || sw.Items[0].Name != "bash" {
		t.Errorf("software %+v", sw.Items)
	}
	var hist struct {
		Range         string `json:"range"`
		BucketSeconds int    `json:"bucketSeconds"`
		Samples       []struct {
			CPUPercent  float64 `json:"cpuPercent"`
			DiskPercent float64 `json:"diskPercent"`
		} `json:"samples"`
	}
	admin.expect(http.StatusOK, "GET", device+"/metrics", nil, &hist)
	if hist.Range != "24h" || hist.BucketSeconds != 300 || len(hist.Samples) != 1 || hist.Samples[0].CPUPercent != 42 || hist.Samples[0].DiskPercent != 91 {
		t.Errorf("history %+v", hist)
	}
	admin.expect(http.StatusOK, "GET", device+"/metrics?range=1h", nil, &hist)
	if hist.BucketSeconds != 60 {
		t.Errorf("1h history %+v", hist)
	}
	wantStatus(t, admin.do("GET", device+"/metrics?range=forever", nil), http.StatusUnprocessableEntity, "validation_failed")

	var found struct {
		Items []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Devices int    `json:"devices"`
		} `json:"items"`
		Truncated bool `json:"truncated"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/software?q=SSL&organizationId="+acme, nil, &found)
	if len(found.Items) != 1 || found.Items[0].Devices != 1 || found.Truncated {
		t.Errorf("search %+v", found)
	}
	wantStatus(t, admin.do("GET", "/api/v1/software?siteId=nope", nil), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("GET", "/api/v1/software?organizationId=nope", nil), http.StatusUnprocessableEntity, "validation_failed")
	var holders struct {
		Items []struct {
			DeviceName string `json:"deviceName"`
			SiteName   string `json:"siteName"`
		} `json:"items"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/software/devices?name=openssl&version="+url.QueryEscape("3.5.1"), nil, &holders)
	if len(holders.Items) != 1 || holders.Items[0].DeviceName != "inv-01" || holders.Items[0].SiteName != "HQ" {
		t.Errorf("devices %+v", holders)
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/software/devices?name=openssl&version=0.9", nil, &holders)
	if len(holders.Items) != 0 {
		t.Errorf("other version %+v", holders)
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/software/devices?name=openssl&organizationId="+acme+"&siteId="+hq.ID, nil, &holders)
	if len(holders.Items) != 1 {
		t.Errorf("filtered devices %+v", holders)
	}
	wantStatus(t, admin.do("GET", "/api/v1/software/devices", nil), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("GET", "/api/v1/software/devices?name=openssl&organizationId=nope", nil), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("GET", "/api/v1/software/devices?name=openssl&siteId=nope", nil), http.StatusUnprocessableEntity, "validation_failed")

	// Unknown devices, and requests the agent API refuses.
	for _, p := range []string{"/inventory", "/software", "/metrics"} {
		wantStatus(t, admin.do("GET", "/api/v1/devices/00000000-0000-4000-8000-000000000000"+p, nil), http.StatusNotFound, "not_found")
		wantStatus(t, admin.do("GET", "/api/v1/devices/nope"+p, nil), http.StatusNotFound, "not_found")
	}
	if _, err := ac.Inventory(ctx, []byte("[1,2")); err == nil {
		t.Error("junk inventory accepted")
	}
	big := bytes.Repeat([]byte(" "), agentproto.MaxInventoryBody+1)
	if _, err := ac.Inventory(ctx, big); err == nil {
		t.Error("oversized inventory accepted")
	}
	r := h.raw("POST", agentproto.PathInventory, body, "")
	wantStatus(t, r, http.StatusUnauthorized, "agent_unauthorized")

	// Signed out, nothing is readable.
	wantStatus(t, h.client().do("GET", device+"/inventory", nil), http.StatusUnauthorized, "")
}
