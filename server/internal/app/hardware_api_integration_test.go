//go:build integration

package app_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// TestHardwareAPI sends hardware reports through the agent API, signed as
// agents sign them, and reads disk health through the console API
// (ADR-0065).
func TestHardwareAPI(t *testing.T) {
	h := newHarness(t, false)
	admin, _ := setUp(t, h)
	acme := orgID(t, admin, "Acme")
	var hq idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/sites", map[string]string{"name": "HQ", "timezone": "UTC"}, &hq)
	var token struct {
		Secret string `json:"secret"`
	}
	admin.expect(http.StatusCreated, "POST", "/api/v1/sites/"+hq.ID+"/enrollment-tokens", map[string]any{"name": "Disks", "expiresInDays": 1}, &token)
	ctx := context.Background()
	ac := h.agentClient()
	key := newKey(t)
	enr, err := ac.Enroll(ctx, token.Secret, key.Public().(ed25519.PublicKey), facts("hw-01"))
	if err != nil {
		t.Fatal(err)
	}
	device := "/api/v1/devices/" + enr.DeviceID
	sign := func(b []byte) string {
		s, err := agentproto.Sign(key, enr.DeviceID, "POST", agentproto.PathHardware, b, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	send := func(b []byte, contentType string) response {
		t.Helper()
		req, _ := http.NewRequest("POST", h.srv.URL+agentproto.PathHardware, bytes.NewReader(b))
		req.Host = "rmm.test"
		req.Header.Set("Content-Type", contentType)
		req.Header.Set("Authorization", sign(b))
		resp, err := h.srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(resp.Body)
		return response{status: resp.StatusCode, body: buf.Bytes(), header: resp.Header}
	}

	type diskView struct {
		Key, Name, State, Reason string
	}
	var disks struct{ Items []diskView }
	type deviceRow struct {
		ID         string `json:"id"`
		DiskHealth *struct {
			Label  string         `json:"label"`
			States map[string]int `json:"states"`
		} `json:"diskHealth"`
	}
	var list struct{ Items []deviceRow }
	listed := func(c *client, filter string) []deviceRow {
		t.Helper()
		c.expect(http.StatusOK, "GET", "/api/v1/devices?diskHealth="+filter, nil, &list)
		return list.Items
	}

	// Before any report: no disks, Not reported.
	admin.expect(http.StatusOK, "GET", device+"/disks", nil, &disks)
	if disks.Items == nil || len(disks.Items) != 0 {
		t.Errorf("before any report %+v", disks.Items)
	}
	if rows := listed(admin, "not_reported"); len(rows) != 1 || rows[0].DiskHealth != nil {
		t.Errorf("not reported %+v", rows)
	}

	read := agentproto.Read
	notKept := agentproto.NotRead(agentproto.FactUnsupported, agentproto.ReasonNotKept)
	report := agentproto.HardwareReport{Disks: []agentproto.DiskHealth{
		{
			Name: "nvme0n1", Model: "Example NVMe 1TB", Serial: "N1", State: agentproto.FactRead, Protocol: agentproto.ProtocolNVMe,
			Route: "nvme", ReadAt: time.Now(), CriticalWarning: read(1 << 2), SMARTStatus: notKept, Thresholds: notKept,
			Temperature: read(41), TemperatureLimit: read(70), Wear: read(12), AvailableSpare: read(100), AvailableSpareThreshold: read(10),
			MediaErrors: read(0), ReallocatedSectors: notKept, PendingSectors: notKept, UncorrectableSectors: notKept,
			DriveErrors: read(2), PowerOnHours: read(5000), DataWritten: read(90000), UnsafeShutdowns: read(11), PowerMode: notKept,
		},
		{Name: "sdb", Model: "Example USB 2TB", Serial: "U1", State: agentproto.FactUnavailable, Reason: agentproto.ReasonUSBBridge},
	}}
	body, _ := json.Marshal(report)
	wantStatus(t, send(body, "application/json"), http.StatusNoContent, "")

	admin.expect(http.StatusOK, "GET", device+"/disks", nil, &disks)
	if len(disks.Items) != 2 || disks.Items[0].Name != "nvme0n1" || disks.Items[0].State != "failing" ||
		disks.Items[1].State != "unavailable" || disks.Items[1].Reason != agentproto.ReasonUSBBridge {
		t.Fatalf("disks %+v", disks.Items)
	}
	var detail struct {
		Name, State string
		History     []struct{ State string }
		Alerts      []any
	}
	admin.expect(http.StatusOK, "GET", device+"/disks/"+disks.Items[0].Key, nil, &detail)
	if detail.Name != "nvme0n1" || detail.State != "failing" || len(detail.History) != 1 || detail.History[0].State != "failing" || detail.Alerts == nil {
		t.Errorf("disk %+v", detail)
	}
	rows := listed(admin, "failing")
	if len(rows) != 1 || rows[0].DiskHealth == nil || rows[0].DiskHealth.Label != "failing" || rows[0].DiskHealth.States["unavailable"] != 1 {
		t.Errorf("failing devices %+v", rows)
	}
	if rows := listed(admin, "unavailable"); len(rows) != 1 {
		t.Errorf("devices with an unavailable disk %+v", rows)
	}
	if rows := listed(admin, "healthy"); len(rows) != 0 {
		t.Errorf("healthy devices %+v", rows)
	}
	wantStatus(t, admin.do("GET", "/api/v1/devices?diskHealth=reported", nil), http.StatusUnprocessableEntity, "validation_failed")

	// Read-Only users of the organization see disks; others do not.
	invite(t, h, admin, "rory@acme.example", []map[string]any{{"role": "read_only", "organizationId": acme}})
	viewer := h.client()
	viewer.signIn("rory@acme.example", "a long and unusual passphrase", "")
	viewer.expect(http.StatusOK, "GET", device+"/disks", nil, &disks)
	if len(disks.Items) != 2 {
		t.Errorf("read-only %+v", disks.Items)
	}
	viewer.expect(http.StatusOK, "GET", device+"/disks/"+disks.Items[0].Key, nil, &detail)
	var other idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations", map[string]string{"name": "Other"}, &other)
	invite(t, h, admin, "olga@other.example", []map[string]any{{"role": "org_admin", "organizationId": other.ID}})
	stranger := h.client()
	stranger.signIn("olga@other.example", "a long and unusual passphrase", "")
	wantStatus(t, stranger.do("GET", device+"/disks", nil), http.StatusNotFound, "not_found")
	wantStatus(t, stranger.do("GET", device+"/disks/"+disks.Items[0].Key, nil), http.StatusNotFound, "not_found")
	if rows := listed(stranger, "failing"); len(rows) != 0 {
		t.Errorf("another organization's failing devices %+v", rows)
	}
	wantStatus(t, admin.do("GET", device+"/disks/"+"00000000000000000000000000000000", nil), http.StatusNotFound, "not_found")
	wantStatus(t, admin.do("GET", "/api/v1/devices/00000000-0000-4000-8000-000000000000/disks", nil), http.StatusNotFound, "not_found")
	wantStatus(t, admin.do("GET", "/api/v1/devices/nope/disks", nil), http.StatusNotFound, "not_found")
	wantStatus(t, h.client().do("GET", device+"/disks", nil), http.StatusUnauthorized, "")

	// Reports the agent API refuses.
	wantStatus(t, send(body, "text/plain"), http.StatusUnsupportedMediaType, "unsupported_media_type")
	wantStatus(t, send([]byte(`{"disks":[1]}`), "application/json"), http.StatusBadRequest, "hardware_invalid")
	big := bytes.Repeat([]byte(" "), agentproto.MaxHardwareBody+1)
	wantStatus(t, send(big, "application/json"), http.StatusRequestEntityTooLarge, "")
	wantStatus(t, h.raw("POST", agentproto.PathHardware, body, ""), http.StatusUnauthorized, "agent_unauthorized")

	// One report in 10 minutes, with bursts of 6: the first report, the
	// junk one and the 415 spent three (a token is spent once the signature
	// is verified; the oversized one was refused before).
	sent := 3
	for ; sent < 20; sent++ {
		r := send(body, "application/json")
		if r.status == http.StatusTooManyRequests {
			wantStatus(t, r, http.StatusTooManyRequests, "rate_limited")
			break
		}
		wantStatus(t, r, http.StatusNoContent, "")
	}
	if sent != 6 {
		t.Errorf("limited after %d reports, want 6", sent)
	}
}
