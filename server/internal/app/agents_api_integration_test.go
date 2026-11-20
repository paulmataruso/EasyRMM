//go:build integration

package app_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	agentclient "github.com/paulmataruso/easyrmm/agent/client"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/config"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// agentClient is the real agent's client, connected to the test server as
// https://rmm.test.
func (h *harness) agentClient() *agentclient.Client {
	h.t.Helper()
	tr := h.srv.Client().Transport.(*http.Transport).Clone()
	addr := h.srv.Listener.Addr().String()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	// The test certificate names example.com; the Host stays rmm.test.
	tr.TLSClientConfig = &tls.Config{RootCAs: tr.TLSClientConfig.RootCAs, ServerName: "example.com", MinVersion: tls.VersionTLS12}
	c, err := agentclient.New(agentclient.Options{Server: publicOrigin, Version: "1.2.3-test", Transport: tr})
	if err != nil {
		h.t.Fatal(err)
	}
	return c
}

// raw sends an agent request without a browser's headers.
func (h *harness) raw(method, target string, body []byte, auth string) response {
	h.t.Helper()
	req, _ := http.NewRequest(method, h.srv.URL+target, bytes.NewReader(body))
	req.Host = "rmm.test"
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return response{status: resp.StatusCode, body: buf.Bytes(), header: resp.Header}
}

type tokenView struct {
	ID        string  `json:"id"`
	SiteID    string  `json:"siteId"`
	Name      string  `json:"name"`
	Status    string  `json:"status"`
	Uses      int     `json:"uses"`
	MaxUses   *int    `json:"maxUses"`
	RevokedAt *string `json:"revokedAt"`
	CreatedBy string  `json:"createdByName"`
}

type agentDevice struct {
	deviceView
	Online        bool   `json:"online"`
	Platform      string `json:"platform"`
	Hostname      string `json:"hostname"`
	OSDescription string `json:"osDescription"`
	Agent         *struct {
		Version    string  `json:"version"`
		Arch       string  `json:"arch"`
		Online     bool    `json:"online"`
		LastSeenAt *string `json:"lastSeenAt"`
	} `json:"agent"`
}

func facts(host string) agentproto.Facts {
	return agentproto.Facts{Hostname: host, OS: "Debian GNU/Linux 13 (trixie)", Platform: "linux", Arch: "amd64", AgentVersion: "1.2.3-test"}
}

func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestAgentEnrollmentAPI(t *testing.T) {
	builds := t.TempDir()
	for name, content := range map[string]string{
		"easyrmm-agent-linux-amd64":       "linux build",
		"easyrmm-agent-windows-amd64.exe": "windows build",
		"easyrmm-agent-windows-arm64":     "missing .exe: ignored",
		"README":                          "ignored",
	} {
		if err := os.WriteFile(filepath.Join(builds, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	h := newHarnessWith(t, false, func(c *config.Config) { c.AgentDir = builds })
	admin, _ := setUp(t, h)
	acme := orgID(t, admin, "Acme")
	var hq, branch idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/sites", map[string]string{"name": "HQ", "timezone": "UTC"}, &hq)
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/sites", map[string]string{"name": "Branch", "timezone": "UTC"}, &branch)
	var branchGroup idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/sites/"+branch.ID+"/device-groups", map[string]string{"name": "Kiosks"}, &branchGroup)

	// --- Tokens -----------------------------------------------------------
	tokens := "/api/v1/sites/" + hq.ID + "/enrollment-tokens"
	wantStatus(t, admin.do("POST", tokens, map[string]any{"name": " ", "expiresInDays": 0}), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("POST", tokens, map[string]any{"name": "x", "expiresInDays": 7, "maxUses": 0}), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("POST", tokens, map[string]any{"name": "x", "expiresInDays": 91}), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("POST", tokens, map[string]any{"name": "x", "expiresInDays": 7, "deviceGroupId": branchGroup.ID}), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("POST", "/api/v1/sites/"+uuid.NewString()+"/enrollment-tokens", map[string]any{"name": "x", "expiresInDays": 7}), http.StatusNotFound, "not_found")

	wantStatus(t, admin.do("POST", "/api/v1/sites/nope/enrollment-tokens", map[string]any{"name": "x", "expiresInDays": 7}), http.StatusNotFound, "not_found")
	wantStatus(t, admin.do("POST", tokens, "not an object"), http.StatusBadRequest, "")
	wantStatus(t, admin.do("GET", "/api/v1/enrollment-tokens?organizationId=nope", nil), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("GET", "/api/v1/enrollment-tokens?siteId=nope", nil), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("GET", "/api/v1/enrollment-tokens/nope", nil), http.StatusNotFound, "not_found")
	wantStatus(t, admin.do("GET", "/api/v1/enrollment-tokens/"+uuid.NewString(), nil), http.StatusNotFound, "not_found")
	wantStatus(t, admin.do("POST", "/api/v1/enrollment-tokens/nope/revoke", nil), http.StatusNotFound, "not_found")
	wantStatus(t, admin.do("POST", "/api/v1/enrollment-tokens/"+uuid.NewString()+"/revoke", nil), http.StatusNotFound, "not_found")
	wantStatus(t, h.client().do("GET", "/api/v1/enrollment-tokens", nil), http.StatusUnauthorized, "")

	var created struct {
		Token     tokenView `json:"token"`
		Secret    string    `json:"secret"`
		ServerURL string    `json:"serverUrl"`
	}
	r := admin.expect(http.StatusCreated, "POST", tokens, map[string]any{"name": "Office rollout", "expiresInDays": 7, "maxUses": 2}, &created)
	if !strings.HasPrefix(created.Secret, "ert_") || len(created.Secret) != 47 || created.ServerURL != publicOrigin ||
		created.Token.Status != "active" || created.Token.CreatedBy != "Ada Admin" || r.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("created = %+v", created)
	}
	var list struct{ Items []json.RawMessage }
	admin.expect(http.StatusOK, "GET", "/api/v1/enrollment-tokens?siteId="+hq.ID+"&status=active", nil, &list)
	if len(list.Items) != 1 || bytes.Contains(list.Items[0], []byte("ert_")) || bytes.Contains(list.Items[0], []byte("secret")) {
		t.Fatalf("token list = %s", list.Items)
	}

	// A technician cannot manage tokens; a site administrator elsewhere
	// does not see these.
	invite(t, h, admin, "tess@acme.example", []map[string]any{{"role": "technician", "organizationId": acme}})
	tech := h.client()
	tech.signIn("tess@acme.example", "a long and unusual passphrase", "")
	wantStatus(t, tech.do("POST", tokens, map[string]any{"name": "x", "expiresInDays": 7}), http.StatusForbidden, "forbidden")
	tech.expect(http.StatusOK, "GET", "/api/v1/enrollment-tokens", nil, &list)
	if len(list.Items) != 0 {
		t.Errorf("technician sees %d tokens", len(list.Items))
	}
	wantStatus(t, tech.do("POST", "/api/v1/enrollment-tokens/"+created.Token.ID+"/revoke", nil), http.StatusNotFound, "not_found")

	// --- Enrollment -------------------------------------------------------
	ctx := context.Background()
	ac := h.agentClient()
	key := newKey(t)
	pub := key.Public().(ed25519.PublicKey)
	if _, err := ac.Enroll(ctx, "ert_not-a-real-token", pub, facts("web-01")); agentclient.Code(err) != "token_invalid" {
		t.Fatalf("unknown token: %v", err)
	}
	if _, err := ac.Enroll(ctx, created.Secret, pub[:5], facts("web-01")); agentclient.Code(err) != "validation_failed" {
		t.Fatalf("short key: %v", err)
	}
	if _, err := ac.Enroll(ctx, created.Secret, pub, facts(" \x00 ")); agentclient.Code(err) != "validation_failed" {
		t.Fatalf("empty hostname: %v", err)
	}
	enr, err := ac.Enroll(ctx, created.Secret, pub, facts("web-01\x07"))
	if err != nil {
		t.Fatal(err)
	}
	if enr.HeartbeatSeconds != 60 || enr.MeshAgent.Available {
		t.Errorf("enroll response = %+v", enr)
	}
	if _, err := ac.Enroll(ctx, created.Secret, pub, facts("web-01")); agentclient.Code(err) != "key_in_use" {
		t.Fatalf("same key again: %v", err)
	}

	var dev agentDevice
	admin.expect(http.StatusOK, "GET", "/api/v1/devices/"+enr.DeviceID, nil, &dev)
	if dev.Name != "web-01" || dev.SiteName != "HQ" || dev.Platform != "linux" || !dev.Online || dev.RemoteAgent || dev.CanTerminal ||
		dev.Agent == nil || !dev.Agent.Online || dev.Agent.Version != "1.2.3-test" || dev.Agent.Arch != "amd64" {
		t.Fatalf("enrolled device = %+v %+v", dev, dev.Agent)
	}

	// --- Signed requests --------------------------------------------------
	ac.SetIdentity(enr.DeviceID, key)
	f := facts("web-01")
	f.OS = "Debian GNU/Linux 13.1 (trixie)"
	hb, err := ac.Heartbeat(ctx, agentproto.HeartbeatRequest{Facts: f})
	if err != nil || hb.HeartbeatSeconds != 60 || hb.MeshAgent.Available {
		t.Fatalf("heartbeat = %+v, %v", hb, err)
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/devices/"+enr.DeviceID, nil, &dev)
	if dev.OSDescription != "Debian GNU/Linux 13.1 (trixie)" {
		t.Errorf("os after heartbeat = %q", dev.OSDescription)
	}
	// A renamed host is renamed in EasyRMM too.
	if _, err := ac.Heartbeat(ctx, agentproto.HeartbeatRequest{Facts: facts("web-01-new")}); err != nil {
		t.Fatal(err)
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/devices/"+enr.DeviceID, nil, &dev)
	if dev.Name != "web-01-new" || dev.Hostname != "web-01-new" {
		t.Errorf("after a hostname change: %q / %q", dev.Name, dev.Hostname)
	}
	// MeshAgent is not offered without remote access.
	if err := ac.MeshAgent(ctx, "linux", "amd64", &bytes.Buffer{}); agentclient.Code(err) != "meshagent_unavailable" {
		t.Errorf("MeshAgent download = %v", err)
	}
	if _, err := ac.MeshSettings(ctx); agentclient.Code(err) != "meshagent_unavailable" {
		t.Errorf("MeshAgent settings = %v", err)
	}

	body, _ := json.Marshal(agentproto.HeartbeatRequest{Facts: facts("web-01-new")})
	sign := func(k ed25519.PrivateKey, device string, at time.Time) string {
		s, err := agentproto.Sign(k, device, "POST", agentproto.PathHeartbeat, body, at)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	good := sign(key, enr.DeviceID, time.Now())
	wantStatus(t, h.raw("POST", agentproto.PathHeartbeat, body, good), http.StatusOK, "")
	wantStatus(t, h.raw("POST", agentproto.PathHeartbeat, body, good), http.StatusUnauthorized, "replayed")
	wantStatus(t, h.raw("POST", agentproto.PathHeartbeat, body, sign(key, enr.DeviceID, time.Now().Add(-10*time.Minute))), http.StatusUnauthorized, "clock_skew")
	wantStatus(t, h.raw("POST", agentproto.PathHeartbeat, body, sign(newKey(t), enr.DeviceID, time.Now())), http.StatusUnauthorized, "agent_unauthorized")
	wantStatus(t, h.raw("POST", agentproto.PathHeartbeat, body, sign(key, uuid.NewString(), time.Now())), http.StatusUnauthorized, "device_unknown")
	wantStatus(t, h.raw("POST", agentproto.PathHeartbeat, body, sign(key, "not-a-uuid", time.Now())), http.StatusUnauthorized, "agent_unauthorized")
	wantStatus(t, h.raw("POST", agentproto.PathHeartbeat, body, "Bearer x"), http.StatusUnauthorized, "agent_unauthorized")
	wantStatus(t, h.raw("POST", agentproto.PathHeartbeat, []byte(`{"facts":{}}`), sign(key, enr.DeviceID, time.Now())), http.StatusUnauthorized, "agent_unauthorized")
	// The body is part of the signature, and must be the protocol's JSON.
	odd := []byte(`{"facts":{"hostname":"x"},"extra":1}`)
	s, _ := agentproto.Sign(key, enr.DeviceID, "POST", agentproto.PathHeartbeat, odd, time.Now())
	wantStatus(t, h.raw("POST", agentproto.PathHeartbeat, odd, s), http.StatusBadRequest, "bad_request")
	big := bytes.Repeat([]byte("x"), agentproto.MaxBody+1)
	wantStatus(t, h.raw("POST", agentproto.PathHeartbeat, big, good), http.StatusRequestEntityTooLarge, "body_too_large")
	wantStatus(t, h.raw("GET", "/api/agent/v1/nothing", nil, ""), http.StatusNotFound, "not_found")
	wantStatus(t, h.raw("GET", agentproto.PathEnroll, nil, ""), http.StatusNotFound, "not_found")

	// Agents need no Origin or CSRF token; browsers' API calls still do.
	wantStatus(t, h.raw("POST", "/api/v1/auth/logout", nil, ""), http.StatusForbidden, "csrf_failed")

	// --- Token lifecycle ---------------------------------------------------
	second, err := h.agentClient().Enroll(ctx, created.Secret, newKey(t).Public().(ed25519.PublicKey), facts("web-02"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.agentClient().Enroll(ctx, created.Secret, newKey(t).Public().(ed25519.PublicKey), facts("web-03")); agentclient.Code(err) != "token_invalid" {
		t.Fatalf("used-up token: %v", err)
	}
	var tok tokenView
	admin.expect(http.StatusOK, "GET", "/api/v1/enrollment-tokens/"+created.Token.ID, nil, &tok)
	if tok.Status != "used_up" || tok.Uses != 2 {
		t.Errorf("token after two enrollments = %+v", tok)
	}
	var other struct {
		Token  tokenView `json:"token"`
		Secret string    `json:"secret"`
	}
	admin.expect(http.StatusCreated, "POST", tokens, map[string]any{"name": "Unlimited", "expiresInDays": 1}, &other)
	admin.expect(http.StatusOK, "POST", "/api/v1/enrollment-tokens/"+other.Token.ID+"/revoke", nil, &tok)
	if tok.Status != "revoked" || tok.RevokedAt == nil {
		t.Errorf("revoked token = %+v", tok)
	}
	admin.expect(http.StatusOK, "POST", "/api/v1/enrollment-tokens/"+other.Token.ID+"/revoke", nil, &tok) // idempotent
	if _, err := h.agentClient().Enroll(ctx, other.Secret, newKey(t).Public().(ed25519.PublicKey), facts("web-04")); agentclient.Code(err) != "token_invalid" {
		t.Fatalf("revoked token: %v", err)
	}
	admin.expect(http.StatusCreated, "POST", tokens, map[string]any{"name": "Short", "expiresInDays": 1}, &other)
	exec(t, h, `UPDATE enrollment_tokens SET expires_at = now() - interval '1 second' WHERE id = $1`, other.Token.ID)
	if _, err := h.agentClient().Enroll(ctx, other.Secret, newKey(t).Public().(ed25519.PublicKey), facts("web-05")); agentclient.Code(err) != "token_invalid" {
		t.Fatalf("expired token: %v", err)
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/enrollment-tokens?siteId="+hq.ID+"&status=active", nil, &list)
	if len(list.Items) != 0 {
		t.Errorf("active tokens = %s", list.Items)
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/enrollment-tokens?organizationId="+acme, nil, &list)
	if len(list.Items) != 3 {
		t.Errorf("all tokens = %d", len(list.Items))
	}

	// --- Online state -----------------------------------------------------
	exec(t, h, `UPDATE devices SET agent_last_seen_at = now() - interval '4 minutes' WHERE id = $1`, second.DeviceID)
	var devs struct{ Items []agentDevice }
	admin.expect(http.StatusOK, "GET", "/api/v1/devices?status=offline", nil, &devs)
	if len(devs.Items) != 1 || devs.Items[0].ID != second.DeviceID || devs.Items[0].Online || devs.Items[0].Agent.Online {
		t.Errorf("offline devices = %+v", devs.Items)
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/devices?status=online", nil, &devs)
	if len(devs.Items) != 1 || devs.Items[0].ID != enr.DeviceID {
		t.Errorf("online devices = %+v", devs.Items)
	}

	// --- Audit --------------------------------------------------------------
	var audit struct {
		Items []struct {
			Action    string         `json:"action"`
			ActorType string         `json:"actorType"`
			Details   map[string]any `json:"details"`
		} `json:"items"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/audit?deviceId="+enr.DeviceID, nil, &audit)
	if len(audit.Items) != 1 || audit.Items[0].Action != "device.enroll" || audit.Items[0].ActorType != "agent" ||
		audit.Items[0].Details["token"] != "Office rollout" || audit.Items[0].Details["device"] != "web-01" {
		t.Errorf("enrollment audit = %+v", audit.Items)
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/audit?action=enrollment_token.revoke", nil, &audit)
	if len(audit.Items) != 1 {
		t.Errorf("revocation audit = %+v", audit.Items)
	}

	// --- Downloads ------------------------------------------------------------
	var dl struct {
		ServerURL string `json:"serverUrl"`
		Items     []struct {
			OS, Arch, File, SHA256 string
			Size                   int64
		} `json:"items"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/agent-downloads", nil, &dl)
	sum := sha256.Sum256([]byte("linux build"))
	if dl.ServerURL != publicOrigin || len(dl.Items) != 2 || dl.Items[0].File != "easyrmm-agent-linux-amd64" ||
		dl.Items[0].OS != "linux" || dl.Items[0].Size != 11 || dl.Items[0].SHA256 != hex.EncodeToString(sum[:]) || dl.Items[1].OS != "windows" {
		t.Fatalf("downloads = %+v", dl)
	}
	r = h.raw("GET", "/api/agent/v1/download/easyrmm-agent-linux-amd64", nil, "")
	if r.status != http.StatusOK || string(r.body) != "linux build" || r.header.Get("X-Checksum-Sha256") != dl.Items[0].SHA256 {
		t.Errorf("download: %d %q %v", r.status, r.body, r.header)
	}
	r = h.raw("GET", "/api/agent/v1/download/SHA256SUMS", nil, "")
	if !strings.Contains(string(r.body), dl.Items[0].SHA256+"  easyrmm-agent-linux-amd64\n") || strings.Contains(string(r.body), "README") {
		t.Errorf("checksums = %q", r.body)
	}
	for _, bad := range []string{"README", "easyrmm-agent-windows-arm64", "..%2f..%2fetc%2fpasswd", "easyrmm-agent-linux-amd64.sig"} {
		if r := h.raw("GET", "/api/agent/v1/download/"+bad, nil, ""); r.status != http.StatusNotFound {
			t.Errorf("download %s: %d", bad, r.status)
		}
	}
	r = h.raw("GET", "/api/agent/v1/install.sh", nil, "")
	if r.status != http.StatusOK || !strings.HasPrefix(string(r.body), "#!/bin/sh") ||
		!strings.Contains(string(r.body), "SERVER='https://rmm.test'") || !strings.Contains(string(r.body), "--proto '=https'") {
		t.Errorf("installer: %d %.300s", r.status, r.body)
	}
}

func TestAgentDevicesWithoutBuilds(t *testing.T) {
	h := newHarnessWith(t, false, func(c *config.Config) { c.AgentDir = filepath.Join(t.TempDir(), "missing") })
	admin, _ := setUp(t, h)
	var dl struct {
		Items []any `json:"items"`
	}
	r := admin.expect(http.StatusOK, "GET", "/api/v1/agent-downloads", nil, &dl)
	if dl.Items == nil || len(dl.Items) != 0 || !strings.Contains(string(r.body), `"items":[]`) {
		t.Errorf("downloads = %s", r.body)
	}
	if r := h.raw("GET", "/api/agent/v1/download/SHA256SUMS", nil, ""); r.status != http.StatusOK || len(r.body) != 0 {
		t.Errorf("checksums without builds: %d %q", r.status, r.body)
	}
}

// exec runs SQL as the platform.
func exec(t *testing.T, h *harness, sql string, args ...any) {
	t.Helper()
	err := h.db.DB.InTx(context.Background(), database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), sql, args...)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestAgentRequestLimits covers what one device may send (Phase 9 security
// review): a request naming no enrolled device is refused before its body
// is read, and an enrolled device that sends far more than an agent does
// is refused with 429, without its body being read either. Requests that
// name the device but are not signed by it do not use up its allowance.
func TestAgentRequestLimits(t *testing.T) {
	h := newHarness(t, false)
	admin, _ := setUp(t, h)
	acme := orgID(t, admin, "Acme")
	var hq idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/sites", map[string]string{"name": "HQ", "timezone": "UTC"}, &hq)
	var token struct {
		Secret string `json:"secret"`
	}
	admin.expect(http.StatusCreated, "POST", "/api/v1/sites/"+hq.ID+"/enrollment-tokens", map[string]any{"name": "Limits", "expiresInDays": 1}, &token)
	ctx := context.Background()
	ac := h.agentClient()
	key := newKey(t)
	enr, err := ac.Enroll(ctx, token.Secret, key.Public().(ed25519.PublicKey), facts("lim-01"))
	if err != nil {
		t.Fatal(err)
	}
	ac.SetIdentity(enr.DeviceID, key)
	body, _ := json.Marshal(agentproto.HeartbeatRequest{Facts: facts("lim-01")})
	sign := func(k ed25519.PrivateKey, device string, b []byte) string {
		s, err := agentproto.Sign(k, device, "POST", agentproto.PathHeartbeat, b, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	// A request naming a device that is not enrolled is answered while its
	// body is still arriving.
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })
	go func() { _, _ = pw.Write([]byte(`{"facts":`)) }()
	rctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(rctx, "POST", h.srv.URL+agentproto.PathHeartbeat, pr)
	req.Host = "rmm.test"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", sign(key, uuid.NewString(), body))
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		t.Fatalf("a request from no enrolled device waited for its body: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unknown device: %d", resp.StatusCode)
	}

	// Badly signed requests naming the device do not spend its allowance.
	stranger := newKey(t)
	for range 150 {
		wantStatus(t, h.raw("POST", agentproto.PathHeartbeat, body, sign(stranger, enr.DeviceID, body)), http.StatusUnauthorized, "agent_unauthorized")
	}
	if _, err := ac.Heartbeat(ctx, agentproto.HeartbeatRequest{Facts: facts("lim-01")}); err != nil {
		t.Fatalf("after badly signed requests: %v", err)
	}

	// Far more requests than an agent sends.
	ok := 1
	for ; ok < 400; ok++ {
		r := h.raw("POST", agentproto.PathHeartbeat, body, sign(key, enr.DeviceID, body))
		if r.status == http.StatusTooManyRequests {
			wantStatus(t, r, http.StatusTooManyRequests, "rate_limited")
			break
		}
		wantStatus(t, r, http.StatusOK, "")
	}
	if ok < 100 || ok >= 400 {
		t.Fatalf("limited after %d requests", ok)
	}
	// Once limited, the body is not read: an oversized one is refused for
	// the rate, not its size. The allowance refills a token a second, so on
	// a slow runner one can come back between the last refusal and this
	// request, which is then refused for its size without spending it (a
	// token is spent only once the signature over the body is verified).
	// Each time, ordinary requests spend what came back and it is tried
	// again; a server that read the body first would refuse every try for
	// its size.
	big := bytes.Repeat([]byte("x"), agentproto.MaxBody+1)
	r := h.raw("POST", agentproto.PathHeartbeat, big, sign(key, enr.DeviceID, big))
	for try := 1; try < 3 && r.status == http.StatusRequestEntityTooLarge; try++ {
		for range 400 {
			if h.raw("POST", agentproto.PathHeartbeat, body, sign(key, enr.DeviceID, body)).status == http.StatusTooManyRequests {
				break
			}
		}
		r = h.raw("POST", agentproto.PathHeartbeat, big, sign(key, enr.DeviceID, big))
	}
	wantStatus(t, r, http.StatusTooManyRequests, "rate_limited")
	if _, err := ac.Heartbeat(ctx, agentproto.HeartbeatRequest{Facts: facts("lim-01")}); agentclient.Code(err) != "rate_limited" {
		t.Fatalf("the agent's own client: %v", err)
	}

	// Inventory uploads have a smaller allowance of their own.
	ac2 := h.agentClient()
	key2 := newKey(t)
	enr2, err := ac2.Enroll(ctx, token.Secret, key2.Public().(ed25519.PublicKey), facts("lim-02"))
	if err != nil {
		t.Fatal(err)
	}
	ac2.SetIdentity(enr2.DeviceID, key2)
	inv := agentproto.Inventory{OS: agentproto.OSInfo{Name: "Debian GNU/Linux 13 (trixie)"}, PackageManager: "dpkg"}
	ups := 0
	for ; ups < 20; ups++ {
		inv.Packages = []agentproto.Package{{Name: "pkg", Version: strconv.Itoa(ups)}}
		b, _ := json.Marshal(inv)
		if _, err := ac2.Inventory(ctx, b); err != nil {
			if agentclient.Code(err) != "rate_limited" {
				t.Fatalf("upload %d: %v", ups, err)
			}
			break
		}
	}
	if ups != 6 {
		t.Errorf("%d inventory uploads before the limit", ups)
	}
	if _, err := ac2.Heartbeat(ctx, agentproto.HeartbeatRequest{Facts: facts("lim-02")}); err != nil {
		t.Errorf("heartbeats stop with inventory uploads: %v", err)
	}
}
