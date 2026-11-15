package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// fakeServer checks signatures like the EasyRMM server does.
type fakeServer struct {
	t    *testing.T
	pub  ed25519.PublicKey
	mesh []byte
	// short makes the MeshAgent download end early.
	short bool
}

func (f *fakeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	if r.URL.Path != agentproto.PathEnroll {
		a, err := agentproto.Parse(r.Header.Get("Authorization"))
		if err != nil || !a.Verify(f.pub, r.Method, r.RequestURI, body) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":{"code":"agent_unauthorized","message":"The request signature is not valid."}}`)
			return
		}
	}
	switch r.URL.Path {
	case agentproto.PathEnroll:
		var in agentproto.EnrollRequest
		if err := json.Unmarshal(body, &in); err != nil || r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if in.Token != "ert_good" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":{"code":"token_invalid","message":"not valid"}}`)
			return
		}
		k, _ := base64.StdEncoding.DecodeString(in.PublicKey)
		f.pub = k
		_, _ = io.WriteString(w, `{"deviceId":"dev-1","heartbeatSeconds":60,"meshAgent":{"available":true}}`)
	case agentproto.PathHeartbeat:
		_, _ = io.WriteString(w, `{"heartbeatSeconds":30,"meshAgent":{"available":false}}`)
	case agentproto.PathMeshAgent:
		if r.URL.Query().Get("os") != "linux" || r.URL.Query().Get("arch") != "arm64" {
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		if f.short {
			w.Header().Set("Content-Length", strconv.Itoa(len(f.mesh)+10))
		}
		_, _ = w.Write(f.mesh)
	case agentproto.PathMeshSettings:
		_, _ = io.WriteString(w, "MeshID=0x1")
	default:
		w.WriteHeader(http.StatusTeapot)
		_, _ = io.WriteString(w, "not json")
	}
}

func newPair(t *testing.T) (*Client, *fakeServer) {
	t.Helper()
	f := &fakeServer{t: t, mesh: bytes.Repeat([]byte{0x7f}, 4096)}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	c, err := New(Options{Server: srv.URL, Version: "9.9"})
	if err != nil {
		t.Fatal(err)
	}
	return c, f
}

func TestEnrollAndSignedRequests(t *testing.T) {
	c, f := newPair(t)
	ctx := context.Background()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)

	if _, err := c.Heartbeat(ctx, agentproto.Facts{}); err == nil || !strings.Contains(err.Error(), "not enrolled") {
		t.Errorf("heartbeat before enrolling: %v", err)
	}
	_, err := c.Enroll(ctx, "ert_bad", pub, agentproto.Facts{Hostname: "h"})
	if Code(err) != "token_invalid" || !strings.Contains(err.Error(), "401 token_invalid: not valid") {
		t.Errorf("bad token: %v", err)
	}
	resp, err := c.Enroll(ctx, "ert_good", pub, agentproto.Facts{Hostname: "h"})
	if err != nil || resp.DeviceID != "dev-1" || !resp.MeshAgent.Available || !bytes.Equal(f.pub, pub) {
		t.Fatalf("enroll = %+v, %v", resp, err)
	}

	c.SetIdentity("dev-1", key)
	hb, err := c.Heartbeat(ctx, agentproto.Facts{Hostname: "h"})
	if err != nil || hb.HeartbeatSeconds != 30 {
		t.Fatalf("heartbeat = %+v, %v", hb, err)
	}
	var buf bytes.Buffer
	if err := c.MeshAgent(ctx, "linux", "arm64", &buf); err != nil || buf.Len() != 4096 {
		t.Errorf("MeshAgent = %d bytes, %v", buf.Len(), err)
	}
	if err := c.MeshAgent(ctx, "plan9", "arm64", &buf); err == nil || Code(err) != "" {
		t.Errorf("MeshAgent for an unknown platform: %v", err)
	}
	f.short = true
	if err := c.MeshAgent(ctx, "linux", "arm64", io.Discard); err == nil {
		t.Error("a truncated download was accepted")
	}
	if b, err := c.MeshSettings(ctx); err != nil || string(b) != "MeshID=0x1" {
		t.Errorf("settings = %q, %v", b, err)
	}

	// A different key's signature is refused by the server.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	c.SetIdentity("dev-1", other)
	if _, err := c.Heartbeat(ctx, agentproto.Facts{}); Code(err) != "agent_unauthorized" {
		t.Errorf("wrong key: %v", err)
	}
	// Errors without the JSON envelope keep the status.
	c.SetIdentity("dev-1", key)
	err = c.call(ctx, http.MethodGet, "/elsewhere", nil, true, &struct{}{})
	var e *Error
	if !errors.As(err, &e) || e.Status != http.StatusTeapot || e.Error() != "server answered 418" {
		t.Errorf("plain error = %v", err)
	}
	if Code(io.EOF) != "" {
		t.Error("code of a non-server error")
	}
}

func TestParseServer(t *testing.T) {
	for in, want := range map[string]string{
		"https://rmm.example.com":       "https://rmm.example.com",
		"https://rmm.example.com/":      "https://rmm.example.com",
		" https://rmm.example.com:8443": "https://rmm.example.com:8443",
		"http://127.0.0.1:8080":         "http://127.0.0.1:8080",
		"http://localhost":              "http://localhost",
	} {
		u, err := ParseServer(in)
		if err != nil || u.String() != want {
			t.Errorf("ParseServer(%q) = %v, %v", in, u, err)
		}
	}
	for _, bad := range []string{
		"", "rmm.example.com", "http://rmm.example.com", "ftp://rmm.example.com", "https://u:p@rmm.example.com",
		"https://rmm.example.com/console", "https://rmm.example.com?x=1", "https://rmm.example.com#x", "https://",
	} {
		if _, err := ParseServer(bad); err == nil {
			t.Errorf("ParseServer(%q) accepted", bad)
		}
	}
	if _, err := New(Options{Server: "nope"}); err == nil {
		t.Error("New with a bad server")
	}
}

func TestPrivateCA(t *testing.T) {
	f := &fakeServer{t: t}
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := New(Options{Server: srv.URL, CAFile: ca})
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := c.Enroll(context.Background(), "ert_good", pub, agentproto.Facts{}); err != nil {
		t.Errorf("enroll through a private CA: %v", err)
	}
	// Without the CA the certificate is not trusted.
	plain, _ := New(Options{Server: srv.URL})
	if _, err := plain.Enroll(context.Background(), "ert_good", pub, agentproto.Facts{}); err == nil {
		t.Error("an untrusted certificate was accepted")
	}
	if _, err := New(Options{Server: srv.URL, CAFile: filepath.Join(dir, "missing.pem")}); err == nil {
		t.Error("missing CA file accepted")
	}
	junk := filepath.Join(dir, "junk.pem")
	_ = os.WriteFile(junk, []byte("not pem"), 0o600)
	if _, err := New(Options{Server: srv.URL, CAFile: junk}); err == nil {
		t.Error("CA file without certificates accepted")
	}
	if c.Server() != srv.URL {
		t.Errorf("Server() = %s", c.Server())
	}
}
