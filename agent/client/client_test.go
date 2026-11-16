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
	case agentproto.PathJobsPoll:
		_, _ = io.WriteString(w, `{"jobs":[],"cancel":["r9"]}`)
	case agentproto.PathJobStart("r1"):
		_, _ = io.WriteString(w, `{"proceed":true}`)
	case agentproto.PathJobStart("r2"):
		_, _ = io.WriteString(w, `{"proceed":`)
	case agentproto.PathJobResult("r1"):
		var in agentproto.ResultRequest
		if err := json.Unmarshal(body, &in); err != nil || in.Status != agentproto.RunSucceeded {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case agentproto.PathInventory:
		if string(body) == "bad" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":{"code":"inventory_invalid","message":"no"}}`)
			return
		}
		_, _ = io.WriteString(w, `{"hash":"`+strconv.Itoa(len(body))+`"}`)
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

	if _, err := c.Heartbeat(ctx, agentproto.HeartbeatRequest{}); err == nil || !strings.Contains(err.Error(), "not enrolled") {
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
	hb, err := c.Heartbeat(ctx, agentproto.HeartbeatRequest{Facts: agentproto.Facts{Hostname: "h"}})
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
	if h, err := c.Inventory(ctx, []byte(`{"os":{}}`)); err != nil || h != "9" {
		t.Errorf("inventory = %q, %v", h, err)
	}
	if _, err := c.Inventory(ctx, []byte("bad")); Code(err) != "inventory_invalid" {
		t.Errorf("refused inventory: %v", err)
	}

	// A different key's signature is refused by the server.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	c.SetIdentity("dev-1", other)
	if _, err := c.Heartbeat(ctx, agentproto.HeartbeatRequest{}); Code(err) != "agent_unauthorized" {
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

func TestDownload(t *testing.T) {
	build := bytes.Repeat([]byte{0x42}, 3000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("a build download is signed; it needs no identity")
		}
		switch r.URL.EscapedPath() {
		case agentproto.PathAgentDownload("easyrmm-agent-linux-amd64"):
			_, _ = w.Write(build)
		case agentproto.PathAgentDownload("short"):
			w.Header().Set("Content-Length", strconv.Itoa(len(build)+5))
			_, _ = w.Write(build)
		case agentproto.PathAgentDownload("a%2Fb"):
			_, _ = io.WriteString(w, "escaped")
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"error":{"code":"not_found","message":"no such build"}}`)
		}
	}))
	t.Cleanup(srv.Close)
	c, err := New(Options{Server: srv.URL, Version: "9.9"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	var buf bytes.Buffer
	if err := c.Download(ctx, "easyrmm-agent-linux-amd64", &buf); err != nil || !bytes.Equal(buf.Bytes(), build) {
		t.Errorf("download = %d bytes, %v", buf.Len(), err)
	}
	if err := c.Download(ctx, "short", io.Discard); err == nil {
		t.Error("a truncated download was accepted")
	}
	// A file name cannot reach another path.
	buf.Reset()
	if err := c.Download(ctx, "a/b", &buf); err != nil || buf.String() != "escaped" {
		t.Errorf("escaped name = %q, %v", buf.String(), err)
	}
	if err := c.Download(ctx, "missing", io.Discard); Code(err) != "not_found" {
		t.Errorf("missing build: %v", err)
	}
	if err := c.Download(ctx, "easyrmm-agent-linux-amd64", failingWriter{}); err == nil {
		t.Error("a failed write was not reported")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestJobCalls(t *testing.T) {
	c, _ := newPair(t)
	ctx := context.Background()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := c.Enroll(ctx, "ert_good", pub, agentproto.Facts{}); err != nil {
		t.Fatal(err)
	}
	c.SetIdentity("dev-1", key)

	if p, err := c.Poll(ctx); err != nil || len(p.Cancel) != 1 || p.Cancel[0] != "r9" {
		t.Errorf("poll = %+v, %v", p, err)
	}
	if s, err := c.Start(ctx, "r1"); err != nil || !s.Proceed {
		t.Errorf("start = %+v, %v", s, err)
	}
	if _, err := c.Start(ctx, "r2"); err == nil || !strings.Contains(err.Error(), "reading the server's answer") {
		t.Errorf("a cut-off answer: %v", err)
	}
	if err := c.Result(ctx, "r1", agentproto.ResultRequest{Status: agentproto.RunSucceeded}); err != nil {
		t.Errorf("result: %v", err)
	}
	if err := c.Result(ctx, "r1", agentproto.ResultRequest{Status: "bogus"}); err == nil {
		t.Error("a refused result was accepted")
	}
}

func TestUnreachableServer(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	c, err := New(Options{Server: srv.URL, Version: "9.9"})
	if err != nil {
		t.Fatal(err)
	}
	srv.Close()
	ctx := context.Background()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := c.Enroll(ctx, "ert_good", pub, agentproto.Facts{}); err == nil || Code(err) != "" {
		t.Errorf("enroll: %v", err)
	}
	c.SetIdentity("dev-1", key)
	if _, err := c.Heartbeat(ctx, agentproto.HeartbeatRequest{}); err == nil {
		t.Error("heartbeat to a closed server succeeded")
	}
	if _, err := c.MeshSettings(ctx); err == nil {
		t.Error("settings from a closed server")
	}
	if err := c.Result(ctx, "r1", agentproto.ResultRequest{}); err == nil {
		t.Error("result to a closed server succeeded")
	}
	if err := c.Download(ctx, "x", io.Discard); err == nil {
		t.Error("download from a closed server succeeded")
	}
}
