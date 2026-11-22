package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// fakeServer checks signatures like the EasyRMM server does.
type fakeServer struct {
	t    *testing.T
	pub  ed25519.PublicKey
	mesh []byte
	// job signs MeshAgent's downloads, as the server's job key does.
	job ed25519.PrivateKey
	// short makes the MeshAgent download and the settings end early; huge
	// sends more than agentproto.MaxMeshAgentBytes; tamper changes the
	// settings after signing them.
	short, huge, tamper bool
}

// signDownload signs a download as the server does.
func (f *fakeServer) signDownload(w http.ResponseWriter, r *http.Request, body []byte) {
	a, _ := agentproto.Parse(r.Header.Get("Authorization"))
	w.Header().Set(agentproto.HeaderDownloadSignature, agentproto.SignDownload(f.job, a, r.RequestURI, sha256.Sum256(body)))
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
		if f.huge {
			_, _ = io.CopyN(w, zeros{}, agentproto.MaxMeshAgentBytes+1)
			return
		}
		f.signDownload(w, r, f.mesh)
		if f.short {
			w.Header().Set("Content-Length", strconv.Itoa(len(f.mesh)+10))
		}
		_, _ = w.Write(f.mesh)
	case agentproto.PathMeshSettings:
		f.signDownload(w, r, []byte("MeshID=0x1"))
		if f.short {
			w.Header().Set("Content-Length", "100")
		}
		if f.tamper {
			_, _ = io.WriteString(w, "MeshID=0x2")
			return
		}
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

// zeros reads as an endless run of zero bytes.
type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func newPair(t *testing.T) (*Client, *fakeServer) {
	t.Helper()
	_, job, _ := ed25519.GenerateKey(rand.Reader)
	f := &fakeServer{t: t, mesh: bytes.Repeat([]byte{0x7f}, 4096), job: job}
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
	// MeshAgent's downloads carry the job key's signature over what they hold.
	jobPub := f.job.Public().(ed25519.PublicKey)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	var buf bytes.Buffer
	signed, err := c.MeshAgent(ctx, "linux", "arm64", &buf)
	if err != nil || buf.Len() != 4096 || signed.SHA256 != sha256.Sum256(f.mesh) || signed.Verify(jobPub) != nil {
		t.Errorf("MeshAgent = %d bytes, %+v, %v", buf.Len(), signed, err)
	}
	if err := signed.Verify(otherPub); !errors.Is(err, agentproto.ErrDownloadSignature) {
		t.Errorf("MeshAgent verified with another key: %v", err)
	}
	if _, err := c.MeshAgent(ctx, "plan9", "arm64", &buf); err == nil || Code(err) != "" {
		t.Errorf("MeshAgent for an unknown platform: %v", err)
	}
	f.short = true
	if _, err := c.MeshAgent(ctx, "linux", "arm64", io.Discard); err == nil {
		t.Error("a truncated download was accepted")
	}
	f.short, f.huge = false, true
	if _, err := c.MeshAgent(ctx, "linux", "arm64", io.Discard); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("an oversized download: %v", err)
	}
	b, signed, err := c.MeshSettings(ctx)
	if err != nil || string(b) != "MeshID=0x1" || signed.Verify(jobPub) != nil {
		t.Errorf("settings = %q, %+v, %v", b, signed, err)
	}
	f.short = true
	if _, _, err := c.MeshSettings(ctx); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("settings cut short: %v", err)
	}
	f.short, f.tamper = false, true
	if b, signed, err := c.MeshSettings(ctx); err != nil || string(b) != "MeshID=0x2" || !errors.Is(signed.Verify(jobPub), agentproto.ErrDownloadSignature) {
		t.Errorf("settings changed after signing = %q, %v, %v", b, signed.Verify(jobPub), err)
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

	if p, err := c.Poll(ctx, nil); err != nil || len(p.Cancel) != 1 || p.Cancel[0] != "r9" {
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

// levelServer answers heartbeats with a protocol level and, below level 2,
// decodes polls and results strictly, as a server of the release before
// does (ADR-0009). It keeps the bodies it got.
type levelServer struct {
	mu     sync.Mutex
	level  int
	bodies map[string][]string
}

// releaseBeforeResult is ResultRequest as 1.0.0-rc.4 declares it.
type releaseBeforeResult struct {
	Status          string    `json:"status"`
	ExitCode        *int      `json:"exitCode"`
	Stdout          string    `json:"stdout"`
	Stderr          string    `json:"stderr"`
	StdoutTruncated bool      `json:"stdoutTruncated"`
	StderrTruncated bool      `json:"stderrTruncated"`
	Error           string    `json:"error"`
	StartedAt       time.Time `json:"startedAt,omitzero"`
	FinishedAt      time.Time `json:"finishedAt,omitzero"`
}

func (s *levelServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, _ := io.ReadAll(r.Body)
	kind := path.Base(r.URL.Path)
	s.bodies[kind] = append(s.bodies[kind], string(b))
	strict := func(v any) bool {
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		if s.level < 2 && dec.Decode(v) != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":{"code":"bad_request","message":"unknown field"}}`)
			return false
		}
		return true
	}
	switch kind {
	case "heartbeat":
		_ = json.NewEncoder(w).Encode(agentproto.HeartbeatResponse{Protocol: s.level, HeartbeatSeconds: 60})
	case "poll":
		if strict(&struct{}{}) {
			_, _ = io.WriteString(w, `{"jobs":[],"cancel":[]}`)
		}
	case "result":
		if strict(&releaseBeforeResult{}) {
			_, _ = io.WriteString(w, `{}`)
		}
	}
}

func (s *levelServer) set(level int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.level = level
}

func (s *levelServer) last(kind string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.bodies[kind]
	if len(list) == 0 {
		return ""
	}
	return list[len(list)-1]
}

// TestNewFieldsFollowTheServersLevel: the poll's accepts and the result's
// interpreter (ADR-0064) go only to a server whose last heartbeat answer
// was of level 2 or higher, and not after one of level 1 (ADR-0009).
func TestNewFieldsFollowTheServersLevel(t *testing.T) {
	s := &levelServer{bodies: map[string][]string{}}
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	c, err := New(Options{Server: srv.URL, Version: "9.9"})
	if err != nil {
		t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	c.SetIdentity("dev-1", key)
	ctx := context.Background()
	accepts := []string{agentproto.CapJobPwsh}
	zero := 0
	result := agentproto.ResultRequest{Status: agentproto.RunSucceeded, ExitCode: &zero,
		Interpreter: &agentproto.Interpreter{Edition: agentproto.EditionCore, Version: "7.6.10", Arch: agentproto.ArchX64, Path: `C:\Program Files\PowerShell\7\pwsh.exe`}}
	poll := func(want string) {
		t.Helper()
		if _, err := c.Poll(ctx, accepts); err != nil {
			t.Fatalf("poll: %v", err)
		}
		if got := s.last("poll"); got != want {
			t.Errorf("poll sent %s, want %s", got, want)
		}
	}
	beat := func(level int) {
		t.Helper()
		s.set(level)
		if _, err := c.Heartbeat(ctx, agentproto.HeartbeatRequest{}); err != nil {
			t.Fatal(err)
		}
	}

	// Before any answer: the poll says nothing, and a result that names its
	// program waits for the first answer.
	poll(`{}`)
	if c.Level() != 0 {
		t.Errorf("level %d before any answer", c.Level())
	}
	short, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if err := c.Result(short, "r1", result); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("a result before any answer: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- c.Result(ctx, "r1", result) }()
	time.Sleep(50 * time.Millisecond)
	beat(0) // the release before: no level
	if err := <-done; err != nil {
		t.Fatalf("the waiting result: %v", err)
	}
	if c.Level() != 1 || strings.Contains(s.last("result"), "interpreter") {
		t.Errorf("level %d, result sent %s", c.Level(), s.last("result"))
	}
	poll(`{}`)

	beat(2)
	poll(`{"accepts":["job.pwsh"]}`)
	if err := c.Result(ctx, "r2", result); err != nil || !strings.Contains(s.last("result"), `"interpreter":{"edition":"Core","version":"7.6.10","arch":"x64"`) {
		t.Errorf("a level 2 server: %v, result sent %s", err, s.last("result"))
	}
	if _, err := c.Poll(ctx, []string{}); err != nil || s.last("poll") != `{"accepts":[]}` {
		t.Errorf("a build that accepts nothing says so: %v %s", err, s.last("poll"))
	}

	// After an answer of level 1 again (the server was rolled back).
	beat(1)
	poll(`{}`)
	if err := c.Result(ctx, "r3", result); err != nil || strings.Contains(s.last("result"), "interpreter") {
		t.Errorf("a level 1 server: %v, result sent %s", err, s.last("result"))
	}
	// A result that names no program never waits.
	fresh, _ := New(Options{Server: srv.URL, Version: "9.9"})
	fresh.SetIdentity("dev-1", key)
	quick, cancelQuick := context.WithTimeout(ctx, 5*time.Second)
	defer cancelQuick()
	if err := fresh.Result(quick, "r4", agentproto.ResultRequest{Status: agentproto.RunFailed, Error: "x"}); err != nil {
		t.Errorf("a result without a program: %v", err)
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
	if _, _, err := c.MeshSettings(ctx); err == nil {
		t.Error("settings from a closed server")
	}
	if err := c.Result(ctx, "r1", agentproto.ResultRequest{}); err == nil {
		t.Error("result to a closed server succeeded")
	}
	if err := c.Download(ctx, "x", io.Discard); err == nil {
		t.Error("download from a closed server succeeded")
	}
}
