package runner

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/agent/client"
	"github.com/paulmataruso/easyrmm/agent/host"
	"github.com/paulmataruso/easyrmm/agent/state"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// server answers heartbeats with a programmable result.
type server struct {
	mu        sync.Mutex
	status    int
	code      string
	available bool
	// Inventory: the hash the server claims to hold, what was uploaded,
	// and an error status for uploads.
	invHash    string
	uploads    [][]byte
	invStatus  int
	heartbeats []agentproto.HeartbeatRequest
	// beats counts heartbeat requests, answered or not.
	beats int
	// Hardware reports: those taken, how many were sent, and an error
	// status for them.
	hardware   []agentproto.HardwareReport
	hwRequests int
	hwStatus   int
	// update is the heartbeat answer's update instruction, JSON.
	update string
	// easyPatch is its EasyPatch install instruction, JSON.
	easyPatch string
	// uninstall is its uninstall instruction, JSON.
	uninstall string
	// job signs MeshAgent's downloads, as the server's job key does;
	// tamper changes the binary after signing it.
	job    ed25519.PrivateKey
	tamper bool
	// protocol is the heartbeat answer's level, none when 0 (ADR-0009).
	protocol int
	// settingsSHA is the MeshAgent settings hash the heartbeat announces (ADR-0069).
	settingsSHA string
}

// download serves a signed download, as the server does.
func (s *server) download(w http.ResponseWriter, r *http.Request, body string) {
	a, _ := agentproto.Parse(r.Header.Get("Authorization"))
	w.Header().Set(agentproto.HeaderDownloadSignature, agentproto.SignDownload(s.job, a, r.RequestURI, sha256.Sum256([]byte(body))))
	if s.tamper {
		body += "!"
	}
	_, _ = io.WriteString(w, body)
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch r.URL.Path {
	case agentproto.PathHardware:
		s.hwRequests++
		if s.hwStatus != 0 {
			w.WriteHeader(s.hwStatus)
			return
		}
		var in agentproto.HardwareReport
		_ = json.NewDecoder(r.Body).Decode(&in)
		s.hardware = append(s.hardware, in)
		w.WriteHeader(http.StatusAccepted)
	case agentproto.PathHeartbeat:
		s.beats++
		if s.status != 0 {
			w.WriteHeader(s.status)
			_, _ = io.WriteString(w, `{"error":{"code":"`+s.code+`","message":"m"}}`)
			return
		}
		var req agentproto.HeartbeatRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		s.heartbeats = append(s.heartbeats, req)
		update := ""
		if s.update != "" {
			update = `,"update":` + s.update
		}
		if s.easyPatch != "" {
			update += `,"easyPatchInstall":` + s.easyPatch
		}
		if s.uninstall != "" {
			update += `,"uninstall":` + s.uninstall
		}
		if s.protocol != 0 {
			update += `,"protocol":` + strconv.Itoa(s.protocol)
		}
		announce := ""
		if s.settingsSHA != "" {
			announce = `,"settingsSha256":"` + s.settingsSHA + `"`
		}
		_, _ = io.WriteString(w, `{"heartbeatSeconds":60,"inventoryHash":"`+s.invHash+`","meshAgent":{"available":`+map[bool]string{true: "true", false: "false"}[s.available]+announce+`}`+update+`}`)
	case agentproto.PathInventory:
		if s.invStatus != 0 {
			w.WriteHeader(s.invStatus)
			_, _ = io.WriteString(w, `{"error":{"code":"inventory_invalid","message":"m"}}`)
			return
		}
		b, _ := io.ReadAll(r.Body)
		s.uploads = append(s.uploads, b)
		_, _ = io.WriteString(w, `{"hash":"h"}`)
	case agentproto.PathMeshSettings:
		s.download(w, r, "MeshID=0x1")
	case agentproto.PathMeshAgent:
		s.download(w, r, "ELF")
	}
}

// mesh is a fake MeshAgent manager.
type mesh struct {
	installed  bool
	installErr error
	started    int
	node       string
	nodeErr    error
	settings   string
	binary     string
	applied    string
	reconf     int
	reconfErr  error
}

func (m *mesh) Installed() bool { return m.installed }

func (m *mesh) Install(_ context.Context, download func(io.Writer) error, settings []byte) error {
	if m.installErr != nil {
		return m.installErr
	}
	var b strings.Builder
	if err := download(&b); err != nil {
		return err
	}
	m.binary, m.settings, m.installed = b.String(), string(settings), true
	return nil
}

func (m *mesh) Start(context.Context) error { m.started++; return nil }

func (m *mesh) AppliedSettings() string { return m.applied }

func (m *mesh) Reconfigure(_ context.Context, settings []byte) error {
	if m.reconfErr != nil {
		return m.reconfErr
	}
	sum := sha256.Sum256(settings)
	m.settings, m.applied = string(settings), hex.EncodeToString(sum[:])
	m.reconf++
	return nil
}

func (m *mesh) NodeID(context.Context) (string, error) { return m.node, m.nodeErr }

func newRunner(t *testing.T, s *server, m *mesh) *Runner {
	t.Helper()
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	c, err := client.New(client.Options{Server: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	c.SetIdentity("dev-1", key)
	jobPub, job, _ := ed25519.GenerateKey(rand.Reader)
	s.job = job
	store, _, err := state.Open(host.Paths{Root: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(store.Dir(), 0o700); err != nil {
		t.Fatal(err)
	}
	r := &Runner{
		Client: c, Store: store,
		Facts: func() agentproto.Facts { return agentproto.Facts{Hostname: "h"} },
		Log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Key:   func() ed25519.PublicKey { return jobPub },
	}
	if m != nil {
		r.Mesh = m
	}
	r.defaults()
	return r
}

func TestBeatInstallsMeshAgentWhenOffered(t *testing.T) {
	s := &server{}
	m := &mesh{}
	r := newRunner(t, s, m)
	ctx := context.Background()

	if wait, _ := r.beat(ctx); wait < 54*time.Second || wait > 66*time.Second {
		t.Errorf("next heartbeat in %v", wait)
	}
	st, _ := r.Store.LoadStatus()
	if st.LastHeartbeat.IsZero() || st.MeshAgent != "not available from the server" || m.installed {
		t.Errorf("status = %+v", st)
	}

	s.available = true
	if wait, _ := r.beat(ctx); wait != r.AfterSetup {
		t.Errorf("after installing, next heartbeat in %v", wait)
	}
	if !m.installed || m.binary != "ELF" || m.settings != "MeshID=0x1" {
		t.Fatalf("MeshAgent = %+v", m)
	}
	m.node = "AB"
	if _, err := r.beat(ctx); err != nil {
		t.Fatal(err)
	}
	if r.status.MeshNodeID != "AB" || r.status.MeshAgent != "installed" {
		t.Errorf("status = %+v", r.status)
	}

	// Run starts an installed MeshAgent and stops with its context.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil || m.started != 1 {
			t.Errorf("Run = %v, started %d", err, m.started)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
}

// MeshAgent runs as SYSTEM or root: nothing is installed that the server
// did not sign with the pinned job key.
func TestBeatRefusesUnsignedMeshAgent(t *testing.T) {
	ctx := context.Background()
	for name, c := range map[string]struct {
		prepare func(*Runner, *server)
		want    string
	}{
		"no key pinned yet": {func(r *Runner, _ *server) { r.Key = func() ed25519.PublicKey { return nil } },
			"install failed: no server key is pinned yet"},
		"another server's key": {func(r *Runner, _ *server) {
			other, _, _ := ed25519.GenerateKey(rand.Reader)
			r.Key = func() ed25519.PublicKey { return other }
		}, "install failed: MeshAgent's settings: agentproto: the download's signature does not verify"},
		"changed on the way": {func(_ *Runner, s *server) { s.tamper = true },
			"install failed: MeshAgent's settings: agentproto: the download's signature does not verify"},
	} {
		s := &server{available: true}
		m := &mesh{}
		r := newRunner(t, s, m)
		c.prepare(r, s)
		if _, err := r.beat(ctx); err != nil {
			t.Fatal(err)
		}
		if m.installed || !strings.HasPrefix(r.status.MeshAgent, c.want) {
			t.Errorf("%s: installed %v, status %q", name, m.installed, r.status.MeshAgent)
		}
	}

	// A binary that does not match its signature is not installed either.
	s := &server{available: true}
	m := &mesh{}
	r := newRunner(t, s, m)
	tamperBinary := &binaryTamper{Handler: s}
	srv := httptest.NewServer(tamperBinary)
	t.Cleanup(srv.Close)
	c, err := client.New(client.Options{Server: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	c.SetIdentity("dev-1", key)
	r.Client = c
	if _, err := r.beat(ctx); err != nil {
		t.Fatal(err)
	}
	if m.installed || !strings.HasPrefix(r.status.MeshAgent, "install failed: MeshAgent: agentproto: the download's signature does not verify") {
		t.Errorf("tampered binary: installed %v, status %q", m.installed, r.status.MeshAgent)
	}
}

// binaryTamper changes MeshAgent's binary after the server signed it.
type binaryTamper struct{ http.Handler }

func (b *binaryTamper) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != agentproto.PathMeshAgent {
		b.Handler.ServeHTTP(w, r)
		return
	}
	rec := httptest.NewRecorder()
	b.Handler.ServeHTTP(rec, r)
	w.Header().Set(agentproto.HeaderDownloadSignature, rec.Header().Get(agentproto.HeaderDownloadSignature))
	_, _ = w.Write(append(rec.Body.Bytes(), '!'))
}

func TestHeartbeatInterval(t *testing.T) {
	for in, want := range map[int]time.Duration{
		0: time.Minute, -5: time.Minute, 1: 10 * time.Second, 60: time.Minute,
		600: 10 * time.Minute, 1 << 30: 10 * time.Minute,
	} {
		if got := heartbeatInterval(in); got != want {
			t.Errorf("heartbeatInterval(%d) = %v, want %v", in, got, want)
		}
	}
}

func TestBeatInstallFailureWaits(t *testing.T) {
	s := &server{available: true}
	m := &mesh{installErr: errors.New("disk full"), nodeErr: errors.New("x")}
	r := newRunner(t, s, m)
	if _, err := r.beat(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.status.MeshAgent, "install failed: disk full") {
		t.Errorf("status = %+v", r.status)
	}
	// No second attempt before InstallWait passes.
	m.installErr = nil
	if _, err := r.beat(context.Background()); err != nil {
		t.Fatal(err)
	}
	if m.installed {
		t.Error("retried the install immediately")
	}
	r.lastInstall = time.Now().Add(-r.InstallWait)
	if _, err := r.beat(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !m.installed {
		t.Error("install not retried after the wait")
	}
}

func TestBeatFailuresBackOff(t *testing.T) {
	s := &server{status: http.StatusBadGateway, code: "x"}
	r := newRunner(t, s, nil)
	var waits []time.Duration
	for range 4 {
		w, _ := r.beat(context.Background())
		waits = append(waits, w)
	}
	for i, want := range []time.Duration{5, 10, 20, 40} {
		w := want * time.Second
		if waits[i] < w*9/10 || waits[i] > w*11/10 {
			t.Errorf("retry %d after %v, want about %v", i+1, waits[i], w)
		}
	}
	st, _ := r.Store.LoadStatus()
	if !strings.Contains(st.LastError, "502") || st.LastErrorAt.IsZero() {
		t.Errorf("status = %+v", st)
	}
	r.failures = 20
	if w, _ := r.beat(context.Background()); w > r.MaxRetry*11/10 {
		t.Errorf("backoff not capped: %v", w)
	}

	s.status, s.code = http.StatusUnauthorized, "device_unknown"
	r.failures = 0
	if w, _ := r.beat(context.Background()); w < r.MaxRetry*9/10 {
		t.Errorf("unknown device retried after %v", w)
	}
	s.code = "clock_skew"
	r.failures = 0
	if w, _ := r.beat(context.Background()); w > 6*time.Second {
		t.Errorf("clock skew retried after %v", w)
	}

	// Recovery clears the error.
	s.status = 0
	if _, err := r.beat(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.status.LastError != "" || r.failures != 0 {
		t.Errorf("after recovery: %+v", r.status)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if w, _ := r.beat(ctx); w != 0 {
		t.Errorf("canceled beat waits %v", w)
	}
}

func TestJitter(t *testing.T) {
	for range 100 {
		if j := jitter(time.Minute); j < 54*time.Second || j >= 66*time.Second {
			t.Fatalf("jitter = %v", j)
		}
	}
	if jitter(0) != 0 || jitter(2) != 2 {
		t.Error("tiny durations changed")
	}
}

// removal records the uninstall instructions it gets.
type removal struct {
	got    []*agentproto.SignedUninstall
	inline bool
}

func (r *removal) Apply(_ context.Context, u *agentproto.SignedUninstall) bool {
	r.got = append(r.got, u)
	return r.inline
}

// An uninstall instruction goes to the removal and nothing else happens:
// no inventory, no MeshAgent install, no EasyPatch agent (ADR-0050).
func TestUninstallInstruction(t *testing.T) {
	s := &server{available: true, invHash: "other", uninstall: `{"payload":"cA==","signature":"cw=="}`, easyPatch: `{"payload":"e30=","signature":"cw=="}`}
	m := &mesh{}
	r := newRunner(t, s, m)
	rm := &removal{}
	r.Removal = rm
	ep := &easyPatch{}
	r.EasyPatch = ep
	r.Inventory = func(context.Context) agentproto.Inventory { return agentproto.Inventory{} }
	ctx := context.Background()
	wait, err := r.beat(ctx)
	if err != nil || wait <= 0 {
		t.Fatalf("beat: %v %v", wait, err)
	}
	if len(rm.got) != 1 || rm.got[0].Payload != "cA==" || rm.got[0].Signature != "cw==" {
		t.Errorf("removal got %+v", rm.got)
	}
	if m.installed || len(s.uploads) != 0 || len(ep.started) != 0 {
		t.Errorf("did more: MeshAgent %v, uploads %d, EasyPatch %d", m.installed, len(s.uploads), len(ep.started))
	}
	// Inline: the runner stops for the agent to uninstall itself.
	rm.inline = true
	if err := r.Run(ctx); !errors.Is(err, ErrRemoved) {
		t.Errorf("Run = %v", err)
	}
	// Without a removal the instruction is ignored, and still nothing else
	// happens.
	r.Removal = nil
	if _, err := r.beat(ctx); err != nil || m.installed {
		t.Errorf("beat without removal: %v, MeshAgent %v", err, m.installed)
	}
}

// A device moved to another site: the heartbeat announces the new settings'
// hash, and the agent fetches them, checks the signature and the hash, and
// reconfigures MeshAgent once (ADR-0069).
func TestBeatAppliesMovedSiteSettings(t *testing.T) {
	ctx := context.Background()
	sum := sha256.Sum256([]byte("MeshID=0x1"))
	good := hex.EncodeToString(sum[:])

	s := &server{available: true, settingsSHA: good}
	m := &mesh{installed: true, applied: "old"}
	r := newRunner(t, s, m)
	if _, err := r.beat(ctx); err != nil {
		t.Fatal(err)
	}
	if m.reconf != 1 || m.settings != "MeshID=0x1" || m.applied != good {
		t.Fatalf("MeshAgent = %+v", m)
	}
	// The agent reports what it applied, and applies nothing again.
	if _, err := r.beat(ctx); err != nil {
		t.Fatal(err)
	}
	if m.reconf != 1 || s.heartbeats[1].Facts.MeshSettingsSHA256 != good {
		t.Errorf("reconfigured %d times; reported %q", m.reconf, s.heartbeats[1].Facts.MeshSettingsSHA256)
	}

	// Settings that are not the ones announced, or not signed, are refused.
	for name, c := range map[string]func(*Runner, *server){
		"another hash":        func(_ *Runner, s *server) { s.settingsSHA = strings.Repeat("a", 64) },
		"changed on the way":  func(_ *Runner, s *server) { s.tamper = true },
		"no key pinned yet":   func(r *Runner, _ *server) { r.Key = func() ed25519.PublicKey { return nil } },
		"reconfiguring fails": nil,
	} {
		s := &server{available: true, settingsSHA: good}
		m := &mesh{installed: true, applied: "old"}
		if name == "reconfiguring fails" {
			m.reconfErr = errors.New("no permission")
		}
		r := newRunner(t, s, m)
		if c != nil {
			c(r, s)
		}
		if _, err := r.beat(ctx); err != nil {
			t.Fatal(err)
		}
		if m.reconf != 0 || m.applied != "old" || !strings.HasPrefix(r.status.MeshAgent, "settings update failed") {
			t.Errorf("%s: reconfigured %d, applied %q, status %q", name, m.reconf, m.applied, r.status.MeshAgent)
		}
	}
}
