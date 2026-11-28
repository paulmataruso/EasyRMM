package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// addressTLS is a server over TLS that answers the check as the EasyRMM
// server does, signing with job, and records the move reports it gets.
type addressTLS struct {
	*httptest.Server
	mu      sync.Mutex
	reports []agentproto.MoveReport
}

func newAddressTLS(t *testing.T, job ed25519.PrivateKey) *addressTLS {
	t.Helper()
	a := &addressTLS{}
	a.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, err := agentproto.Parse(r.Header.Get("Authorization"))
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case agentproto.PathAddress:
			var in agentproto.AddressRequest
			_ = json.NewDecoder(r.Body).Decode(&in)
			_ = json.NewEncoder(w).Encode(agentproto.SignAddress(job, auth, in.Address))
		case agentproto.PathMove:
			var in agentproto.MoveReport
			_ = json.NewDecoder(r.Body).Decode(&in)
			a.mu.Lock()
			a.reports = append(a.reports, in)
			a.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(a.Close)
	return a
}

func (a *addressTLS) got() []agentproto.MoveReport {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]agentproto.MoveReport(nil), a.reports...)
}

// enrolledHarness enrolls the harness's agent with the plain server, pins a
// job key and makes it trust the test TLS certificate through a CA file.
func enrolledHarness(t *testing.T, tlsSrv *httptest.Server, jobPub ed25519.PublicKey) (*harness, *httptest.Server) {
	t.Helper()
	linuxOnly(t)
	var beats atomic.Int32
	plain := fakeServer(t, &beats)
	h := newHarness(t)
	t.Setenv("EASYRMM_TOKEN", "ert_good")
	if err := h.run("enroll", "--server", plain.URL); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := h.e.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsSrv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.CAFile = ca
	cfg.PinFirstKey(agentproto.EncodeKey(jobPub), 1)
	if err := h.e.store.SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	return h, plain
}

func (h *harness) server(t *testing.T) string {
	t.Helper()
	cfg, _, err := h.e.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	return cfg.Server
}

func TestSetServerChecksThenSwitchesAndReports(t *testing.T) {
	pub, job, _ := ed25519.GenerateKey(rand.Reader)
	srv := newAddressTLS(t, job)
	h, plain := enrolledHarness(t, srv.Server, pub)

	if err := h.run("set-server", srv.URL); err != nil {
		t.Fatal(err)
	}
	if got := h.server(t); got != srv.URL {
		t.Errorf("agent.json names %q, want %q", got, srv.URL)
	}
	if !strings.Contains(h.out.String(), "now talks to "+srv.URL) || !strings.Contains(h.out.String(), "Restart the agent") {
		t.Errorf("output: %q", h.out)
	}
	reps := srv.got()
	if len(reps) != 1 || !reps[0].Moved || reps[0].Kind != agentproto.MoveSetServer || reps[0].From != plain.URL || reps[0].To != srv.URL {
		t.Errorf("the server was told %+v", reps)
	}

	if err := h.run("status"); err != nil || !strings.Contains(h.out.String(), "Server:     "+srv.URL) || !strings.Contains(h.out.String(), "Previous:   "+plain.URL) {
		t.Errorf("status: %q %v", h.out, err)
	}
	// Again to the same address: nothing to do.
	if err := h.run("set-server", srv.URL+"/"); err != nil || !strings.Contains(h.out.String(), "already at") {
		t.Errorf("same address: %q %v", h.out, err)
	}
}

func TestSetServerRefusesWhatDoesNotConfirmOrIsNotHTTPS(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, otherJob, _ := ed25519.GenerateKey(rand.Reader)
	// The address answers, but signs with a key the agent does not trust.
	imposter := newAddressTLS(t, otherJob)
	h, plain := enrolledHarness(t, imposter.Server, pub)

	if err := h.run("set-server", imposter.URL); err == nil || !strings.Contains(err.Error(), "did not confirm") {
		t.Errorf("an imposter: %v", err)
	}
	if got := h.server(t); got != plain.URL {
		t.Errorf("a failed check moved the agent to %q", got)
	}
	if _, ok := h.e.store.LoadAddresses().Previous(); ok {
		t.Error("a failed check recorded a previous address")
	}
	// The failure is reported at the address the agent is at: the plain one
	// has no such route here, which is dropped quietly. The imposter hears nothing.
	if len(imposter.got()) != 0 {
		t.Errorf("the address that failed the check was sent %+v", imposter.got())
	}

	for _, args := range [][]string{
		nil, {"a", "b"}, {"http://" + strings.TrimPrefix(imposter.URL, "https://")}, {"rmm.example.com"}, {"https://rmm.example.com/path"},
	} {
		if err := h.run(append([]string{"set-server"}, args...)...); err == nil {
			t.Errorf("set-server %v accepted", args)
		}
	}
	// Not as root, nothing is changed.
	h.e.isRoot = func() bool { return false }
	if err := h.run("set-server", imposter.URL); err == nil || !strings.Contains(err.Error(), "as root") {
		t.Errorf("as a user: %v", err)
	}
	// An address nothing answers on.
	h.e.isRoot = func() bool { return true }
	dead := httptest.NewTLSServer(http.NotFoundHandler())
	url := dead.URL
	dead.Close()
	if err := h.run("set-server", url); err == nil {
		t.Error("an address nothing answers on was accepted")
	}
}

func TestInstallAgainAtAnAddressTheAgentMovedFromOrOneThatConfirms(t *testing.T) {
	pub, job, _ := ed25519.GenerateKey(rand.Reader)
	first := newAddressTLS(t, job)
	h, plain := enrolledHarness(t, first.Server, pub)
	if err := h.run("set-server", first.URL); err != nil {
		t.Fatal(err)
	}

	// The address it moved from: already enrolled, and the server is now elsewhere.
	if err := h.run("enroll", "--server", plain.URL); err != nil || !strings.Contains(h.out.String(), "Already enrolled; this server is now at "+first.URL) {
		t.Errorf("an address moved from: %q %v", h.out, err)
	}
	if got := h.server(t); got != first.URL {
		t.Errorf("that moved the agent to %q", got)
	}

	// Another address the same server confirms: the agent switches to it.
	second := newAddressTLS(t, job)
	if err := h.run("enroll", "--server", second.URL); err != nil || !strings.Contains(h.out.String(), "confirmed") {
		t.Fatalf("an address that confirms: %q %v", h.out, err)
	}
	if got := h.server(t); got != second.URL {
		t.Errorf("agent.json names %q", got)
	}
	if reps := second.got(); len(reps) != 1 || reps[0].Kind != agentproto.MoveInstall || !reps[0].Moved {
		t.Errorf("the report: %+v", reps)
	}

	// An address that does not confirm: refused as before, and nothing changes.
	_, otherJob, _ := ed25519.GenerateKey(rand.Reader)
	imposter := newAddressTLS(t, otherJob)
	if err := h.run("enroll", "--server", imposter.URL); err == nil || !strings.Contains(err.Error(), "uninstall") {
		t.Errorf("an imposter: %v", err)
	}
	if got := h.server(t); got != second.URL {
		t.Errorf("agent.json names %q", got)
	}
	// An address that is not https cannot be confirmed either.
	if err := h.run("enroll", "--server", "http://127.0.0.1:1"); err == nil || !strings.Contains(err.Error(), "uninstall") {
		t.Errorf("plain http: %v", err)
	}
}

func TestStatusShowsNoPreviousAddressBeforeAMove(t *testing.T) {
	pub, job, _ := ed25519.GenerateKey(rand.Reader)
	srv := newAddressTLS(t, job)
	h, _ := enrolledHarness(t, srv.Server, pub)
	if err := h.run("status"); err != nil || strings.Contains(h.out.String(), "Previous:") {
		t.Errorf("status: %q %v", h.out, err)
	}
}
