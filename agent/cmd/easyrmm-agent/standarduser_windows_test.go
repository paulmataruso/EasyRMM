//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"io/fs"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/agent/state"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// plantedServer is a server of the user's: a TLS listener whose certificate
// only its own authority vouches for, which the user plants as the agent's.
type plantedServer struct {
	*httptest.Server
	ca        []byte // its authority, PEM
	completed atomic.Int32
}

func newPlantedServer(t *testing.T) *plantedServer {
	t.Helper()
	s := &plantedServer{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"heartbeatSeconds":600,"meshAgent":{"available":false}}`)
	}))
	// A connection counts once its TLS handshake has completed: one the
	// agent refused never does.
	var seen sync.Map
	srv.Config.ConnState = func(c net.Conn, st http.ConnState) {
		tc, ok := c.(*tls.Conn)
		if !ok || st == http.StateNew || !tc.ConnectionState().HandshakeComplete {
			return
		}
		if _, dup := seen.LoadOrStore(c, true); !dup {
			s.completed.Add(1)
		}
	}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // refused handshakes are expected
	srv.StartTLS()
	t.Cleanup(srv.Close)
	s.Server = srv
	s.ca = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	return s
}

// TestStandardUserPlantsState: a standard user, before the agent is
// installed, makes the agent's state folder under ProgramData and leaves
// there an enrollment naming a server of theirs, with that server's own
// authority and a job key of theirs; or an enrollment waiting for approval;
// or a junction at logs. Then an administrator installs, naming that server.
// The same again where an administrator made the folder before, with the
// access list it inherits from ProgramData, and the user only made what is
// in it. Each time the check sets the user's folder aside: the agent never
// completes a TLS connection to that server, writes nothing through the
// junction, and the user cannot write in the folder the agent made instead.
//
// The account is a real one, made for the run; the helper that plants runs
// with its own token, so what it makes has the owner and access list Windows
// gives a standard user's files.
func TestStandardUserPlantsState(t *testing.T) {
	p := machineTest(t)
	u := newStandardUser(t)
	dir := p.State()
	top := filepath.Dir(dir)
	_, jobKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name string
		// files are what the user leaves, given the server; planted is the
		// entry that must be set aside.
		files    func(srv *plantedServer) map[string]string
		junction bool
		planted  string
	}{
		{name: "an enrollment", planted: "agent.json", files: func(srv *plantedServer) map[string]string {
			cfg, _ := json.Marshal(state.Config{
				Server: srv.URL, CAFile: filepath.Join(dir, "ca.pem"), DeviceID: "planted", EnrolledAt: time.Now().UTC(),
				MeshAgentMode: "child", JobKey: agentproto.EncodeKey(jobKey.Public().(ed25519.PublicKey)),
			})
			return map[string]string{"agent.json": string(cfg), "device.key": plantedKey, "ca.pem": string(srv.ca)}
		}},
		{name: "a pending enrollment", planted: "pending.json", files: func(srv *plantedServer) map[string]string {
			pending, _ := json.Marshal(state.Pending{
				Server: srv.URL, CAFile: filepath.Join(dir, "ca.pem"), MeshAgentMode: "child",
				Token: "ert_planted", Code: "PLANTED", Since: time.Now().UTC(),
			})
			return map[string]string{"pending.json": string(pending), "device.key": plantedKey, "ca.pem": string(srv.ca)}
		}},
		{name: "a junction at logs", planted: "logs", junction: true},
	} {
		for _, adminMade := range []bool{false, true} {
			name := c.name + ", in folders the user made"
			if adminMade {
				name = c.name + ", in a folder an administrator made"
			}
			t.Run(name, func(t *testing.T) {
				t.Cleanup(func() { removeAgentFolders(t, p) })
				srv := newPlantedServer(t)
				if adminMade {
					// As an administrator would without the agent: the
					// folders inherit ProgramData's list, under which every
					// user may add files.
					if err := os.MkdirAll(dir, 0o755); err != nil {
						t.Fatal(err)
					}
				}
				ops := []string{"mkdir", dir}
				if c.files != nil {
					stage := filepath.Join(t.TempDir(), "stage")
					mkdirACL(t, stage, readableByUsers)
					for name, content := range c.files(srv) {
						if err := os.WriteFile(filepath.Join(stage, name), []byte(content), 0o600); err != nil {
							t.Fatal(err)
						}
						ops = append(ops, "copy", filepath.Join(stage, name), filepath.Join(dir, name))
					}
				}
				elsewhere := t.TempDir()
				if c.junction {
					ops = append(ops, "junction", filepath.Join(dir, "logs"), elsewhere)
				}
				if err := u.run(t, ops...); err != nil {
					t.Fatalf("planting as the user: %v", err)
				}
				if o := owner(t, filepath.Join(dir, c.planted)); !o.Equals(u.sid) {
					t.Fatalf("%s is owned by %s, not by the user %s", c.planted, o, u.sid)
				}

				// The install, as install.ps1 runs it, with a stand-in for the
				// service manager.
				h := newHarness(t)
				var logged bytes.Buffer
				h.e.paths, h.e.sd = p, &services{}
				h.e.log = slog.New(slog.NewTextHandler(&logged, nil))
				installErr := h.run("install", "--server", srv.URL, "--token", "ert_test")
				installed := h.out.String()

				// Then the service's start: it opens its log, and runs.
				h.e.store = state.Store{}
				lf, logErr := h.e.openServiceLog()
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				done := make(chan error, 1)
				go func() { done <- h.e.run(ctx) }()
				var runErr error
			wait:
				for {
					select {
					case runErr = <-done:
						break wait
					case <-time.After(100 * time.Millisecond):
						if srv.completed.Load() > 0 {
							cancel()
						}
					}
				}
				cancel()
				if lf != nil {
					_ = lf.Close()
				}

				if n := srv.completed.Load(); n != 0 {
					t.Errorf("the user's server completed %d TLS connections: the agent trusted the planted authority", n)
				}
				if installErr == nil || !strings.Contains(installErr.Error(), "certificate") || strings.Contains(installed, "Already") {
					t.Errorf("install: %v, %q; want it to enroll anew, and fail to trust the user's server", installErr, installed)
				}
				if logErr != nil || !errors.Is(runErr, state.ErrNotEnrolled) {
					t.Errorf("the service's start: log %v, run %v; want an agent that is not enrolled", logErr, runErr)
				}
				if left, _ := os.ReadDir(elsewhere); len(left) != 0 {
					t.Errorf("written where the junction pointed: %v", left)
				}

				// What the user made is set aside, whole: the folder they made,
				// or, in the administrator's folder they could write in, that.
				moved, inside := top, filepath.Join(filepath.Base(dir), c.planted)
				if adminMade {
					moved, inside = dir, c.planted
				}
				m, _ := filepath.Glob(moved + ".untrusted-*")
				if len(m) != 1 {
					t.Fatalf("%s moved aside to %v", moved, m)
				}
				if _, err := os.Lstat(filepath.Join(m[0], inside)); err != nil {
					t.Errorf("the planted %s is not where it was set aside: %v", c.planted, err)
				}
				if !strings.Contains(logged.String(), "moved aside") {
					t.Errorf("nothing logged: %s", logged.String())
				}
				// The service made its own logs folder, a plain one.
				if fi, err := os.Lstat(filepath.Join(dir, c.planted)); c.junction && (err != nil || fi.Mode().Type() != fs.ModeDir) {
					t.Errorf("logs in the agent's folder: %v, %v; want the agent's own folder", fi, err)
				} else if !c.junction && !errors.Is(err, fs.ErrNotExist) {
					t.Errorf("%s is in the agent's folder: %v", c.planted, err)
				}

				// The folders the agent made instead keep the user out.
				for _, d := range []string{dir, top} {
					if err := u.run(t, "create", filepath.Join(d, "planted.txt")); !errors.Is(err, errDenied) {
						t.Errorf("as the user, creating a file in %s: %v; want access denied", d, err)
					}
				}
			})
		}
	}
}
