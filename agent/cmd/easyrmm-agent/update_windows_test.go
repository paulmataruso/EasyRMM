//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/agent/host"
	"github.com/paulmataruso/easyrmm/agent/state"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// fleet is a server of the agent protocol for one update: it enrolls
// devices, checks each signed request against the key the device enrolled
// with, delivers one job, and, once told to, tells devices to update to
// one build. A job's result is taken only from that build, so the run the
// build before it finished stays in its journal across the update.
type fleet struct {
	*httptest.Server
	t       *testing.T
	jobKey  ed25519.PrivateKey
	build   []byte
	version string // the build's
	file    string

	mu       sync.Mutex
	keys     map[string]ed25519.PublicKey // by device
	beats    map[string]int               // by device and agent version
	invHash  map[string]string
	jobSent  bool
	runID    string
	tries    int               // results offered
	results  map[string]string // the version that reported each run
	updating bool
	updateID string
	failures []string // updates the agents reported failing
}

func newFleet(t *testing.T, build []byte, version string) *fleet {
	t.Helper()
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	f := &fleet{
		t: t, jobKey: key, build: build, version: version,
		file: fmt.Sprintf("easyrmm-agent-windows-%s.exe", runtime.GOARCH),
		keys: map[string]ed25519.PublicKey{}, beats: map[string]int{}, invHash: map[string]string{},
		results: map[string]string{}, runID: uuid.NewString(), updateID: uuid.NewString(),
	}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	return f
}

func (f *fleet) publicJobKey() string {
	return agentproto.EncodeKey(f.jobKey.Public().(ed25519.PublicKey))
}

// device checks a signed request and returns the device and its body.
func (f *fleet) device(r *http.Request) (string, []byte, bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	if err != nil {
		return "", nil, false
	}
	a, err := agentproto.Parse(r.Header.Get("Authorization"))
	if err != nil {
		return "", nil, false
	}
	f.mu.Lock()
	key := f.keys[a.Device]
	f.mu.Unlock()
	if !a.Verify(key, r.Method, r.URL.RequestURI(), body) || !a.Fresh(time.Now()) {
		return "", nil, false
	}
	return a.Device, body, true
}

func reply(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fleet) serve(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if path == agentproto.PathEnroll {
		var in agentproto.EnrollRequest
		pub, err := []byte(nil), json.NewDecoder(r.Body).Decode(&in)
		if err == nil {
			pub, err = base64.StdEncoding.DecodeString(in.PublicKey)
		}
		if err != nil || in.Token != "ert_good" || len(pub) != ed25519.PublicKeySize {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":{"code":"token_invalid","message":"no"}}`)
			return
		}
		f.mu.Lock()
		id := fmt.Sprintf("dev-%d", len(f.keys)+1)
		f.keys[id] = pub
		f.mu.Unlock()
		reply(w, agentproto.EnrollResponse{DeviceID: id, HeartbeatSeconds: agentproto.MinHeartbeatSeconds, JobKey: f.publicJobKey()})
		return
	}
	if path == agentproto.PathAgentDownload(f.file) {
		_, _ = w.Write(f.build)
		return
	}
	dev, body, ok := f.device(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":{"code":"unauthorized","message":"bad signature"}}`)
		return
	}
	agent := strings.TrimPrefix(r.UserAgent(), "easyrmm-agent/")
	switch {
	case path == agentproto.PathHeartbeat:
		var in agentproto.HeartbeatRequest
		_ = json.Unmarshal(body, &in)
		f.mu.Lock()
		f.beats[dev+" "+in.Facts.AgentVersion]++
		if in.Update != nil {
			f.failures = append(f.failures, in.Update.Error)
		}
		resp := agentproto.HeartbeatResponse{Protocol: agentproto.Protocol, HeartbeatSeconds: agentproto.MinHeartbeatSeconds,
			JobKey: f.publicJobKey(), InventoryHash: f.invHash[dev]}
		if f.updating {
			sum := sha256.Sum256(f.build)
			u, err := agentproto.SignUpdate(f.jobKey, agentproto.UpdatePayload{
				V: agentproto.UpdatePayloadVersion, ID: f.updateID, DeviceID: dev, File: f.file, Size: int64(len(f.build)),
				SHA256: hex.EncodeToString(sum[:]), Version: f.version, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(10 * time.Minute).UTC(),
			})
			if err != nil {
				f.t.Error(err)
			}
			resp.Update = &u
		}
		f.mu.Unlock()
		reply(w, resp)
	case path == agentproto.PathInventory:
		var inv agentproto.Inventory
		_ = json.Unmarshal(body, &inv)
		h := inv.Hash()
		f.mu.Lock()
		f.invHash[dev] = h
		f.mu.Unlock()
		reply(w, agentproto.InventoryResponse{Hash: h})
	case path == agentproto.PathJobsPoll:
		f.mu.Lock()
		send := !f.jobSent
		f.jobSent = true
		f.mu.Unlock()
		resp := agentproto.PollResponse{Jobs: []agentproto.SignedJob{}, Cancel: []string{}}
		if send {
			j, err := agentproto.SignJob(f.jobKey, agentproto.JobPayload{
				V: agentproto.JobPayloadVersion, RunID: f.runID, JobID: uuid.NewString(), DeviceID: dev,
				Shell: agentproto.ShellCmd, Script: "@echo before the update", Args: []string{}, TimeoutSeconds: 60,
				IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(10 * time.Minute).UTC(),
			})
			if err != nil {
				f.t.Error(err)
			}
			resp.Jobs = append(resp.Jobs, j)
		} else {
			select {
			case <-r.Context().Done():
			case <-time.After(2 * time.Second):
			}
		}
		reply(w, resp)
	case path == agentproto.PathJobStart(f.runID):
		reply(w, agentproto.StartResponse{Proceed: true})
	case path == agentproto.PathJobResult(f.runID):
		f.mu.Lock()
		f.tries++
		take := agent == f.version
		if take {
			f.results[f.runID] = agent
		}
		f.mu.Unlock()
		if !take {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, `{"error":{"code":"unavailable","message":"later"}}`)
			return
		}
		reply(w, struct{}{})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// heartbeats counts a device's heartbeats from an agent version.
func (f *fleet) heartbeats(dev, version string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.beats[dev+" "+version]
}

// buildVersion runs a build's version command and returns its version.
func buildVersion(t *testing.T, exe string) string {
	t.Helper()
	out, err := exec.Command(exe, "version").Output()
	f := strings.Fields(string(out))
	if err != nil || len(f) < 2 {
		t.Fatalf("%s version: %q, %v", exe, out, err)
	}
	return f[1]
}

// eventually waits until ok holds.
func eventually(t *testing.T, limit time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("after %s: %s did not happen", limit, what)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// TestUpdateFromBeforeTheStateCheck: an agent built from main before the
// state check (PR #61) is installed as administrator, as install.ps1 does,
// with its service, and enrolls; it runs a job, heartbeats and keeps its
// status and its job journal. The server then tells it to update to this
// build, which it does as any update: it downloads the build, puts it in
// place and stops, and Windows starts the service again. The new build's
// check, at the service's start, finds only state the agent wrote: it sets
// nothing aside and sets no access list back, and the agent goes on as the
// same device, with the same key, and reports the run its predecessor left
// in the journal.
//
// EASYRMM_TEST_AGENT_BEFORE and EASYRMM_TEST_AGENT_AFTER name the two builds,
// which must print different versions; CI builds them.
func TestUpdateFromBeforeTheStateCheck(t *testing.T) {
	p := machineTest(t)
	before, after := os.Getenv("EASYRMM_TEST_AGENT_BEFORE"), os.Getenv("EASYRMM_TEST_AGENT_AFTER")
	if before == "" || after == "" {
		t.Fatal("set EASYRMM_TEST_AGENT_BEFORE and EASYRMM_TEST_AGENT_AFTER to the builds before and after the state check")
	}
	if st := (host.WindowsServices{}).State(t.Context(), host.AgentWindowsService); st != "not installed" {
		t.Fatalf("the %s service is %s: the test needs a computer without the agent", host.AgentWindowsService, st)
	}
	oldVersion, newVersion := buildVersion(t, before), buildVersion(t, after)
	if oldVersion == newVersion {
		t.Fatalf("both builds say they are %s", oldVersion)
	}
	build, err := os.ReadFile(after)
	if err != nil {
		t.Fatal(err)
	}
	f := newFleet(t, build, newVersion)
	dir, top := p.State(), filepath.Dir(p.State())
	agentLog := filepath.Join(p.Logs(), logName)
	t.Cleanup(func() {
		if t.Failed() {
			b, _ := os.ReadFile(agentLog)
			t.Logf("the agent's log:\n%s", b)
		}
		// Whichever build is installed removes the agent and its service.
		if out, err := exec.Command(p.Binary(), "uninstall").CombinedOutput(); err != nil {
			t.Logf("uninstall: %v\n%s", err, out)
			_ = (host.WindowsServices{}).Remove(context.Background(), host.AgentWindowsService)
		}
	})

	cmd := exec.Command(before, "install", "--server", f.URL)
	cmd.Env = append(os.Environ(), "EASYRMM_TOKEN=ert_good")
	if out, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(out), "Enrolled with "+f.URL+" as device dev-1") {
		t.Fatalf("installing the build before the check: %v\n%s", err, out)
	}

	// The build before the check runs as the service and writes its state.
	journal := filepath.Join(dir, "jobs", "journal", f.runID+".json")
	eventually(t, 3*time.Minute, "the build before the check heartbeats, runs the job and keeps its status and journal", func() bool {
		f.mu.Lock()
		tried := f.tries > 0
		f.mu.Unlock()
		_, st := os.Stat(filepath.Join(dir, "status.json"))
		_, jr := os.Stat(journal)
		return f.heartbeats("dev-1", oldVersion) > 0 && tried && st == nil && jr == nil
	})
	key, err := os.ReadFile(filepath.Join(dir, "device.key"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := os.ReadFile(filepath.Join(dir, "agent.json"))
	if err != nil {
		t.Fatal(err)
	}
	security := map[string]string{}
	for _, d := range []string{top, dir} {
		security[d] = securityOf(t, d)
	}
	logged, err := os.ReadFile(agentLog)
	if err != nil {
		t.Fatalf("the build before the check keeps no log: %v", err)
	}
	f.mu.Lock()
	f.updating = true
	f.mu.Unlock()

	// It updates itself; Windows starts the service again with this build.
	eventually(t, 5*time.Minute, "this build heartbeats as the same device and reports the journal's run", func() bool {
		f.mu.Lock()
		reported := f.results[f.runID] == newVersion
		f.mu.Unlock()
		_, marker := os.Stat(filepath.Join(dir, "update.json"))
		return f.heartbeats("dev-1", newVersion) > 0 && reported && os.IsNotExist(marker)
	})

	f.mu.Lock()
	devices, failures := len(f.keys), f.failures
	f.mu.Unlock()
	if devices != 1 || len(failures) != 0 {
		t.Errorf("%d devices enrolled, update failures %q; want one device, updated", devices, failures)
	}
	if installed, err := os.ReadFile(p.Binary()); err != nil || !bytes.Equal(installed, build) {
		t.Errorf("the installed build is not this one: %v", err)
	}
	if m := untrusted(p); len(m) != 0 {
		t.Errorf("the check set aside %v", m)
	}
	for d, before := range security {
		if now := securityOf(t, d); now != before {
			t.Errorf("the access list of %s changed:\nbefore %s\nafter  %s", d, before, now)
		}
	}
	if now, err := os.ReadFile(filepath.Join(dir, "device.key")); err != nil || !bytes.Equal(now, key) {
		t.Errorf("the device key changed: %v", err)
	}
	var c state.Config
	if now, err := os.ReadFile(filepath.Join(dir, "agent.json")); err != nil || json.Unmarshal(now, &c) != nil || c.DeviceID != "dev-1" {
		t.Errorf("the enrollment changed: %v\nbefore %s\nafter  %s", err, cfg, now)
	}
	all, err := os.ReadFile(agentLog)
	if err != nil || len(all) < len(logged) {
		t.Fatalf("the agent's log: %v", err)
	}
	since := string(all[len(logged):])
	if !strings.Contains(since, "EasyRMM agent started") || !strings.Contains(since, "version="+newVersion) || !strings.Contains(since, "device_id=dev-1") {
		t.Errorf("this build did not log its start as dev-1:\n%s", since)
	}
	if strings.Contains(since, "moved aside") || strings.Contains(since, "set back") {
		t.Errorf("this build's check changed the state:\n%s", since)
	}
}
