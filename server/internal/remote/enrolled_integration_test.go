//go:build integration

package remote

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/agents"
	"github.com/paulmataruso/easyrmm/server/internal/devices"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/agentapi"
	"github.com/paulmataruso/easyrmm/server/internal/meshcentral"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// buildAgent compiles the EasyRMM agent for Linux into dir.
func buildAgent(t *testing.T, dir string) string {
	t.Helper()
	mod, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "easyrmm-agent")
	cmd := exec.Command("go", "build", "-trimpath", "-o", out, "./agent/cmd/easyrmm-agent")
	cmd.Dir = filepath.Dir(strings.TrimSpace(string(mod)))
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building the agent: %v\n%s", err, b)
	}
	return out
}

// serveAgentAPI serves the agent API over TLS on loopback with the test
// certificate, as the EasyRMM server's public hostname would.
func (r *rig) serveAgentAPI(svc *agents.Service) string {
	r.t.Helper()
	cert, err := tls.LoadX509KeyPair(r.env.CertFile, r.env.KeyFile)
	if err != nil {
		r.t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		r.t.Fatal(err)
	}
	server := "https://" + r.env.Hostname + ":" + strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	api, err := agentapi.New(svc, &agents.Builds{}, server, r.log)
	if err != nil {
		r.t.Fatal(err)
	}
	srv := &http.Server{Handler: api.Handler(), ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	r.t.Cleanup(func() { _ = srv.Close() })
	return server
}

// TestEnrolledAgentEndToEnd installs the real EasyRMM agent in a container
// with a deployment token. It enrolls, fetches MeshAgent and its settings
// through the server from MeshCentral, runs it, and reports MeshAgent's node
// id, after which the device is one record reachable by remote session.
func TestEnrolledAgentEndToEnd(t *testing.T) {
	image := os.Getenv("EASYRMM_TEST_AGENT_IMAGE")
	if image == "" {
		t.Fatal("EASYRMM_TEST_AGENT_IMAGE is not set (a glibc Linux image for the test agent; see the Makefile)")
	}
	r := newRig(t)
	acme := r.org("Acme")
	hq := r.site(acme.ID, "HQ")
	techID, tech := r.user("Tess Tech", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: acme.ID, SiteID: hq.ID})
	r.reconcile()

	upstream, _ := url.Parse(r.env.URL)
	g, err := NewGateway(r.svc, GatewayConfig{Upstream: upstream, Secure: true, CacheTTL: 200 * time.Millisecond}, r.log)
	if err != nil {
		t.Fatal(err)
	}
	r.serveGateway(g)
	go r.svc.Run(r.ctx)

	files, err := meshcentral.NewFiles(r.env.URL, r.env.Key)
	if err != nil {
		t.Fatal(err)
	}
	svc := agents.New(r.db, r.audit, NewMeshAgents(r.svc, files), r.log)
	server := r.serveAgentAPI(svc)
	tok, err := svc.CreateToken(r.ctx, r.sys, hq.ID, agents.TokenInput{Name: "End to end", ExpiresInDays: 1})
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil { //nolint:gosec // the agent runs as another user and keeps its files here
		t.Fatal(err)
	}
	buildAgent(t, dir)
	ca, err := os.ReadFile(r.env.CertFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.pem"), ca, 0o644); err != nil { //nolint:gosec // a public certificate
		t.Fatal(err)
	}
	name := "easyrmm-testenrolled-" + uuid.NewString()[:8]
	docker(t, "run", "-d", "--name", name, "--network", "host",
		"--add-host", r.env.Hostname+":127.0.0.1",
		"--user", "65534:65534", "--read-only", "--tmpfs", "/tmp", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges", "-v", dir+":/agent",
		"-e", "EASYRMM_AGENT_ROOT=/agent/root", "-e", "EASYRMM_TOKEN="+tok.Secret,
		image, "sh", "-c", "/agent/easyrmm-agent enroll --server "+server+" --ca-file /agent/ca.pem && exec /agent/easyrmm-agent run")
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("agent output:\n%s", docker(t, "logs", "--tail", "80", name))
		}
		_, _ = exec.Command("docker", "rm", "-f", name).CombinedOutput()
	})

	// The agent enrolls, installs MeshAgent and links it: one device, with
	// both agents connected.
	dev := &devices.Device{}
	r.waitFor(3*time.Minute, "the enrolled device to be linked to its MeshAgent", func() bool {
		list, err := r.dev.List(r.ctx, tech, devices.Query{})
		if err != nil || len(list) != 1 {
			return false
		}
		dev = list[0]
		return dev.Agent != nil && dev.RemoteAgent && dev.RemoteOnline
	})
	if !dev.Agent.Online || !dev.Online || !dev.CanTerminal || dev.Platform != "linux" || !strings.Contains(dev.OSDescription, "Debian") ||
		dev.Agent.Arch != "amd64" || dev.SiteID != hq.ID {
		t.Errorf("device = %+v, agent %+v", dev, dev.Agent)
	}
	// The link is to the MeshAgent in this container.
	printed := docker(t, "exec", name, "sh", "-c", "cd /agent/root/usr/local/lib/easyrmm-agent/meshagent && ./meshagent -nodeid")
	if key, err := agentproto.MeshNodeKey(printed); err != nil || key != dev.MeshNodeID {
		t.Errorf("container's node id %q (%v), device's %q", key, err, dev.MeshNodeID)
	}
	if n := r.count(`SELECT count(*) FROM audit_log WHERE action = 'device.enroll' AND device_id = $1`, dev.ID); n != 1 {
		t.Errorf("enrollment audit records = %d", n)
	}
	if n := r.count(`SELECT count(*) FROM audit_log WHERE action = 'device.remote_link' AND device_id = $1`, dev.ID); n != 1 {
		t.Errorf("link audit records = %d", n)
	}
	st := docker(t, "exec", "-e", "EASYRMM_AGENT_ROOT=/agent/root", name, "/agent/easyrmm-agent", "status")
	if !strings.Contains(st, "Device:     "+dev.ID.String()) || !strings.Contains(st, "MeshAgent:  installed") {
		t.Errorf("status:\n%s", st)
	}

	// A remote session can start on the enrolled device.
	if _, err := r.svc.StartSession(r.ctx, tech, r.session(techID), dev.ID, KindTerminal); err != nil {
		t.Fatalf("starting a session on the enrolled device: %v", err)
	}

	// Stopping the container takes both agents offline; the enrolled device
	// stays.
	docker(t, "stop", "-t", "5", name)
	// MeshCentral reports the disconnection as an event; the refresh it
	// triggers must not wait for the periodic sync (five minutes).
	r.waitFor(30*time.Second, "MeshAgent to be reported offline", func() bool {
		d, err := r.dev.Get(r.ctx, tech, dev.ID)
		return err == nil && !d.RemoteOnline
	})
	if d, err := r.dev.Get(r.ctx, tech, dev.ID); err != nil || d.Agent == nil {
		t.Errorf("enrolled device after stopping: %+v, %v", d, err)
	}
}
