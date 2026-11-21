//go:build integration

package remote

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/agents"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/devices"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/agentapi"
	"github.com/paulmataruso/easyrmm/server/internal/inventory"
	"github.com/paulmataruso/easyrmm/server/internal/jobs"
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
func (r *rig) serveAgentAPI(svc *agents.Service, j *jobs.Service, inv *inventory.Service) string {
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
	api, err := agentapi.New(svc, &agents.Builds{}, []agentapi.Address{{URL: server}}, nil, r.log)
	if err != nil {
		r.t.Fatal(err)
	}
	if j != nil {
		api.WithJobs(j)
	}
	if inv != nil {
		api.WithInventory(inv)
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
	_, jobKey, _ := ed25519.GenerateKey(rand.Reader)
	js := jobs.New(r.db, r.audit, jobKey, 24*time.Hour, 24*time.Hour, r.log)
	t.Cleanup(js.Close)
	svc.SetJobKey(js.PublicKey())
	// The job key also signs uninstall instructions (ADR-0050); no builds
	// to update to.
	svc.SetUpdates(&agents.Builds{}, jobKey)
	invs := inventory.New(r.db, 24*time.Hour, r.log)
	server := r.serveAgentAPI(svc, js, invs)
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
		// The agent's folders belong to its user and are private to it, so
		// only that user can remove them when the tests run unprivileged.
		_, _ = exec.Command("docker", "run", "--rm", "--user", "65534:65534", "-v", dir+":/agent", image, "rm", "-rf", "/agent/root").CombinedOutput()
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

	// The agent pinned the server's job key at enrollment.
	var cfg struct {
		JobKey string `json:"jobKey"`
	}
	// Read as the agent's user: its settings are private to it (mode 0600).
	b := docker(t, "exec", name, "cat", "/agent/root/var/lib/easyrmm-agent/agent.json")
	if err := json.Unmarshal([]byte(b), &cfg); err != nil || cfg.JobKey != js.PublicKey() {
		t.Errorf("pinned job key %q, server's %q (%v)", cfg.JobKey, js.PublicKey(), err)
	}

	// The agent reports the container's inventory and metrics (ADR-0018).
	var report *inventory.Device
	r.waitFor(time.Minute, "the device's inventory and metrics", func() bool {
		report, err = invs.Get(r.ctx, tech, dev.ID)
		return err == nil && report.Inventory != nil && report.Metrics != nil
	})
	if inv := report.Inventory; inv.OS.ID != "debian" || inv.OS.Kernel == "" || inv.PackageManager != "dpkg" || inv.PackageCount < 50 ||
		inv.System.Virtualization != "container" || inv.CPU.Threads == 0 || inv.MemoryBytes == 0 || len(inv.Interfaces) == 0 {
		t.Errorf("inventory %+v", inv)
	}
	if m := report.Metrics; m.MemoryTotal == 0 || m.Processes == 0 || m.UptimeSeconds == 0 || len(m.Filesystems) == 0 || m.Filesystems[0].Mount != "/" {
		t.Errorf("metrics %+v", m)
	}
	if sw, err := invs.Software(r.ctx, tech, dev.ID); err != nil || !slices.ContainsFunc(sw, func(p agentproto.Package) bool { return p.Name == "bash" }) {
		t.Errorf("software without bash (%d packages): %v", len(sw), err)
	}
	if h, err := invs.Hash(r.ctx, dev.ID); err != nil || len(h) != 64 {
		t.Errorf("stored hash %q %v", h, err)
	}
	if st := docker(t, "exec", "-e", "EASYRMM_AGENT_ROOT=/agent/root", name, "/agent/easyrmm-agent", "status"); !strings.Contains(st, "Inventory:  sent") {
		t.Errorf("status:\n%s", st)
	}

	// A script runs on the device and reports its output (ADR-0017).
	sc, err := js.CreateScript(r.ctx, r.sys, jobs.ScriptInput{OrganizationID: &acme.ID, Name: "Who am I", Shell: "bash",
		Body: "echo \"args: $1|$2\"\necho \"uid $(id -u) in $PWD\"\necho warning >&2\nexit 4\n"})
	if err != nil {
		t.Fatal(err)
	}
	job, err := js.CreateJob(r.ctx, tech, jobs.JobInput{ScriptID: sc.ID, DeviceIDs: []uuid.UUID{dev.ID}, Args: []string{"one", "two words"}})
	if err != nil {
		t.Fatal(err)
	}
	var run *jobs.Run
	r.waitFor(time.Minute, "the script to finish on the device", func() bool {
		run, err = js.GetRun(r.ctx, tech, job.Runs[0].ID)
		return err == nil && run.FinishedAt != nil
	})
	out, err := js.ReadOutput(r.ctx, tech, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != jobs.StatusFailed || run.ExitCode == nil || *run.ExitCode != 4 || out.Stderr != "warning\n" ||
		!strings.HasPrefix(out.Stdout, "args: one|two words\nuid 65534 in /agent/root/var/lib/easyrmm-agent/jobs/work/run-") || run.StartedAt == nil {
		t.Errorf("run %+v\nstdout %q stderr %q", run, out.Stdout, out.Stderr)
	}

	// A long script stops when canceled.
	slow, err := js.CreateScript(r.ctx, r.sys, jobs.ScriptInput{Name: "Slow", Shell: "sh", Body: "echo started; sleep 600"})
	if err != nil {
		t.Fatal(err)
	}
	job, err = js.CreateJob(r.ctx, tech, jobs.JobInput{ScriptID: slow.ID, DeviceIDs: []uuid.UUID{dev.ID}})
	if err != nil {
		t.Fatal(err)
	}
	r.waitFor(time.Minute, "the slow script to start", func() bool {
		run, err = js.GetRun(r.ctx, tech, job.Runs[0].ID)
		return err == nil && run.Status == jobs.StatusRunning
	})
	if _, err := js.CancelJob(r.ctx, tech, job.ID); err != nil {
		t.Fatal(err)
	}
	r.waitFor(time.Minute, "the canceled script to stop", func() bool {
		run, err = js.GetRun(r.ctx, tech, job.Runs[0].ID)
		return err == nil && run.FinishedAt != nil
	})
	if out, err = js.ReadOutput(r.ctx, tech, run.ID); err != nil || run.Status != jobs.StatusCanceled || out.Stdout != "started\n" {
		t.Errorf("canceled run %+v, output %+v, %v", run, out, err)
	}
	ps := docker(t, "exec", name, "sh", "-c", `for p in /proc/[0-9]*; do tr '\0' ' ' < $p/cmdline 2>/dev/null; echo; done | grep -c '^sleep 600' || true`)
	if strings.TrimSpace(ps) != "0" {
		t.Errorf("the canceled script is still running (%s processes)", strings.TrimSpace(ps))
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

	// Removed from the console (ADR-0050): started again, the agent gets the
	// instruction with its heartbeat. With no service to leave, it removes
	// MeshAgent and itself in its own process, reports, and exits; the
	// device is deleted, and MeshCentral forgets its node.
	docker(t, "start", name)
	r.waitFor(2*time.Minute, "both agents to be back", func() bool {
		d, err := r.dev.Get(r.ctx, tech, dev.ID)
		return err == nil && d.Agent != nil && d.Agent.Online && d.RemoteOnline
	})
	if st, err := svc.RequestRemoval(r.ctx, r.sys, dev.ID); err != nil || st != agents.RemovalAsked {
		t.Fatalf("asking for the removal: %q %v", st, err)
	}
	r.waitFor(2*time.Minute, "the agent to remove itself and the device to go", func() bool {
		_, err := r.dev.Get(r.ctx, tech, dev.ID)
		return errors.Is(err, apperr.ErrNotFound)
	})
	if n := r.count(`SELECT count(*) FROM audit_log WHERE action = 'device.remove' AND device_id = $1 AND actor_type = 'agent'
			AND details->>'confirmed' = 'true'`, dev.ID); n != 1 {
		t.Errorf("removal audit records = %d", n)
	}
	r.waitFor(time.Minute, "the agent's container to exit", func() bool {
		return strings.TrimSpace(docker(t, "inspect", "-f", "{{.State.Status}}", name)) == "exited"
	})
	if code := strings.TrimSpace(docker(t, "inspect", "-f", "{{.State.ExitCode}}", name)); code != "0" {
		t.Errorf("the agent exited with %s", code)
	}
	if logs := docker(t, "logs", "--tail", "20", name); !strings.Contains(logs, "EasyRMM agent removed on the server's instruction.") {
		t.Errorf("agent output:\n%s", logs)
	}
	left := docker(t, "run", "--rm", "--user", "65534:65534", "-v", dir+":/agent", image, "sh", "-c",
		"ls -A /agent/root/var/lib/easyrmm-agent /agent/root/usr/local/lib/easyrmm-agent 2>/dev/null; true")
	if strings.TrimSpace(left) != "" {
		t.Errorf("left on the computer:\n%s", left)
	}
	r.waitFor(3*time.Minute, "MeshCentral to forget the node", func() bool {
		return r.count(`SELECT count(*) FROM retired_devices WHERE device_id = $1 AND mesh_node_id = $2 AND mesh_removed_at IS NOT NULL`,
			dev.ID, dev.MeshNodeID) == 1
	})
	nodes, err := r.mesh.Nodes(r.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(nodes, func(n meshcentral.Node) bool { return n.ID == dev.MeshNodeID }) {
		t.Error("the node is still in MeshCentral")
	}
	if err := r.svc.SyncDevices(r.ctx); err != nil {
		t.Fatal(err)
	}
	if list, err := r.dev.List(r.ctx, tech, devices.Query{}); err != nil || len(list) != 0 {
		t.Errorf("devices after the removal: %d %v", len(list), err)
	}
}
