//go:build integration

package app_test

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/agent/channel"
	agentclient "github.com/paulmataruso/easyrmm/agent/client"
	"github.com/paulmataruso/easyrmm/agent/host"
	agentjobs "github.com/paulmataruso/easyrmm/agent/jobs"
	"github.com/paulmataruso/easyrmm/agent/logship"
	"github.com/paulmataruso/easyrmm/agent/runner"
	"github.com/paulmataruso/easyrmm/agent/state"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/config"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
)

// The real agent (runner, job worker, log shipper and channel) against the
// real server (every service wired as the app wires them, ADR-0059, M1 to
// M5), over a real database. The console API causes each push, as a
// technician would.

// countingTransport counts the agent's requests by path.
type countingTransport struct {
	next http.RoundTripper
	mu   sync.Mutex
	n    map[string]int
}

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.mu.Lock()
	c.n[r.URL.Path]++
	c.mu.Unlock()
	return c.next.RoundTrip(r)
}

func (c *countingTransport) count(path string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n[path]
}

type chanFixture struct {
	t        *testing.T
	h        *harness
	admin    *client
	org      string
	site     string
	deviceID string
	key      ed25519.PrivateKey
	device   string // the console path
}

// newChanFixture builds the server (with the channel on or off), its hub
// running, and an enrolled device.
func newChanFixture(t *testing.T, channelOn bool) *chanFixture {
	t.Helper()
	remote := withRemote(t)
	h := newHarnessWith(t, false, func(c *config.Config) {
		remote(c)
		c.AgentChannel = channelOn
	})
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Go(func() { h.deps.AgentChannel.Run(ctx) })
	t.Cleanup(func() { cancel(); wg.Wait() })
	admin, _ := setUp(t, h)
	acme := orgID(t, admin, "Acme")
	var hq idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/sites", map[string]string{"name": "HQ", "timezone": "UTC"}, &hq)
	var tok struct {
		Secret string `json:"secret"`
	}
	admin.expect(http.StatusCreated, "POST", "/api/v1/sites/"+hq.ID+"/enrollment-tokens", map[string]any{"name": "t", "expiresInDays": 1}, &tok)
	key := newKey(t)
	enr, err := h.agentClient().Enroll(context.Background(), tok.Secret, key.Public().(ed25519.PublicKey), facts("chan-01"))
	if err != nil {
		t.Fatal(err)
	}
	return &chanFixture{t: t, h: h, admin: admin, org: acme, site: hq.ID, deviceID: enr.DeviceID, key: key,
		device: "/api/v1/devices/" + enr.DeviceID}
}

type chanAgent struct {
	r        *runner.Runner
	ch       *channel.Channel
	w        *agentjobs.Worker
	ship     *logship.Shipper
	requests *countingTransport
	beats    atomic.Int32
	settings atomic.Int32
	repairs  atomic.Int32
}

// startAgent runs an agent whose own heartbeat timer is an hour away, so that
// whatever reaches it before then came over the channel or a poll.
func (f *chanFixture) startAgent() *chanAgent {
	t := f.t
	tr := f.h.srv.Client().Transport.(*http.Transport).Clone()
	addr := f.h.srv.Listener.Addr().String()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	tr.TLSClientConfig = &tls.Config{RootCAs: tr.TLSClientConfig.RootCAs, ServerName: "example.com", MinVersion: tls.VersionTLS12}
	a := &chanAgent{requests: &countingTransport{next: tr, n: map[string]int{}}}
	c, err := agentclient.New(agentclient.Options{Server: publicOrigin, Version: "1.2.3-test", Transport: a.requests})
	if err != nil {
		t.Fatal(err)
	}
	c.SetIdentity(f.deviceID, f.key)
	store, _, err := state.Open(host.Paths{Root: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	var pinned atomic.Pointer[ed25519.PublicKey]
	pinnedKey := func() ed25519.PublicKey {
		if p := pinned.Load(); p != nil {
			return *p
		}
		return nil
	}
	buf, err := logship.OpenBuffer(t.TempDir(), logship.DefaultMaxBytes, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	a.ship = logship.New(buf)
	a.ship.Log, a.ship.FollowEvery = log, 200*time.Millisecond
	a.w = &agentjobs.Worker{Client: c, DeviceID: f.deviceID, Dir: t.TempDir(), Log: log, MinRetry: 100 * time.Millisecond, MaxRetry: time.Second}
	// The handlers are the runner's, the worker's and the shipper's own
	// functions, counted; they run after the runner exists.
	a.ch = channel.New(channel.Config{Dialer: c, DeviceID: f.deviceID, Key: pinnedKey, Log: log, Device: f.key,
		Timing: channel.Timing{FirstWait: 50 * time.Millisecond, MinRetry: 50 * time.Millisecond, MaxRetry: 200 * time.Millisecond},
		Handlers: channel.Handlers{
			Jobs: a.w.Deliver, Logs: a.ship.Apply, PollNow: a.w.PollNow,
			Repair: func(ctx context.Context, s *agentproto.SignedRepair) { a.repairs.Add(1); a.r.ApplyRepair(ctx, s) },
			Settings: func(ctx context.Context, s agentproto.ChannelSettings) {
				a.settings.Add(1)
				a.r.ApplySettings(ctx, s)
			},
		}})
	a.r = &runner.Runner{
		Client: c, Store: store, DeviceID: f.deviceID, Log: log, Channel: a.ch, Key: pinnedKey,
		Facts: func() agentproto.Facts {
			a.beats.Add(1)
			return facts("chan-01")
		},
		Every: time.Hour, MinWake: 20 * time.Millisecond,
		OnJobKey: func(k string) {
			if pub, err := agentproto.DecodeKey(k); err == nil {
				pinned.Store(&pub)
				_ = a.w.SetKey(k)
			}
		},
	}
	a.r.Nudge, a.r.OnJobsWaiting = a.ch.Checkin, a.w.PollNow
	a.w.Live, a.w.Changed = a.ch.Live, a.ch.LiveChanged()
	send := a.ch.LogSender(a.ship.Following, func(ctx context.Context, b agentproto.LogBatch) (agentproto.LogAck, error) {
		return c.AgentLogs(ctx, b)
	})
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Go(func() { a.ch.Run(ctx) })
	wg.Go(func() { _ = a.w.Run(ctx) })
	wg.Go(func() { a.ship.Run(ctx, send) })
	wg.Go(func() { _ = a.r.Run(ctx) })
	t.Cleanup(func() { cancel(); wg.Wait() })
	return a
}

func eventuallyT(t *testing.T, d time.Duration, what string, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timed out after %v: %s", d, what)
}

// live waits for the agent's connection to be up and confirmed by its
// heartbeat, on the server's hub.
func (f *chanFixture) live(a *chanAgent) {
	f.t.Helper()
	id := uuid.MustParse(f.deviceID)
	eventuallyT(f.t, 15*time.Second, "the channel is live and confirmed", func() bool {
		return a.ch.Live() && f.h.deps.AgentChannel.Live(id)
	})
}

// runJob queues a script on the device through the console API and waits for
// its run to succeed.
func (f *chanFixture) runJob(name string) {
	f.t.Helper()
	var sc struct {
		ID string `json:"id"`
	}
	f.admin.expect(http.StatusCreated, "POST", "/api/v1/scripts",
		map[string]any{"organizationId": f.org, "name": name, "shell": "sh", "body": "echo " + name, "timeoutSeconds": 60}, &sc)
	var job jobView
	f.admin.expect(http.StatusCreated, "POST", "/api/v1/jobs", map[string]any{"scriptId": sc.ID, "deviceIds": []string{f.deviceID}}, &job)
	eventuallyT(f.t, 20*time.Second, "the job "+name+" succeeded", func() bool {
		var runs struct{ Items []struct{ Status, ID string } }
		f.admin.expect(http.StatusOK, "GET", "/api/v1/job-runs?deviceId="+f.deviceID, nil, &runs)
		for _, r := range runs.Items {
			if r.ID == job.Runs[0].ID {
				return r.Status == "succeeded"
			}
		}
		return false
	})
}

// Jobs reach a live agent with no poll held: after the first, every job
// arrives by push, and its result returns by the signed HTTPS request.
func TestChannelPushesJobs(t *testing.T) {
	f := newChanFixture(t, true)
	a := f.startAgent()
	f.live(a)
	f.runJob("first")
	polls := a.requests.count(agentproto.PathJobsPoll)
	for _, n := range []string{"second", "third"} {
		f.runJob(n)
	}
	if got := a.requests.count(agentproto.PathJobsPoll); got != polls {
		t.Fatalf("a live agent polled %d more times for jobs the channel carried", got-polls)
	}
	if a.requests.count(agentproto.PathHeartbeat) > 6 {
		t.Errorf("heartbeats: %d; the timer is an hour away", a.requests.count(agentproto.PathHeartbeat))
	}
}

// The fallback: with the channel off, or down, the same jobs arrive by the
// long poll and nothing is lost.
func TestChannelDownFallsBackToThePoll(t *testing.T) {
	t.Run("server switch off", func(t *testing.T) {
		f := newChanFixture(t, false)
		a := f.startAgent()
		f.runJob("by-poll")
		if a.ch.Live() || a.requests.count(agentproto.PathChannel) != 0 || a.requests.count(agentproto.PathJobsPoll) == 0 {
			t.Fatal("the agent did not use the poll alone")
		}
	})
	t.Run("connection closed by the server", func(t *testing.T) {
		f := newChanFixture(t, true)
		a := f.startAgent()
		f.live(a)
		f.runJob("while-live")
		f.h.deps.AgentChannel.Close(uuid.MustParse(f.deviceID), agentproto.ClosingRestart)
		eventuallyT(t, 5*time.Second, "the agent saw the closing", func() bool { return !a.ch.Live() })
		before := a.requests.count(agentproto.PathJobsPoll)
		f.runJob("after-close")
		if a.requests.count(agentproto.PathJobsPoll) <= before {
			t.Fatal("the agent went back to long polls, but never polled")
		}
	})
}

// A device of an organization outside the dev scope gets no push, and still
// gets its job by the poll.
func TestChannelRespectsTheDevScope(t *testing.T) {
	f := newChanFixture(t, true)
	other := uuid.New()
	t.Cleanup(devscope.Set(other))
	a := f.startAgent()
	f.runJob("scoped-out")
	if a.ch.Live() || a.requests.count(agentproto.PathChannel) != 0 {
		t.Fatal("a device outside the dev scope connected")
	}
}

// logs.follow: opening Logs pushes the instruction, the agent's lines arrive
// over signed logs.batch frames (no HTTPS batch), and the same lines are
// stored once.
func TestChannelFollowsLogs(t *testing.T) {
	f := newChanFixture(t, true)
	a := f.startAgent()
	f.live(a)
	for i := range 3 {
		a.ship.Record(agentproto.LogSourceAgent, "info", "line "+string(rune('a'+i)), nil)
	}
	type page struct {
		Items []struct{ Message string } `json:"items"`
	}
	eventuallyT(t, 15*time.Second, "the lines arrived while following", func() bool {
		var p page
		f.admin.expect(http.StatusOK, "GET", f.device+"/agent-logs?follow=true", nil, &p)
		n := 0
		for _, it := range p.Items {
			if strings.HasPrefix(it.Message, "line ") {
				n++
			}
		}
		return n == 3
	})
	if got := a.requests.count(agentproto.PathAgentLogs); got != 0 {
		t.Fatalf("%d batches went over HTTPS while the channel was live and followed", got)
	}
	if !a.ship.Following() {
		t.Fatal("the agent does not follow")
	}
	// A line logged now still arrives, and never twice.
	a.ship.Record(agentproto.LogSourceAgent, "info", "line d", nil)
	eventuallyT(t, 15*time.Second, "the next line arrived", func() bool {
		var p page
		f.admin.expect(http.StatusOK, "GET", f.device+"/agent-logs?follow=true", nil, &p)
		n := 0
		for _, it := range p.Items {
			if it.Message == "line d" {
				n++
			}
		}
		return n == 1
	})
}

// Verbose mode is pushed too, and ends with a push.
func TestChannelPushesVerboseMode(t *testing.T) {
	f := newChanFixture(t, true)
	a := f.startAgent()
	f.live(a)
	f.admin.expect(http.StatusOK, "PUT", f.device+"/agent-logs/verbose", map[string]int{}, nil)
	eventuallyT(t, 10*time.Second, "the agent logs at debug", func() bool { return a.ship.Level.Level() == slog.LevelDebug })
	f.admin.expect(http.StatusNoContent, "DELETE", f.device+"/agent-logs/verbose", nil, nil)
	eventuallyT(t, 10*time.Second, "the agent is back at info", func() bool { return a.ship.Level.Level() == slog.LevelInfo })
	if a.requests.count(agentproto.PathHeartbeat) > 6 {
		t.Errorf("heartbeats: %d; the change should not have needed them", a.requests.count(agentproto.PathHeartbeat))
	}
}

// A repair asked for in the console reaches the agent by push, runs, and its
// outcome is reported at once; the heartbeat timer is an hour away.
func TestChannelPushesRepairs(t *testing.T) {
	f := newChanFixture(t, true)
	ctx := context.Background()
	if err := f.h.db.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO mesh_sites (site_id, organization_id, mesh_id, synced_name) VALUES ($1, $2, 'mesh-1234567890', 'HQ')`, f.site, f.org)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	a := f.startAgent()
	f.live(a)
	// The agent says what the server needs to see to plan a MeshAgent repair.
	ac := f.h.agentClient()
	ac.SetIdentity(f.deviceID, f.key)
	if _, err := ac.Heartbeat(ctx, agentproto.HeartbeatRequest{Facts: facts("chan-01"), MeshAgent: &agentproto.MeshAgentState{Installed: false, Error: "install failed: x"}}); err != nil {
		t.Fatal(err)
	}
	beats := a.requests.count(agentproto.PathHeartbeat)
	f.admin.expect(http.StatusCreated, "POST", f.device+"/repairs", map[string]string{}, nil)
	eventuallyT(t, 10*time.Second, "the agent was handed the step by push", func() bool { return a.repairs.Load() >= 1 })
	// The agent has no MeshAgent on this test computer, so the step fails; the
	// outcome is what the server must learn, by a heartbeat the agent asked for.
	var list struct {
		Items []struct {
			Steps []struct{ State, Error string } `json:"steps"`
		} `json:"items"`
	}
	eventuallyT(t, 15*time.Second, "the outcome was reported", func() bool {
		f.admin.expect(http.StatusOK, "GET", f.device+"/repairs", nil, &list)
		return len(list.Items) > 0 && len(list.Items[0].Steps) > 0 && list.Items[0].Steps[0].State == "failed"
	})
	if !strings.Contains(list.Items[0].Steps[0].Error, "not supported on this device") {
		t.Errorf("the step's error: %q", list.Items[0].Steps[0].Error)
	}
	if got := a.requests.count(agentproto.PathHeartbeat) - beats; got > 6 {
		t.Errorf("%d heartbeats for one repair", got)
	}
}

// A settings push (here, after a device moved) reaches the agent, which then
// checks in at once.
func TestChannelPushesSettings(t *testing.T) {
	f := newChanFixture(t, true)
	a := f.startAgent()
	f.live(a)
	var grp idObj
	f.admin.expect(http.StatusCreated, "POST", "/api/v1/sites/"+f.site+"/device-groups", map[string]string{"name": "Servers"}, &grp)
	time.Sleep(300 * time.Millisecond)
	beats := a.requests.count(agentproto.PathHeartbeat)
	f.admin.expect(http.StatusOK, "POST", "/api/v1/devices/move", move([]string{f.deviceID}, f.site, &grp.ID), nil)
	eventuallyT(t, 10*time.Second, "the settings reached the agent", func() bool { return a.settings.Load() >= 1 })
	eventuallyT(t, 10*time.Second, "the agent checked in after them", func() bool { return a.requests.count(agentproto.PathHeartbeat) > beats })
}

// A removal wakes the agent, which checks in at once and takes the uninstall
// instruction from its heartbeat answer.
func TestChannelWakesForARemoval(t *testing.T) {
	f := newChanFixture(t, true)
	a := f.startAgent()
	f.live(a)
	time.Sleep(300 * time.Millisecond)
	beats := a.requests.count(agentproto.PathHeartbeat)
	f.admin.expect(http.StatusOK, "POST", f.device+"/removal", nil, nil)
	eventuallyT(t, 10*time.Second, "the agent checked in on the wake", func() bool { return a.requests.count(agentproto.PathHeartbeat) > beats })
}
