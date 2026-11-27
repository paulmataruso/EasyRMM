//go:build integration

package agentchannel_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/agentchannel"
	"github.com/paulmataruso/easyrmm/server/internal/agents"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/agentapi"
	"github.com/paulmataruso/easyrmm/server/internal/jobkeys"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

// fixture is a real agent API over a real database, with the channel hub
// wired as the app wires it. Its clients sign as the agent does, using only
// agentproto.
type fixture struct {
	t      *testing.T
	inst   *testdb.Instance
	svc    *agents.Service
	hub    *agentchannel.Hub
	srv    *httptest.Server
	jobPub ed25519.PublicKey
	orgA   uuid.UUID
	orgB   uuid.UUID
	siteA  uuid.UUID
	siteB  uuid.UUID

	mu     sync.Mutex
	claims map[uuid.UUID]int
	logs   map[uuid.UUID]int
}

type fixtureOpts struct {
	off      bool
	maxConns int
	perSec   int
	timing   agentchannel.Timing
	held     func() bool
	keyFor   func(ctx context.Context, device uuid.UUID, def ed25519.PrivateKey) (ed25519.PrivateKey, error)
	fds      func() (uint64, uint64, bool)
	claim    func(ctx context.Context, f *fixture, dev uuid.UUID, max int) (*agentproto.PollResponse, error)
}

func newFixture(t *testing.T, o fixtureOpts) *fixture {
	t.Helper()
	inst := testdb.New(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	f := &fixture{t: t, inst: inst, jobPub: pub, claims: map[uuid.UUID]int{}, logs: map[uuid.UUID]int{}}
	f.svc = agents.New(inst.DB, audit.New(inst.DB, time.Now), nil, log)
	f.svc.SetKeys(jobkeys.Static(priv))
	opt := agentchannel.Options{
		Enabled: !o.off, Key: priv, Instance: "test-instance", MaxConns: o.maxConns, UpgradesPerSecond: o.perSec,
		Timing: o.timing, Held: o.held, Descriptors: o.fds, Log: log,
		Claim: func(ctx context.Context, dev uuid.UUID, max int) (*agentproto.PollResponse, error) {
			f.mu.Lock()
			f.claims[dev]++
			f.mu.Unlock()
			if o.claim != nil {
				return o.claim(ctx, f, dev, max)
			}
			return f.markSent(ctx, dev)
		},
		OnLogBatch: func(_ context.Context, dev uuid.UUID, b agentproto.LogBatch) (*agentproto.LogAck, error) {
			f.mu.Lock()
			f.logs[dev] += len(b.Records)
			f.mu.Unlock()
			return &agentproto.LogAck{Seq: int64(len(b.Records))}, nil
		},
	}
	if o.keyFor != nil {
		opt.KeyFor = func(ctx context.Context, device uuid.UUID) (ed25519.PrivateKey, error) {
			return o.keyFor(ctx, device, priv)
		}
	}
	f.hub = agentchannel.New(opt)
	f.svc.OnDeviceGone(func(id uuid.UUID) { f.hub.Close(id, agentproto.ClosingRemoved) })
	api, err := agentapi.New(f.svc, nil, []agentapi.Address{{URL: "https://rmm.example.com"}}, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	api.WithChannel(f.hub)
	f.srv = httptest.NewServer(api.Handler())
	t.Cleanup(f.srv.Close)

	ctx := context.Background()
	if err := inst.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
		for _, o := range []struct {
			name      string
			org, site *uuid.UUID
		}{{"A", &f.orgA, &f.siteA}, {"B", &f.orgB, &f.siteB}} {
			if err := tx.QueryRow(ctx, `INSERT INTO organizations (name) VALUES ($1) RETURNING id`, o.name).Scan(o.org); err != nil {
				return err
			}
			if err := tx.QueryRow(ctx, `INSERT INTO sites (organization_id, name) VALUES ($1, 'HQ') RETURNING id`, *o.org).Scan(o.site); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return f
}

// markSent is a claim as the jobs service makes it: queued runs of the
// device become sent, in the real database.
func (f *fixture) markSent(ctx context.Context, dev uuid.UUID) (*agentproto.PollResponse, error) {
	resp := &agentproto.PollResponse{Jobs: []agentproto.SignedJob{}, Cancel: []string{}}
	err := f.inst.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `UPDATE job_runs SET status = 'sent', sent_at = now(), deliveries = deliveries + 1
			WHERE device_id = $1 AND status = 'queued' RETURNING id`, dev)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			resp.Jobs = append(resp.Jobs, agentproto.SignedJob{Payload: id.String(), Signature: "x"})
		}
		return rows.Err()
	})
	if err != nil || len(resp.Jobs) == 0 {
		return nil, err
	}
	return resp, nil
}

func (f *fixture) claimCount(dev uuid.UUID) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.claims[dev]
}

func (f *fixture) logCount(dev uuid.UUID) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.logs[dev]
}

type device struct {
	id  uuid.UUID
	org uuid.UUID
	key ed25519.PrivateKey
}

func (f *fixture) device(org uuid.UUID) *device {
	f.t.Helper()
	ctx := context.Background()
	site := f.siteA
	if org == f.orgB {
		site = f.siteB
	}
	tok, err := f.svc.CreateToken(ctx, access.System("test"), site, agents.TokenInput{Name: "t", ExpiresInDays: 1})
	if err != nil {
		f.t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	resp, err := f.svc.Enroll(ctx, netip.MustParseAddr("192.0.2.10"), agentproto.EnrollRequest{
		Token: tok.Secret, PublicKey: base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)),
		Facts: agentproto.Facts{Hostname: "h-" + uuid.NewString()[:8], Platform: "linux", Arch: "amd64", AgentVersion: "1"},
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return &device{id: uuid.MustParse(resp.DeviceID), org: org, key: key}
}

// queueRun puts a queued job run in the database for d.
func (f *fixture) queueRun(d *device) uuid.UUID {
	f.t.Helper()
	ctx := context.Background()
	job, run := uuid.New(), uuid.New()
	sum := bytes.Repeat([]byte{1}, 32)
	if err := f.inst.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO jobs (id, script_name, shell, body, body_sha256, timeout_seconds, expires_at)
			VALUES ($1, 's', 'sh', 'true', $2, 60, now() + interval '1 hour')`, job, sum); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO job_runs (id, job_id, organization_id, site_id, device_id, expires_at)
			SELECT $1, $2, organization_id, site_id, id, now() + interval '1 hour' FROM devices WHERE id = $3`, run, job, d.id)
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
	return run
}

func (f *fixture) runStatus(run uuid.UUID) string {
	f.t.Helper()
	var s string
	if err := f.inst.DB.ReadTx(context.Background(), database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT status FROM job_runs WHERE id = $1`, run).Scan(&s)
	}); err != nil {
		f.t.Fatal(err)
	}
	return s
}

// forged is a header that names d but is signed with another key.
func (d *device) forged(signer *device) string {
	h, err := agentproto.Sign(signer.key, d.id.String(), http.MethodGet, agentproto.PathChannel, nil, time.Now())
	if err != nil {
		panic(err)
	}
	return h
}

// header signs an upgrade request as the agent does, at time at.
func (d *device) header(at time.Time) string {
	h, err := agentproto.Sign(d.key, d.id.String(), http.MethodGet, agentproto.PathChannel, nil, at)
	if err != nil {
		panic(err)
	}
	return h
}

// client is a connection as the agent holds it: it verifies every frame with
// the job key and checks their sequence.
type client struct {
	t       *testing.T
	f       *fixture
	d       *device
	ws      *websocket.Conn
	connID  string
	seq     uint64
	sendSeq uint64
	hello   agentproto.ChannelMessage
	in      chan incoming
}

type refusal struct {
	Status     int
	Code       string
	RetryAfter string
}

// asRefusal is err as a refusal, or nil.
func asRefusal(err error) *refusal {
	var r *refusal
	if errors.As(err, &r) {
		return r
	}
	return nil
}

func (r *refusal) Error() string { return fmt.Sprintf("refused: %d %s", r.Status, r.Code) }

func (f *fixture) url() string {
	return "ws" + strings.TrimPrefix(f.srv.URL, "http") + agentproto.PathChannel
}

// dialWith opens the channel with the given Authorization header. It
// returns a refusal for any answer but 101.
func (f *fixture) dialWith(d *device, header string, protocols []string) (*client, error) {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ws, resp, err := websocket.Dial(ctx, f.url(), &websocket.DialOptions{
		HTTPHeader:      http.Header{"Authorization": {header}},
		Subprotocols:    protocols,
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		if resp == nil {
			return nil, err
		}
		defer func() { _ = resp.Body.Close() }()
		var body struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		b, _ := io.ReadAll(resp.Body)
		_ = json.Unmarshal(b, &body)
		return nil, &refusal{Status: resp.StatusCode, Code: body.Error.Code, RetryAfter: resp.Header.Get("Retry-After")}
	}
	ws.SetReadLimit(agentproto.MaxChannelBigFrame)
	c := &client{t: f.t, f: f, d: d, ws: ws, in: make(chan incoming, 64)}
	f.t.Cleanup(func() { _ = ws.CloseNow() })
	// The first frame names the connection; read it before the checks.
	_, data, err := ws.Read(ctx)
	if err != nil {
		f.t.Fatalf("reading the hello: %v", err)
	}
	m, err := agentproto.VerifyChannelMessage(f.jobPub, data, agentproto.MaxChannelBigFrame)
	if err != nil || m.Type != agentproto.TypeHello {
		f.t.Fatalf("the first frame: %+v %v", m, err)
	}
	c.hello, c.connID, c.seq = m, m.ConnID, 1
	if err := m.Check(d.id.String(), m.ConnID, 1); err != nil {
		f.t.Fatal(err)
	}
	go c.pump()
	return c, nil
}

func (f *fixture) dial(d *device) *client {
	f.t.Helper()
	c, err := f.dialWith(d, d.header(time.Now()), []string{agentproto.ChannelSubprotocol})
	if err != nil {
		f.t.Fatalf("dial: %v", err)
	}
	return c
}

func (f *fixture) dialRefused(d *device) *refusal {
	f.t.Helper()
	c, err := f.dialWith(d, d.header(time.Now()), []string{agentproto.ChannelSubprotocol})
	if c != nil {
		f.t.Fatal("the upgrade was accepted")
	}
	var r *refusal
	if !errors.As(err, &r) {
		f.t.Fatalf("dial: %v", err)
	}
	return r
}

// read returns the next verified message, or an error: a timeout (the
// connection stays up) or the connection ending.
func (c *client) read(wait time.Duration) (agentproto.ChannelMessage, error) {
	if wait < 0 {
		wait = 0
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case in := <-c.in:
		return in.m, in.err
	case <-t.C:
		return agentproto.ChannelMessage{}, errTimeout
	}
}

var errTimeout = errors.New("timed out")

type incoming struct {
	m   agentproto.ChannelMessage
	err error
}

// pump reads the connection for as long as it lasts, verifying each frame
// as the agent does.
func (c *client) pump() {
	defer close(c.in)
	for {
		_, data, err := c.ws.Read(context.Background())
		if err != nil {
			c.in <- incoming{err: err}
			return
		}
		m, err := agentproto.VerifyChannelMessage(c.f.jobPub, data, agentproto.MaxChannelBigFrame)
		if err == nil {
			c.seq++
			err = m.Check(c.d.id.String(), c.connID, c.seq)
		}
		if err != nil {
			c.t.Errorf("frame %d: %v", c.seq, err)
			_ = c.ws.CloseNow()
			c.in <- incoming{err: err}
			return
		}
		c.in <- incoming{m: m}
	}
}

func (c *client) next(wait time.Duration) agentproto.ChannelMessage {
	c.t.Helper()
	m, err := c.read(wait)
	if err != nil {
		c.t.Fatalf("reading: %v", err)
	}
	return m
}

// nextNot returns the next message that is not a tick.
func (c *client) nextNot(wait time.Duration) (agentproto.ChannelMessage, error) {
	deadline := time.Now().Add(wait)
	for {
		m, err := c.read(time.Until(deadline))
		if err != nil || m.Type != agentproto.TypeTick {
			return m, err
		}
	}
}

// quiet says that nothing but ticks arrives for d.
func (c *client) quiet(d time.Duration) {
	c.t.Helper()
	m, err := c.nextNot(d)
	if err == nil {
		c.t.Fatalf("received %q, wanted nothing", m.Type)
	}
	if !errors.Is(err, errTimeout) {
		c.t.Fatalf("the connection ended: %v", err)
	}
}

// ends waits for the connection to end and returns the closing message, if
// one came, and the close status.
func (c *client) ends(wait time.Duration) (*agentproto.ChannelMessage, websocket.StatusCode) {
	c.t.Helper()
	var closing *agentproto.ChannelMessage
	deadline := time.Now().Add(wait)
	for {
		m, err := c.read(time.Until(deadline))
		if err != nil {
			st := websocket.CloseStatus(err)
			if errors.Is(err, errTimeout) {
				c.t.Fatalf("the connection did not end: %v", err)
			}
			return closing, st // -1 when it was cut without a close frame
		}
		if m.Type == agentproto.TypeClosing {
			mm := m
			closing = &mm
		}
	}
}

// sendBatch sends a signed logs.batch frame as the agent does.
func (c *client) sendBatch(records int) error {
	c.sendSeq++
	b := &agentproto.LogBatch{}
	for i := 0; i < records; i++ {
		b.Records = append(b.Records, agentproto.LogRecord{Seq: int64(i + 1), Time: time.Now(), Source: "agent", Level: "info", Message: "m"})
	}
	frame, err := agentproto.SignChannelAgentFrame(c.d.key, agentproto.ChannelAgentFrame{Type: agentproto.TypeLogsBatch, ConnID: c.connID, Seq: c.sendSeq, Batch: b})
	if err != nil {
		c.t.Fatal(err)
	}
	return c.sendRaw(websocket.MessageText, frame)
}

func (c *client) sendRaw(typ websocket.MessageType, b []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return c.ws.Write(ctx, typ, b)
}

// heartbeat sends a signed heartbeat naming the connection (rep nil names
// none, and sends no report) at time at, and returns the answer.
func (f *fixture) heartbeat(d *device, rep *agentproto.ChannelReport, at time.Time) agentproto.HeartbeatResponse {
	f.t.Helper()
	body, _ := json.Marshal(agentproto.HeartbeatRequest{
		Facts:     agentproto.Facts{Hostname: "h", Platform: "linux", Arch: "amd64", AgentVersion: "1"},
		Channel:   []string{agentproto.ChannelCapability},
		Transport: rep,
	})
	h, _ := agentproto.Sign(d.key, d.id.String(), http.MethodPost, agentproto.PathHeartbeat, body, at)
	req, _ := http.NewRequest(http.MethodPost, f.srv.URL+agentproto.PathHeartbeat, bytes.NewReader(body))
	req.Header.Set("Authorization", h)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		f.t.Fatalf("heartbeat: %d %s", resp.StatusCode, b)
	}
	var out agentproto.HeartbeatResponse
	if err := json.Unmarshal(b, &out); err != nil {
		f.t.Fatal(err)
	}
	return out
}

// confirm has a heartbeat name c's connection.
func (f *fixture) confirm(c *client) agentproto.HeartbeatResponse {
	f.t.Helper()
	return f.heartbeat(c.d, &agentproto.ChannelReport{ConnID: c.connID, Since: time.Now().Unix()}, time.Now())
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if ok() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out: %s", what)
}
