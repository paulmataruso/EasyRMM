package meshcentral

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// fakeControl speaks the control.ashx protocol: it checks the auth cookie,
// sends serverinfo, and answers commands through handle.
type fakeControl struct {
	t      *testing.T
	key    []byte
	handle func(cmd map[string]any) []map[string]any
	refuse atomic.Bool
	conns  atomic.Int32

	mu    sync.Mutex
	conn  *websocket.Conn
	ready chan struct{}
}

func newFakeControl(t *testing.T, key []byte) (*fakeControl, *httptest.Server) {
	f := &fakeControl{t: t, key: key, ready: make(chan struct{}, 10)}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeControl) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/control.ashx" {
		http.NotFound(w, r)
		return
	}
	o, err := DecodeCookie(r.URL.Query().Get("auth"), f.key, time.Now(), time.Hour)
	c, aerr := websocket.Accept(w, r, nil)
	if aerr != nil {
		return
	}
	defer func() { _ = c.CloseNow() }()
	ctx := r.Context()
	send := func(m map[string]any) {
		b, _ := json.Marshal(m)
		_ = c.Write(ctx, websocket.MessageText, b)
	}
	if err != nil || o["userid"] != "user//easyrmm-service" || f.refuse.Load() {
		send(map[string]any{"action": "close", "cause": "noauth", "msg": "noauth-2b"})
		return
	}
	f.conns.Add(1)
	send(map[string]any{"action": "serverinfo", "serverinfo": map[string]any{"tlshash": "ABC", "agentCertHash": "def"}})
	send(map[string]any{"action": "userinfo"})
	f.mu.Lock()
	f.conn = c
	f.mu.Unlock()
	f.ready <- struct{}{}
	for {
		_, data, err := c.Read(ctx)
		if err != nil {
			return
		}
		var cmd map[string]any
		_ = json.Unmarshal(data, &cmd)
		for _, reply := range f.handle(cmd) {
			send(reply)
		}
	}
}

// push sends an unsolicited message on the current connection.
func (f *fakeControl) push(m map[string]any) {
	f.mu.Lock()
	c := f.conn
	f.mu.Unlock()
	b, _ := json.Marshal(m)
	_ = c.Write(context.Background(), websocket.MessageText, b)
}

func (f *fakeControl) drop() {
	f.mu.Lock()
	c := f.conn
	f.mu.Unlock()
	_ = c.CloseNow()
}

func echo(cmd map[string]any, fields map[string]any) map[string]any {
	r := map[string]any{"action": cmd["action"], "responseid": cmd["responseid"]}
	for k, v := range fields {
		r[k] = v
	}
	return r
}

func startClient(t *testing.T, srv *httptest.Server, key []byte, o ClientOptions) (*Client, context.CancelFunc) {
	t.Helper()
	o.BaseURL, o.Key = srv.URL, key
	c, err := NewClient(o)
	if err != nil {
		t.Fatal(err)
	}
	c.minBackoff, c.maxBackoff = 10*time.Millisecond, 50*time.Millisecond
	c.callTimeout = 2 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return c, cancel
}

func waitConnected(t *testing.T, c *Client) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !c.Connected() {
		if time.Now().After(deadline) {
			t.Fatal("client did not connect")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestNewClientValidation(t *testing.T) {
	key := testKey(t)
	for _, base := range []string{"", "ftp://x", "http://", "://"} {
		if _, err := NewClient(ClientOptions{BaseURL: base, Key: key}); err == nil {
			t.Errorf("base URL %q accepted", base)
		}
	}
	if _, err := NewClient(ClientOptions{BaseURL: "http://127.0.0.1:1", Key: key[:10]}); err == nil {
		t.Error("short key accepted")
	}
	c, err := NewClient(ClientOptions{BaseURL: "https://mesh.internal:8443", Key: key})
	if err != nil || c.endpoint != "wss://mesh.internal:8443/control.ashx" {
		t.Errorf("endpoint = %q, err = %v", c.endpoint, err)
	}
}

func TestClientCommandsAndCorrelation(t *testing.T) {
	key := testKey(t)
	f, srv := newFakeControl(t, key)
	var held []map[string]any
	var hmu sync.Mutex
	f.handle = func(cmd map[string]any) []map[string]any {
		switch cmd["action"] {
		case "meshes":
			if cmd["tag"] != cmd["responseid"] {
				t.Errorf("tag and responseid differ: %v", cmd)
			}
			// List commands answer with tag only.
			return []map[string]any{{"action": "meshes", "tag": cmd["tag"], "meshes": []any{
				map[string]any{"_id": "mesh//a", "name": "A", "desc": "d", "mtype": 2, "links": map[string]any{"user//easyrmm-service": map[string]any{"rights": 4294967295}}},
			}}}
		case "users":
			return []map[string]any{{"action": "users", "tag": cmd["tag"], "users": []any{map[string]any{"_id": "user//u", "name": "u", "siteadmin": 5312}}}}
		case "nodes":
			return []map[string]any{echo(cmd, map[string]any{"nodes": map[string]any{
				"mesh//a": []any{map[string]any{"_id": "node//1", "name": "PC1", "conn": 1, "agent": map[string]any{"id": 4, "ver": 0, "caps": 15}}},
				"mesh//b": []any{map[string]any{"_id": "node//2", "name": "PC2", "conn": 0}},
			}})}
		case "createmesh":
			if cmd["meshtype"] != float64(2) {
				t.Errorf("createmesh type %v", cmd["meshtype"])
			}
			return []map[string]any{echo(cmd, map[string]any{"result": "ok", "meshid": "mesh//new"})}
		case "addmeshuser":
			if cmd["meshid"] == "mesh//bad" {
				return []map[string]any{echo(cmd, map[string]any{"result": "Unknown user easyrmm-x", "success": 0, "failed": 1})}
			}
			return []map[string]any{echo(cmd, map[string]any{"result": "Added user easyrmm-x", "success": 1, "failed": 0})}
		case "deleteuser":
			return []map[string]any{echo(cmd, map[string]any{"result": "User does not exists"})}
		case "adduser":
			return []map[string]any{echo(cmd, map[string]any{"result": "User already exists"})}
		case "slow":
			hmu.Lock()
			held = append(held, cmd)
			hmu.Unlock()
			return nil
		case "fast":
			// Answer the held slow command after this one: out of order.
			out := []map[string]any{echo(cmd, map[string]any{"result": "ok", "n": "fast"})}
			hmu.Lock()
			for _, h := range held {
				out = append(out, echo(h, map[string]any{"result": "ok", "n": "slow"}))
			}
			held = nil
			hmu.Unlock()
			return out
		}
		return []map[string]any{echo(cmd, map[string]any{"result": "ok"})}
	}
	var readyCalls atomic.Int32
	c, _ := startClient(t, srv, key, ClientOptions{OnReady: func() { readyCalls.Add(1) }})
	waitConnected(t, c)
	ctx := context.Background()

	if c.Info().TLSHash != "ABC" || c.Info().AgentCertHash != "def" {
		t.Errorf("info = %+v", c.Info())
	}
	meshes, err := c.Meshes(ctx)
	if err != nil || len(meshes) != 1 || meshes[0].Links["user//easyrmm-service"].Rights != RightFullAdmin {
		t.Fatalf("meshes = %+v, %v", meshes, err)
	}
	users, err := c.Users(ctx)
	if err != nil || len(users) != 1 || users[0].SiteAdmin != 5312 {
		t.Fatalf("users = %+v, %v", users, err)
	}
	nodes, err := c.Nodes(ctx)
	if err != nil || len(nodes) != 2 {
		t.Fatalf("nodes = %+v, %v", nodes, err)
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	if nodes[0].MeshID != "mesh//a" || !nodes[0].AgentConnected() || nodes[0].Agent.Type != 4 || nodes[1].AgentConnected() {
		t.Errorf("nodes = %+v", nodes)
	}
	if id, err := c.CreateMesh(ctx, "n", "d"); err != nil || id != "mesh//new" {
		t.Errorf("create = %q, %v", id, err)
	}
	if err := c.SetMeshRights(ctx, "mesh//a", "user//x", 8); err != nil {
		t.Errorf("set rights: %v", err)
	}
	var ce *CommandError
	if err := c.SetMeshRights(ctx, "mesh//bad", "user//x", 8); !errors.As(err, &ce) || ce.Result != "Unknown user easyrmm-x" {
		t.Errorf("failed set rights: %v", err)
	}
	if err := c.DeleteUser(ctx, "user//x"); !IsUnknown(err) || IsAlreadyExists(err) {
		t.Errorf("delete missing user: %v", err)
	}
	if err := c.AddUser(ctx, "x", "X", 0); !IsAlreadyExists(err) || IsUnknown(err) {
		t.Errorf("add existing user: %v", err)
	}
	if IsUnknown(errors.New("plain")) || IsAlreadyExists(errors.New("plain")) {
		t.Error("plain errors classified as MeshCentral results")
	}
	for _, call := range []func() error{
		func() error { return c.EditMesh(ctx, "mesh//a", "n", "d") },
		func() error { return c.DeleteMesh(ctx, "mesh//a") },
		func() error { return c.EditUser(ctx, "user//x", "X", 0) },
		func() error { return c.RemoveMeshUser(ctx, "mesh//a", "user//x") },
	} {
		if err := call(); err != nil {
			t.Error(err)
		}
	}

	// Replies are matched to their own request even when out of order.
	slowDone := make(chan map[string]json.RawMessage)
	go func() {
		r, err := c.call(ctx, "slow", nil)
		if err != nil {
			t.Error(err)
		}
		slowDone <- r
	}()
	time.Sleep(50 * time.Millisecond)
	fast, err := c.call(ctx, "fast", nil)
	if err != nil || str(fast["n"]) != "fast" {
		t.Errorf("fast = %v, %v", fast, err)
	}
	if slow := <-slowDone; str(slow["n"]) != "slow" {
		t.Errorf("slow = %v", slow)
	}
	if readyCalls.Load() != 1 {
		t.Errorf("OnReady called %d times", readyCalls.Load())
	}
}

func TestClientMalformedReplies(t *testing.T) {
	key := testKey(t)
	f, srv := newFakeControl(t, key)
	f.handle = func(cmd map[string]any) []map[string]any {
		switch cmd["action"] {
		case "createmesh":
			return []map[string]any{echo(cmd, map[string]any{"result": "ok"})}
		case "addmeshuser":
			return []map[string]any{echo(cmd, map[string]any{"result": "Nothing done"})}
		}
		return []map[string]any{echo(cmd, map[string]any{cmd["action"].(string): "not a list", "nodes": 5})}
	}
	c, _ := startClient(t, srv, key, ClientOptions{})
	waitConnected(t, c)
	ctx := context.Background()
	if _, err := c.Meshes(ctx); err == nil {
		t.Error("bad meshes accepted")
	}
	if _, err := c.Users(ctx); err == nil {
		t.Error("bad users accepted")
	}
	if _, err := c.Nodes(ctx); err == nil {
		t.Error("bad nodes accepted")
	}
	if _, err := c.CreateMesh(ctx, "a", "b"); err == nil {
		t.Error("createmesh without id accepted")
	}
	if err := c.SetMeshRights(ctx, "m", "u", 8); err == nil {
		t.Error("addmeshuser without success accepted")
	}
}

func TestClientEventsAndReconnect(t *testing.T) {
	key := testKey(t)
	f, srv := newFakeControl(t, key)
	block := make(chan struct{})
	f.handle = func(cmd map[string]any) []map[string]any {
		if cmd["action"] == "hang" {
			<-block
			return nil
		}
		return []map[string]any{echo(cmd, map[string]any{"result": "ok"})}
	}
	events := make(chan Event, 10)
	c, _ := startClient(t, srv, key, ClientOptions{OnEvent: func(e Event) { events <- e }})
	<-f.ready
	waitConnected(t, c)

	f.push(map[string]any{"action": "event", "event": map[string]any{"etype": "node", "action": "nodeconnect", "nodeid": "node//1", "meshid": "mesh//a"}})
	f.push(map[string]any{"action": "pong"})
	select {
	case e := <-events:
		if e.Type != "node" || e.Action != "nodeconnect" || e.NodeID != "node//1" || e.MeshID != "mesh//a" || len(e.Raw) == 0 {
			t.Errorf("event = %+v", e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event delivered")
	}

	// A call in flight when the connection drops fails as unavailable.
	errc := make(chan error, 1)
	go func() { _, err := c.call(context.Background(), "hang", nil); errc <- err }()
	time.Sleep(50 * time.Millisecond)
	f.drop()
	if err := <-errc; !errors.Is(err, ErrUnavailable) {
		t.Errorf("in-flight call error = %v", err)
	}
	close(block)

	// The client reconnects by itself and works again.
	<-f.ready
	waitConnected(t, c)
	if _, err := c.call(context.Background(), "ping2", nil); err != nil {
		t.Errorf("after reconnect: %v", err)
	}
	if f.conns.Load() < 2 {
		t.Errorf("connections = %d", f.conns.Load())
	}
}

func TestClientServerCloseMessage(t *testing.T) {
	key := testKey(t)
	f, srv := newFakeControl(t, key)
	f.handle = func(map[string]any) []map[string]any { return nil }
	c, _ := startClient(t, srv, key, ClientOptions{})
	<-f.ready
	waitConnected(t, c)
	f.refuse.Store(true) // later reconnects are refused
	f.push(map[string]any{"action": "close", "cause": "serverShutdown"})
	deadline := time.Now().Add(3 * time.Second)
	for c.Connected() {
		if time.Now().After(deadline) {
			t.Fatal("still connected after the server closed the session")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestClientRefusedAndUnavailable(t *testing.T) {
	key := testKey(t)
	_, srv := newFakeControl(t, key)
	other := testKey(t) // MeshCentral does not know this key
	c, _ := startClient(t, srv, other, ClientOptions{})
	time.Sleep(200 * time.Millisecond)
	if c.Connected() {
		t.Fatal("connected with the wrong key")
	}
	c.callTimeout = 100 * time.Millisecond
	if _, err := c.Meshes(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Errorf("call while refused = %v", err)
	}
}

func TestClientNoServer(t *testing.T) {
	key := testKey(t)
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close() // nothing listens any more
	c, _ := startClient(t, srv, key, ClientOptions{})
	time.Sleep(100 * time.Millisecond)
	if c.Connected() {
		t.Fatal("connected to nothing")
	}
	// The error is logged and shown to administrators; it must not carry the login token.
	err := c.session(context.Background())
	if err == nil || !strings.Contains(err.Error(), "/control.ashx") {
		t.Fatalf("session error = %v", err)
	}
	if strings.Contains(err.Error(), "auth=") && !strings.Contains(err.Error(), "auth=[redacted]") {
		t.Fatalf("session error leaks the login token: %v", err)
	}
	var ue *url.Error
	if !errors.As(err, &ue) {
		t.Errorf("redaction hid the underlying error: %v", err)
	}
}

func TestRedactedError(t *testing.T) {
	base := fmt.Errorf("get %q: refused", "ws://x/control.ashx?auth=s3cr%24t")
	err := redact(base, "s3cr$t", "s3cr%24t", "")
	if got := err.Error(); got != `get "ws://x/control.ashx?auth=[redacted]": refused` {
		t.Errorf("redacted = %s", got)
	}
	if !errors.Is(err, base) {
		t.Error("redaction broke the error chain")
	}
}

func TestClientPingDetectsDeadServer(t *testing.T) {
	key := testKey(t)
	f, srv := newFakeControl(t, key)
	f.handle = func(map[string]any) []map[string]any { return nil }
	o := ClientOptions{BaseURL: srv.URL, Key: key}
	c, err := NewClient(o)
	if err != nil {
		t.Fatal(err)
	}
	c.minBackoff, c.maxBackoff, c.pingInterval = 10*time.Millisecond, 20*time.Millisecond, 20*time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	<-f.ready
	waitConnected(t, c)
	time.Sleep(100 * time.Millisecond) // several successful pings
	if !c.Connected() {
		t.Error("healthy connection dropped")
	}
	cancel()
	<-done
	if c.Connected() {
		t.Error("still connected after Run returned")
	}
}
