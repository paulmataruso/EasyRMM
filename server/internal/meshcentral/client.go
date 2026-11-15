package meshcentral

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
)

// ErrUnavailable is returned when MeshCentral cannot be reached.
var ErrUnavailable = errors.New("meshcentral: not connected")

// CommandError is a failure MeshCentral reported for a command.
type CommandError struct {
	Action string
	Result string
}

func (e *CommandError) Error() string {
	return fmt.Sprintf("meshcentral: %s: %s", e.Action, e.Result)
}

// Event is a MeshCentral server event delivered on the control channel, for
// example a device connecting ({"etype":"node","action":"nodeconnect"}).
type Event struct {
	Type   string          `json:"etype"`
	Action string          `json:"action"`
	NodeID string          `json:"nodeid"`
	MeshID string          `json:"meshid"`
	Raw    json.RawMessage `json:"-"`
}

// Client keeps one control.ashx WebSocket open to MeshCentral as the service
// account, reconnecting with backoff, and correlates replies to commands.
type Client struct {
	endpoint string
	key      []byte
	user     string
	log      *slog.Logger
	now      func() time.Time
	onEvent  func(Event)
	onReady  func()

	// Tunables, overridden in tests.
	minBackoff, maxBackoff time.Duration
	pingInterval           time.Duration
	callTimeout            time.Duration

	seq atomic.Uint64

	mu      sync.Mutex
	conn    *websocket.Conn
	ready   chan struct{} // closed while connected
	pending map[string]chan reply
	info    ServerInfo
}

type reply struct {
	msg map[string]json.RawMessage
	err error
}

// ServerInfo is what MeshCentral reports when a control session opens.
type ServerInfo struct {
	// TLSHash is the SHA-384 of the HTTPS certificate MeshCentral expects
	// agents to see (from certUrl), upper-case hex.
	TLSHash string `json:"tlshash"`
	// AgentCertHash identifies MeshCentral's agent certificate.
	AgentCertHash string `json:"agentCertHash"`
}

// ClientOptions configure NewClient.
type ClientOptions struct {
	// BaseURL is MeshCentral's loopback HTTP address, http://127.0.0.1:14430.
	BaseURL string
	// Key is the shared loginCookieEncryptionKey.
	Key []byte
	Log *slog.Logger
	// OnEvent, if set, receives MeshCentral events. It must not block.
	OnEvent func(Event)
	// OnReady, if set, is called after every successful (re)connection. It
	// runs on its own goroutine.
	OnReady func()
}

// NewClient prepares a client; Run connects it.
func NewClient(o ClientOptions) (*Client, error) {
	u, err := url.Parse(o.BaseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("meshcentral: invalid base URL %q", o.BaseURL)
	}
	if len(o.Key) != KeySize {
		return nil, fmt.Errorf("meshcentral: key must be %d bytes", KeySize)
	}
	scheme := "ws"
	if u.Scheme == "https" {
		scheme = "wss"
	}
	log := o.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Client{
		endpoint: scheme + "://" + u.Host + "/control.ashx",
		key:      o.Key, user: UserID(ServiceAccount), log: log, now: time.Now,
		onEvent: o.OnEvent, onReady: o.OnReady,
		minBackoff: time.Second, maxBackoff: 30 * time.Second,
		pingInterval: 30 * time.Second, callTimeout: 30 * time.Second,
		ready:   make(chan struct{}),
		pending: map[string]chan reply{},
	}, nil
}

// Connected reports whether a control session is open.
func (c *Client) Connected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn != nil
}

// Info returns what MeshCentral reported on the current connection.
func (c *Client) Info() ServerInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.info
}

// Run keeps the connection open until ctx ends.
func (c *Client) Run(ctx context.Context) {
	backoff := c.minBackoff
	for ctx.Err() == nil {
		start := time.Now()
		err := c.session(ctx)
		if ctx.Err() != nil {
			return
		}
		if time.Since(start) > 2*c.maxBackoff {
			backoff = c.minBackoff // it was up for a while; retry promptly
		}
		c.log.Warn("MeshCentral control connection lost; reconnecting", "error", err, "retry_in", backoff.String())
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, c.maxBackoff)
	}
}

// session runs one connection until it fails.
func (c *Client) session(ctx context.Context) error {
	auth, err := controlAuth(c.key, c.user, c.now())
	if err != nil {
		return err
	}
	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, resp, err := websocket.Dial(dctx, c.endpoint+"?auth="+url.QueryEscape(auth), &websocket.DialOptions{
		HTTPClient: &http.Client{Timeout: 15 * time.Second},
	})
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		// Dial errors quote the request URL, which carries the login token.
		return fmt.Errorf("connecting to %s: %w", c.endpoint, redact(err, auth, url.QueryEscape(auth)))
	}
	conn.SetReadLimit(64 << 20) // device lists can be large
	defer func() { _ = conn.CloseNow() }()

	sctx, scancel := context.WithCancel(ctx)
	defer scancel()

	// MeshCentral sends serverinfo once the session is authenticated, or a
	// close message if the cookie was rejected.
	first := make(chan error, 1)
	readErr := make(chan error, 1)
	go func() { readErr <- c.readLoop(sctx, conn, first) }()

	select {
	case err := <-first:
		if err != nil {
			return err
		}
	case err := <-readErr:
		return err
	case <-time.After(15 * time.Second):
		return errors.New("MeshCentral did not open a control session")
	case <-ctx.Done():
		return ctx.Err()
	}

	c.mu.Lock()
	c.conn = conn
	close(c.ready)
	c.mu.Unlock()
	c.log.Info("connected to MeshCentral", "endpoint", c.endpoint)
	if c.onReady != nil {
		go c.onReady()
	}
	defer c.disconnected()

	tick := time.NewTicker(c.pingInterval)
	defer tick.Stop()
	for {
		select {
		case err := <-readErr:
			return err
		case <-ctx.Done():
			_ = conn.Close(websocket.StatusNormalClosure, "")
			return ctx.Err()
		case <-tick.C:
			pctx, pcancel := context.WithTimeout(sctx, 10*time.Second)
			err := conn.Ping(pctx)
			pcancel()
			if err != nil {
				return fmt.Errorf("ping: %w", err)
			}
		}
	}
}

func (c *Client) disconnected() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.conn = nil
	c.ready = make(chan struct{})
	for id, ch := range c.pending {
		ch <- reply{err: ErrUnavailable}
		delete(c.pending, id)
	}
}

func (c *Client) readLoop(ctx context.Context, conn *websocket.Conn, first chan<- error) error {
	opened := false
	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			return err
		}
		var msg map[string]json.RawMessage
		if json.Unmarshal(data, &msg) != nil {
			continue
		}
		action := str(msg["action"])
		if !opened {
			switch action {
			case "serverinfo":
				var si struct {
					ServerInfo ServerInfo `json:"serverinfo"`
				}
				_ = json.Unmarshal(data, &si)
				c.mu.Lock()
				c.info = si.ServerInfo
				c.mu.Unlock()
				opened = true
				first <- nil
			case "close":
				first <- fmt.Errorf("MeshCentral refused the control session: %s %s", str(msg["cause"]), str(msg["msg"]))
				return errors.New("session refused")
			}
			continue
		}
		if id := correlation(msg); id != "" {
			c.mu.Lock()
			ch, ok := c.pending[id]
			delete(c.pending, id)
			c.mu.Unlock()
			if ok {
				ch <- reply{msg: msg}
				continue
			}
		}
		if action == "event" && c.onEvent != nil {
			var ev Event
			if raw, ok := msg["event"]; ok && json.Unmarshal(raw, &ev) == nil {
				ev.Raw = raw
				c.onEvent(ev)
			}
		}
		if action == "close" {
			return fmt.Errorf("MeshCentral closed the session: %s", str(msg["cause"]))
		}
	}
}

// correlation returns the request id echoed in a reply: commands echo
// "responseid", list commands echo "tag".
func correlation(msg map[string]json.RawMessage) string {
	if id := str(msg["responseid"]); id != "" {
		return id
	}
	return str(msg["tag"])
}

func str(raw json.RawMessage) string {
	var s string
	if raw != nil && json.Unmarshal(raw, &s) == nil {
		return s
	}
	return ""
}

// call sends a command and waits for its reply. If the connection is down it
// waits for it to come back until ctx (or the call timeout) ends.
func (c *Client) call(ctx context.Context, action string, fields map[string]any) (map[string]json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(ctx, c.callTimeout)
	defer cancel()
	c.mu.Lock()
	ready := c.ready
	c.mu.Unlock()
	select {
	case <-ready:
	case <-ctx.Done():
		return nil, ErrUnavailable
	}

	id := "easyrmm-" + strconv.FormatUint(c.seq.Add(1), 10)
	cmd := make(map[string]any, len(fields)+3)
	for k, v := range fields {
		cmd[k] = v
	}
	cmd["action"], cmd["responseid"], cmd["tag"] = action, id, id
	body, err := json.Marshal(cmd)
	if err != nil {
		return nil, err
	}
	ch := make(chan reply, 1)
	c.mu.Lock()
	conn := c.conn
	if conn == nil {
		c.mu.Unlock()
		return nil, ErrUnavailable
	}
	c.pending[id] = ch
	c.mu.Unlock()
	if err := conn.Write(ctx, websocket.MessageText, body); err != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, r.err
		}
		if res := str(r.msg["result"]); res != "" && res != "ok" {
			return r.msg, &CommandError{Action: action, Result: res}
		}
		return r.msg, nil
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return nil, fmt.Errorf("meshcentral: %s: no reply: %w", action, ctx.Err())
	}
}

// redactedError hides secrets in a wrapped error's message, keeping the chain
// for errors.Is and errors.As.
type redactedError struct {
	err     error
	secrets []string
}

func (e *redactedError) Error() string {
	msg := e.err.Error()
	for _, s := range e.secrets {
		if s != "" {
			msg = strings.ReplaceAll(msg, s, "[redacted]")
		}
	}
	return msg
}

func (e *redactedError) Unwrap() error { return e.err }

func redact(err error, secrets ...string) error {
	return &redactedError{err: err, secrets: secrets}
}
