// Package client talks to an EasyRMM server for the agent: enrollment,
// signed heartbeats and the MeshAgent downloads (ADR-0015).
package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// Client is a connection to one EasyRMM server.
type Client struct {
	base *url.URL
	http *http.Client
	// ws is the HTTP client of the channel's connection: the same transport
	// and roots, HTTP/1.1 only, and no overall timeout (ADR-0059).
	ws     *http.Client
	device string
	key    ed25519.PrivateKey
	now    func() time.Time
	agent  string
	// level is the protocol level of the last heartbeat answer, 1 for an
	// answer without one; known is closed at the first answer. Request
	// fields added after level 2 are sent only while level is 2 or higher
	// (ADR-0009). Nothing waits for the first answer after knownBy.
	level     atomic.Int32
	known     chan struct{}
	knownOnce sync.Once
	knownBy   time.Time
}

// LevelWait bounds how long after a client is made a result waits for the
// first heartbeat answer: a result is reported in the job loop, which must
// not stall when heartbeats fail. Past it a result is sent as to a server
// of level 1 (ADR-0064).
const LevelWait = 30 * time.Second

// Options configure a Client.
type Options struct {
	// Server is the server's public URL, https://rmm.example.com.
	Server string
	// CAFile, if set, is a PEM bundle trusted instead of the system roots,
	// for servers with a private certificate authority.
	CAFile string
	// Version is the agent version, sent as the User-Agent.
	Version string
	// Transport replaces the HTTP transport (tests).
	Transport http.RoundTripper
}

// New returns a client that is not yet enrolled.
func New(o Options) (*Client, error) {
	u, err := ParseServer(o.Server)
	if err != nil {
		return nil, err
	}
	rt := o.Transport
	if rt == nil {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		if o.CAFile != "" {
			pem, err := os.ReadFile(o.CAFile) //nolint:gosec // a path the administrator chose
			if err != nil {
				return nil, fmt.Errorf("reading the CA file: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("%s holds no PEM certificates", o.CAFile)
			}
			t.TLSClientConfig.RootCAs = pool
		}
		rt = t
	}
	wsRT := rt
	if t, ok := rt.(*http.Transport); ok {
		t = t.Clone()
		t.ForceAttemptHTTP2 = false
		t.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
		wsRT = t
	}
	return &Client{
		base:    u,
		http:    &http.Client{Transport: rt, Timeout: 5 * time.Minute},
		ws:      &http.Client{Transport: wsRT},
		now:     time.Now,
		agent:   "easyrmm-agent/" + o.Version,
		known:   make(chan struct{}),
		knownBy: time.Now().Add(LevelWait),
	}, nil
}

// Level is the protocol level of the server's last heartbeat answer
// (ADR-0009): 1 for an answer without a level, 0 before the first answer
// in this process.
func (c *Client) Level() int { return int(c.level.Load()) }

// newFields reports whether request fields added after protocol level 2
// may be sent: the last heartbeat answer was of level 2 or higher.
func (c *Client) newFields() bool { return c.level.Load() >= 2 }

// ParseServer checks a server URL: https (or http for loopback testing),
// with a host and no path, query or credentials.
func ParseServer(s string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSuffix(strings.TrimSpace(s), "/"))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("%q is not a server address; use https://rmm.example.com", s)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if h := u.Hostname(); h != "localhost" && h != "127.0.0.1" && h != "::1" {
			return nil, fmt.Errorf("%q must use https", s)
		}
	default:
		return nil, fmt.Errorf("%q must use https", s)
	}
	u.Path = ""
	return u, nil
}

// Server returns the server URL.
func (c *Client) Server() string { return c.base.String() }

// SetIdentity makes the client sign requests as an enrolled device.
func (c *Client) SetIdentity(device string, key ed25519.PrivateKey) {
	c.device, c.key = device, key
}

// Error is an error response from the server.
type Error struct {
	Status  int
	Code    string
	Message string
	// RetryAfter is the answer's Retry-After header, 0 for none.
	RetryAfter time.Duration
}

func (e *Error) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("server answered %d %s: %s", e.Status, e.Code, e.Message)
	}
	return fmt.Sprintf("server answered %d", e.Status)
}

// Code returns the server's error code for err, or "".
func Code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// Enroll exchanges a deployment token for a device identity.
func (c *Client) Enroll(ctx context.Context, token string, pub ed25519.PublicKey, f agentproto.Facts) (*agentproto.EnrollResponse, error) {
	body, err := json.Marshal(agentproto.EnrollRequest{
		Token: token, PublicKey: base64.StdEncoding.EncodeToString(pub), Facts: f,
	})
	if err != nil {
		return nil, err
	}
	var out agentproto.EnrollResponse
	return &out, c.call(ctx, http.MethodPost, agentproto.PathEnroll, body, false, &out)
}

// Heartbeat reports the device's facts and metrics.
func (c *Client) Heartbeat(ctx context.Context, req agentproto.HeartbeatRequest) (*agentproto.HeartbeatResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	var out agentproto.HeartbeatResponse
	if err := c.call(ctx, http.MethodPost, agentproto.PathHeartbeat, body, true, &out); err != nil {
		return &out, err
	}
	c.level.Store(int32(max(min(out.Protocol, 1<<20), 1))) //nolint:gosec // bounded above
	c.knownOnce.Do(func() { close(c.known) })
	return &out, nil
}

// Inventory uploads the device's inventory, body being its JSON exactly
// as hashed (ADR-0018). It returns the hash the server stored. The caller
// leaves out the fields added after protocol level 2 while Level is below
// 2, as the hash covers exactly what is sent.
func (c *Client) Inventory(ctx context.Context, body []byte) (string, error) {
	var out agentproto.InventoryResponse
	if err := c.call(ctx, http.MethodPost, agentproto.PathInventory, body, true, &out); err != nil {
		return "", err
	}
	return out.Hash, nil
}

// Signed is the server's signature on a download the agent runs
// (agentproto.SignDownload) and what it covers. Nothing downloaded is used
// before Verify succeeds.
type Signed struct {
	Device, Target, Nonce, Signature string
	SHA256                           [sha256.Size]byte
}

// Verify checks the signature with the pinned job key.
func (s Signed) Verify(key ed25519.PublicKey) error {
	return agentproto.VerifyDownload(key, s.Signature, s.Device, s.Target, s.Nonce, s.SHA256)
}

// MeshAgent downloads the MeshAgent binary for a platform into w and
// returns the server's signature on it, for the caller to verify before it
// uses what w holds.
func (c *Client) MeshAgent(ctx context.Context, goos, goarch string, w io.Writer) (Signed, error) {
	q := url.Values{"os": {goos}, "arch": {goarch}}
	target := agentproto.PathMeshAgent + "?" + q.Encode()
	resp, nonce, err := c.send(ctx, http.MethodGet, target, nil, true)
	if err != nil {
		return Signed{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	// A body shorter than its Content-Length fails as io.ErrUnexpectedEOF.
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(w, h), io.LimitReader(resp.Body, agentproto.MaxMeshAgentBytes+1))
	switch {
	case err != nil:
		return Signed{}, fmt.Errorf("downloading MeshAgent: %w", err)
	case n > agentproto.MaxMeshAgentBytes:
		return Signed{}, fmt.Errorf("downloading MeshAgent: larger than %d bytes", agentproto.MaxMeshAgentBytes)
	}
	return c.signed(resp, target, nonce, [sha256.Size]byte(h.Sum(nil))), nil
}

func (c *Client) signed(resp *http.Response, target, nonce string, sum [sha256.Size]byte) Signed {
	return Signed{Device: c.device, Target: target, Nonce: nonce, Signature: resp.Header.Get(agentproto.HeaderDownloadSignature), SHA256: sum}
}

// Download downloads one of the server's agent builds into w (ADR-0027).
// The caller checks what it got against the update it acts on. The request is
// signed, so a server that holds back test builds from some organizations
// (its dev scope) knows whose build to hand out.
func (c *Client) Download(ctx context.Context, file string, w io.Writer) error {
	resp, err := c.do(ctx, http.MethodGet, agentproto.PathAgentDownload(url.PathEscape(file)), nil, true)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	// A body shorter than its Content-Length fails as io.ErrUnexpectedEOF.
	_, err = io.Copy(w, resp.Body)
	return err
}

// MeshSettings returns the MeshAgent settings for the device's site and
// the server's signature on them, for the caller to verify before using
// them.
func (c *Client) MeshSettings(ctx context.Context) ([]byte, Signed, error) {
	resp, nonce, err := c.send(ctx, http.MethodGet, agentproto.PathMeshSettings, nil, true)
	if err != nil {
		return nil, Signed{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, Signed{}, err
	}
	return b, c.signed(resp, agentproto.PathMeshSettings, nonce, sha256.Sum256(b)), nil
}

// do sends a request and returns a 2xx response; other statuses become an
// *Error.
func (c *Client) do(ctx context.Context, method, target string, body []byte, sign bool) (*http.Response, error) {
	resp, _, err := c.send(ctx, method, target, body, sign)
	return resp, err
}

// send is do that also returns the nonce a signed request carried, which
// the server's signature on its answer covers.
func (c *Client) send(ctx context.Context, method, target string, body []byte, sign bool) (*http.Response, string, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base.String()+target, rd)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", c.agent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	var nonce string
	if sign {
		if c.key == nil {
			return nil, "", errors.New("the agent is not enrolled")
		}
		h, err := agentproto.Sign(c.key, c.device, method, target, body, c.now())
		if err != nil {
			return nil, "", err
		}
		req.Header.Set("Authorization", h)
		a, _ := agentproto.Parse(h) // what Sign wrote parses
		nonce = a.Nonce
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, "", err
	}
	if resp.StatusCode/100 == 2 {
		return resp, nonce, nil
	}
	defer func() { _ = resp.Body.Close() }()
	e := &Error{Status: resp.StatusCode}
	var env struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10)); err == nil && json.Unmarshal(b, &env) == nil {
		e.Code, e.Message = env.Error.Code, env.Error.Message
	}
	return nil, "", e
}

// Poll waits for jobs (ADR-0017). The server holds the request for up to
// agentproto.PollWait. accepts, the job capabilities this build takes
// (ADR-0064), is sent only while the last heartbeat answer was of protocol
// level 2 or higher: a process's first poll, before any answer, says
// nothing, and the server keeps what it was told before.
func (c *Client) Poll(ctx context.Context, accepts []string) (*agentproto.PollResponse, error) {
	var req agentproto.PollRequest
	if c.newFields() {
		req.Accepts = append([]string{}, accepts...)
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	var out agentproto.PollResponse
	// Eight jobs with 64 KiB scripts and their arguments, base64-encoded.
	return &out, c.callLimit(ctx, http.MethodPost, agentproto.PathJobsPoll, body, true, &out, 8<<20)
}

// Start asks whether a delivered run may start now.
func (c *Client) Start(ctx context.Context, runID string) (*agentproto.StartResponse, error) {
	var out agentproto.StartResponse
	return &out, c.call(ctx, http.MethodPost, agentproto.PathJobStart(runID), []byte("{}"), true, &out)
}

// Result reports how a run ended. The program it started goes only to a
// server of protocol level 2 or higher; a result that names one waits for
// this process's first heartbeat answer to know the level, so a result kept
// across a restart still carries it (ADR-0064), until LevelWait after the
// client was made: then it goes without, as to a server of level 1.
func (c *Client) Result(ctx context.Context, runID string, r agentproto.ResultRequest) error {
	if r.Interpreter != nil {
		if wait := time.Until(c.knownBy); wait > 0 {
			t := time.NewTimer(wait)
			select {
			case <-c.known:
			case <-t.C:
			case <-ctx.Done():
				t.Stop()
				return ctx.Err()
			}
			t.Stop()
		}
		if !c.newFields() {
			r.Interpreter = nil
		}
	}
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	resp, err := c.do(ctx, http.MethodPost, agentproto.PathJobResult(runID), body, true)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	return resp.Body.Close()
}

// Hardware sends a hardware report, already encoded (ADR-0065). A server
// without the endpoint answers 404, an *Error the caller may drop.
func (c *Client) Hardware(ctx context.Context, body []byte) error {
	resp, err := c.do(ctx, http.MethodPost, agentproto.PathHardware, body, true)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	return resp.Body.Close()
}

// AgentLogs sends a batch of log records (ADR-0069) and returns the
// server's answer. A server without the endpoint answers 404, which the
// caller finds with errors.As and an *Error.
func (c *Client) AgentLogs(ctx context.Context, b agentproto.LogBatch) (agentproto.LogAck, error) {
	body, err := json.Marshal(b)
	if err != nil {
		return agentproto.LogAck{}, err
	}
	var out agentproto.LogAck
	err = c.call(ctx, http.MethodPost, agentproto.PathAgentLogs, body, true, &out)
	return out, err
}

// EscrowVolumes reports the BitLocker volumes and their recovery-password
// protectors' IDs and learns which need escrow (ADR-0081). Never a password.
func (c *Client) EscrowVolumes(ctx context.Context, rep agentproto.EscrowVolumesReport) (agentproto.EscrowVolumesAnswer, error) {
	body, err := json.Marshal(rep)
	if err != nil {
		return agentproto.EscrowVolumesAnswer{}, err
	}
	var out agentproto.EscrowVolumesAnswer
	err = c.call(ctx, http.MethodPost, agentproto.PathEscrowVolumes, body, true, &out)
	return out, err
}

// EscrowUpload sends one sealed recovery key (ADR-0081).
func (c *Client) EscrowUpload(ctx context.Context, rec agentproto.EscrowRecord) (agentproto.EscrowAnswer, error) {
	body, err := json.Marshal(rec)
	if err != nil {
		return agentproto.EscrowAnswer{}, err
	}
	var out agentproto.EscrowAnswer
	err = c.call(ctx, http.MethodPost, agentproto.PathEscrow, body, true, &out)
	return out, err
}

// Removed reports how uninstalling the agent on the server's instruction
// went (ADR-0050).
func (c *Client) Removed(ctx context.Context, r agentproto.RemovedReport) error {
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	resp, err := c.do(ctx, http.MethodPost, agentproto.PathRemoved, body, true)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	return resp.Body.Close()
}

// call sends a request and decodes its JSON answer into dst.
func (c *Client) call(ctx context.Context, method, target string, body []byte, sign bool, dst any) error {
	return c.callLimit(ctx, method, target, body, sign, dst, 1<<20)
}

// callLimit is call with a limit on the answer's size.
func (c *Client) callLimit(ctx context.Context, method, target string, body []byte, sign bool, dst any, limit int64) error {
	resp, err := c.do(ctx, method, target, body, sign)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if err := json.NewDecoder(io.LimitReader(resp.Body, limit)).Decode(dst); err != nil {
		return fmt.Errorf("reading the server's answer: %w", err)
	}
	return nil
}
