// Package client talks to an EasyRMM server for the agent: enrollment,
// signed heartbeats and the MeshAgent downloads (ADR-0015).
package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
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
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// Client is a connection to one EasyRMM server.
type Client struct {
	base   *url.URL
	http   *http.Client
	device string
	key    ed25519.PrivateKey
	now    func() time.Time
	agent  string
}

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
	return &Client{
		base:  u,
		http:  &http.Client{Transport: rt, Timeout: 5 * time.Minute},
		now:   time.Now,
		agent: "easyrmm-agent/" + o.Version,
	}, nil
}

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
	return &out, c.call(ctx, http.MethodPost, agentproto.PathHeartbeat, body, true, &out)
}

// Inventory uploads the device's inventory, body being its JSON exactly
// as hashed (ADR-0018). It returns the hash the server stored.
func (c *Client) Inventory(ctx context.Context, body []byte) (string, error) {
	var out agentproto.InventoryResponse
	if err := c.call(ctx, http.MethodPost, agentproto.PathInventory, body, true, &out); err != nil {
		return "", err
	}
	return out.Hash, nil
}

// MeshAgent downloads the MeshAgent binary for a platform into w.
func (c *Client) MeshAgent(ctx context.Context, goos, goarch string, w io.Writer) error {
	q := url.Values{"os": {goos}, "arch": {goarch}}
	resp, err := c.do(ctx, http.MethodGet, agentproto.PathMeshAgent+"?"+q.Encode(), nil, true)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	n, err := io.Copy(w, resp.Body)
	if err != nil {
		return fmt.Errorf("downloading MeshAgent: %w", err)
	}
	if resp.ContentLength >= 0 && n != resp.ContentLength {
		return fmt.Errorf("downloading MeshAgent: got %d of %d bytes", n, resp.ContentLength)
	}
	return nil
}

// MeshSettings returns the MeshAgent settings for the device's site.
func (c *Client) MeshSettings(ctx context.Context) ([]byte, error) {
	resp, err := c.do(ctx, http.MethodGet, agentproto.PathMeshSettings, nil, true)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	return io.ReadAll(io.LimitReader(resp.Body, 64<<10))
}

// do sends a request and returns a 2xx response; other statuses become an
// *Error.
func (c *Client) do(ctx context.Context, method, target string, body []byte, sign bool) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base.String()+target, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.agent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if sign {
		if c.key == nil {
			return nil, errors.New("the agent is not enrolled")
		}
		h, err := agentproto.Sign(c.key, c.device, method, target, body, c.now())
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", h)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 == 2 {
		return resp, nil
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
	return nil, e
}

// Poll waits for jobs (ADR-0017). The server holds the request for up to
// agentproto.PollWait.
func (c *Client) Poll(ctx context.Context) (*agentproto.PollResponse, error) {
	var out agentproto.PollResponse
	// Eight jobs with 64 KiB scripts and their arguments, base64-encoded.
	return &out, c.callLimit(ctx, http.MethodPost, agentproto.PathJobsPoll, []byte("{}"), true, &out, 8<<20)
}

// Start asks whether a delivered run may start now.
func (c *Client) Start(ctx context.Context, runID string) (*agentproto.StartResponse, error) {
	var out agentproto.StartResponse
	return &out, c.call(ctx, http.MethodPost, agentproto.PathJobStart(runID), []byte("{}"), true, &out)
}

// Result reports how a run ended.
func (c *Client) Result(ctx context.Context, runID string, r agentproto.ResultRequest) error {
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
