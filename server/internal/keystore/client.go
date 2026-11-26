package keystore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// Client talks to the keystore over its Unix socket. The server's container
// reaches the keystore only this way. One connection carries one request.
type Client struct {
	// Path is the socket.
	Path string
	// Timeout bounds one call; the default is 30 seconds. Init and unseal
	// run Argon2id and take longer, so the host command sets more.
	Timeout time.Duration
}

// RemoteError is a refusal or failure the keystore reported.
type RemoteError struct {
	Code string
	Msg  string
}

func (e *RemoteError) Error() string { return "keystore: " + e.Msg }

// ErrUnavailable is a keystore that could not be reached or answered
// badly. The server treats it as "unavailable", never as an answer.
var ErrUnavailable = errors.New("keystore: not reachable")

// Do sends a request and returns the response, or a *RemoteError for a
// refusal, or an error wrapping ErrUnavailable.
func (c *Client) Do(ctx context.Context, req Request) (*Response, error) {
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.Path)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	var resp Response
	if err := json.NewDecoder(io.LimitReader(conn, MaxMessage)).Decode(&resp); err != nil {
		// A refused peer gets silence: no answer at all.
		return nil, fmt.Errorf("%w: no answer", ErrUnavailable)
	}
	if !resp.OK {
		return &resp, &RemoteError{Code: resp.Code, Msg: resp.Error}
	}
	return &resp, nil
}

// Status asks the keystore how it is.
func (c *Client) Status(ctx context.Context) (Status, error) {
	r, err := c.Do(ctx, Request{Op: OpStatus})
	if err != nil {
		return Status{}, err
	}
	if r.Status == nil {
		return Status{}, fmt.Errorf("%w: no status", ErrUnavailable)
	}
	return *r.Status, nil
}

// MadeKey is a new organization key as the keystore returns it: the public
// half and the private half wrapped under the KEK.
type MadeKey struct {
	PublicKey      []byte
	WrappedPrivate string
	KEKVersion     int
}

// CreateOrgKey has the keystore make an organization key of a purpose
// ("escrow" or "service").
func (c *Client) CreateOrgKey(ctx context.Context, org, keyID, purpose string) (MadeKey, error) {
	r, err := c.Do(ctx, Request{Op: OpCreateOrgKey, Org: org, KeyID: keyID, Purpose: purpose})
	if err != nil {
		return MadeKey{}, err
	}
	return MadeKey{PublicKey: r.PublicKey, WrappedPrivate: r.WrappedPrivate, KEKVersion: r.KEKVersion}, nil
}

// VerifyEscrow has the keystore open a record and compare its fingerprint.
// The answer is Match or Mismatch; nothing of the key comes back.
func (c *Client) VerifyEscrow(ctx context.Context, requestID, wrappedPrivate string, ec EscrowContext, enc, ct, fingerprint []byte) (string, error) {
	r, err := c.Do(ctx, Request{Op: OpVerifyEscrow, ID: requestID, WrappedPrivate: wrappedPrivate, Context: &ec,
		Enc: enc, Ciphertext: ct, Fingerprint: fingerprint, Kind: "bitlocker"})
	if err != nil {
		return "", err
	}
	if r.Result != Match && r.Result != Mismatch {
		return "", fmt.Errorf("%w: unexpected answer", ErrUnavailable)
	}
	return r.Result, nil
}
