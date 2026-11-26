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
	return c.do(ctx, req, false)
}

// do is Do. With secret the answer is read into a buffer of ours, decoded
// and the buffer zeroed, so that the only copy of a key left is the one in the
// Response, which the caller zeroes.
func (c *Client) do(ctx context.Context, req Request, secret bool) (*Response, error) {
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
	if secret {
		raw, err := io.ReadAll(io.LimitReader(conn, MaxMessage))
		defer func() { clear(raw[:cap(raw)]) }()
		if err != nil || json.Unmarshal(raw, &resp) != nil {
			return nil, fmt.Errorf("%w: no answer", ErrUnavailable)
		}
	} else if err := json.NewDecoder(io.LimitReader(conn, MaxMessage)).Decode(&resp); err != nil {
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
		Enc: enc, Ciphertext: ct, Fingerprint: fingerprint, Kind: ec.kindOrDefault()})
	if err != nil {
		return "", err
	}
	if r.Result != Match && r.Result != Mismatch {
		return "", fmt.Errorf("%w: unexpected answer", ErrUnavailable)
	}
	return r.Result, nil
}

// ReadEscrow has the keystore open a record and return its recovery password:
// the one call that returns a key. The caller zeroes the slice. requestID is
// the audit request ID the keystore's log keeps, and record the escrow record's
// ID.
func (c *Client) ReadEscrow(ctx context.Context, requestID, record, wrappedPrivate string, ec EscrowContext, enc, ct, fingerprint []byte) ([]byte, error) {
	r, err := c.do(ctx, Request{Op: OpReadEscrow, ID: requestID, Record: record, WrappedPrivate: wrappedPrivate, Context: &ec,
		Enc: enc, Ciphertext: ct, Fingerprint: fingerprint, Kind: ec.kindOrDefault()}, true)
	if err != nil {
		if r != nil {
			clear(r.Plaintext)
		}
		return nil, err
	}
	if len(r.Plaintext) == 0 {
		return nil, fmt.Errorf("%w: unexpected answer", ErrUnavailable)
	}
	return r.Plaintext, nil
}

// LogPage is a stretch of the keystore's log.
type LogPage struct {
	// Prev is the hash of the entry before the first one here.
	Prev    string
	Entries []LogEntry
}

// Log reads the keystore's log after seq.
func (c *Client) Log(ctx context.Context, seq int64, limit int) (LogPage, error) {
	r, err := c.Do(ctx, Request{Op: OpLog, Since: seq, Limit: limit})
	if err != nil {
		return LogPage{}, err
	}
	return LogPage{Prev: r.LogPrev, Entries: r.Entries}, nil
}

// RewrapOrgKey has the keystore move a wrapped organization key from the KEK
// version that wraps it to the primary version. Only the new wrapped form and
// its version come back.
func (c *Client) RewrapOrgKey(ctx context.Context, org, keyID, purpose, wrappedPrivate string) (MadeKey, error) {
	r, err := c.Do(ctx, Request{Op: OpRewrapOrgKey, Org: org, KeyID: keyID, Purpose: purpose, WrappedPrivate: wrappedPrivate})
	if err != nil {
		return MadeKey{}, err
	}
	if r.WrappedPrivate == "" || r.KEKVersion < 1 {
		return MadeKey{}, fmt.Errorf("%w: unexpected answer", ErrUnavailable)
	}
	return MadeKey{WrappedPrivate: r.WrappedPrivate, KEKVersion: r.KEKVersion}, nil
}

// ResealEscrow has the keystore open a record under the organization's old key
// and seal it to the new one. Old and next differ only in the key's ID. Only
// ciphertext comes back.
func (c *Client) ResealEscrow(ctx context.Context, requestID, record, oldWrapped string, old, next EscrowContext, newPublic, enc, ct, fingerprint []byte) (newEnc, newCT []byte, err error) {
	r, err := c.Do(ctx, Request{Op: OpResealEscrow, ID: requestID, Record: record, WrappedPrivate: oldWrapped, Context: &old, NewContext: &next,
		NewPublic: newPublic, Enc: enc, Ciphertext: ct, Fingerprint: fingerprint, Kind: old.kindOrDefault()})
	if err != nil {
		return nil, nil, err
	}
	if len(r.Enc) != 32 || len(r.Ciphertext) == 0 {
		return nil, nil, fmt.Errorf("%w: unexpected answer", ErrUnavailable)
	}
	return r.Enc, r.Ciphertext, nil
}
