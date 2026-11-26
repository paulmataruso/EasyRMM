// Package qaticket is the Quick Assist ticket (ADR-0080): a short-lived,
// server-signed note appended to the downloaded runner as a trailer. The
// server signs it; the runner reads its own trailer and checks the signature
// against the key built into the binary, so a file kept for a week, or one
// from another server, does nothing.
package qaticket

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"
)

// Paths of the runner's own requests (ADR-0080). Enroll is unsigned and
// carries the ticket; the others are signed by the session's key.
const (
	PathEnroll = "/api/agent/v1/qa/enroll"
	PathStatus = "/api/agent/v1/qa/status"
	PathEnd    = "/api/agent/v1/qa/end"
)

// Lifetime is how long a ticket is good for.
const Lifetime = time.Hour

const (
	magic = "EZQAT1"
	// MaxTrailer bounds the trailer a runner will read.
	MaxTrailer = 2048
)

// Errors a runner distinguishes.
var (
	ErrNoTrailer = errors.New("qaticket: no ticket attached")
	ErrBad       = errors.New("qaticket: the ticket is not valid")
	ErrExpired   = errors.New("qaticket: the ticket has expired")
)

// Ticket is what the server signs.
type Ticket struct {
	Link   string `json:"link"`
	Server string `json:"server"`
	Expiry int64  `json:"expiry"`
	// Key is the server's ticket key. A release build is shared by every
	// server, so the runner cannot hold the key in its build (decided in
	// review, amending ADR-0080): it checks the trailer is whole and
	// unexpired against this key, and the server, which holds the real one,
	// is the only authority and checks the ticket itself.
	Key string `json:"key"`
}

func message(t Ticket) []byte {
	return []byte("ticket|" + t.Link + "|" + strconv.FormatInt(t.Expiry, 10) + "|" + t.Server + "|" + t.Key)
}

// Sign returns the trailer to append to a download: magic, the JSON ticket,
// the 64-byte signature, a 4-byte big-endian length of both and the magic.
func Sign(key ed25519.PrivateKey, t Ticket) ([]byte, error) {
	t.Key = base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	body, err := json.Marshal(t)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(key, message(t))
	n := len(body) + len(sig)
	if n+2*len(magic)+4 > MaxTrailer {
		return nil, fmt.Errorf("%w: too large", ErrBad)
	}
	var b bytes.Buffer
	b.WriteString(magic)
	b.Write(body)
	b.Write(sig)
	b.Write(binary.BigEndian.AppendUint32(nil, uint32(n))) //nolint:gosec // n is at most MaxTrailer
	b.WriteString(magic)
	return b.Bytes(), nil
}

// Parse reads the trailer at the end of a file of the given size and checks
// its signature and expiry. With a nil pub it checks against the key the
// ticket carries (the runner); the server passes its own key. A file with no trailer is ErrNoTrailer.
func Parse(r io.ReaderAt, size int64, pub ed25519.PublicKey, now time.Time) (Ticket, error) {
	var zero Ticket
	if size < int64(2*len(magic)+4) {
		return zero, ErrNoTrailer
	}
	tail := make([]byte, len(magic)+4)
	if _, err := r.ReadAt(tail, size-int64(len(tail))); err != nil {
		return zero, ErrNoTrailer
	}
	if string(tail[4:]) != magic {
		return zero, ErrNoTrailer
	}
	n := int(tail[0])<<24 | int(tail[1])<<16 | int(tail[2])<<8 | int(tail[3])
	if n < ed25519.SignatureSize || n+2*len(magic)+4 > MaxTrailer || int64(n+2*len(magic)+4) > size {
		return zero, ErrBad
	}
	buf := make([]byte, len(magic)+n)
	if _, err := r.ReadAt(buf, size-int64(len(tail))-int64(len(buf))); err != nil {
		return zero, ErrBad
	}
	if string(buf[:len(magic)]) != magic {
		return zero, ErrBad
	}
	body, sig := buf[len(magic):len(buf)-ed25519.SignatureSize], buf[len(buf)-ed25519.SignatureSize:]
	var t Ticket
	if err := json.Unmarshal(body, &t); err != nil {
		return zero, ErrBad
	}
	if pub == nil {
		k, err := base64.StdEncoding.DecodeString(t.Key)
		if err != nil {
			return zero, ErrBad
		}
		pub = k
	}
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, message(t), sig) {
		return zero, ErrBad
	}
	if !now.Before(time.Unix(t.Expiry, 0)) {
		return zero, ErrExpired
	}
	return t, nil
}
