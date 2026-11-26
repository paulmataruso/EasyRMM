package keystore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// LogEntry is one line of the keystore's own append-only log (ADR-0081
// section 7). Each line carries the hash of the one before it, so a line
// removed or changed breaks the chain. It holds no key and no ciphertext.
type LogEntry struct {
	Seq int64     `json:"seq"`
	At  time.Time `json:"at"`
	// Op is the operation; Org and Record say what it touched (empty when
	// nothing); RequestID is the server's audit request ID.
	Op        string `json:"op"`
	Org       string `json:"org,omitempty"`
	Record    string `json:"record,omitempty"`
	RequestID string `json:"requestId,omitempty"`
	// Result is "ok", or the code of a refusal.
	Result string `json:"result"`
	// Plaintext marks the entries that returned a key: the ones the server's
	// audit must account for.
	Plaintext bool   `json:"plaintext,omitempty"`
	Prev      string `json:"prev"`
	Hash      string `json:"hash"`
}

// ErrLogChain is a log whose chain does not hold.
var ErrLogChain = errors.New("keystore: the log's hash chain is broken")

// SumLog is the hash of an entry: SHA-256 of its previous hash and its
// own fields without its hash.
func SumLog(e LogEntry) string {
	e.Hash = ""
	b, _ := json.Marshal(e)
	h := sha256.New()
	h.Write([]byte(e.Prev))
	h.Write([]byte{'\n'})
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyLog checks that entries, in order, continue the chain from prev
// (the hash of the entry before the first; empty at the start of the log) and
// that sequence numbers follow on from seq. It returns the last hash and
// sequence number.
func VerifyLog(prev string, seq int64, entries []LogEntry) (string, int64, error) {
	for _, e := range entries {
		if e.Prev != prev || e.Seq != seq+1 || e.Hash != SumLog(e) {
			return prev, seq, ErrLogChain
		}
		prev, seq = e.Hash, e.Seq
	}
	return prev, seq, nil
}
