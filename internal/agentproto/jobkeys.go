package agentproto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Agents that follow the server's job key (ADR-0057, slice 1). One Ed25519
// key signs everything the server asks an agent to do. An agent trusts a
// small set of such keys, each with a generation, and accepts a signature by
// any of them. It takes a new key only from a statement that verifies under a
// key it already trusts (the hand-over), and drops the others only on a
// statement signed by the key that stays (the cut-over). Both are signed
// under contexts of their own, bound to one device and one install, valid for
// ten minutes, and carried only in heartbeat answers, like ADR-0055's trust
// instruction, whose checks they share (strict JSON, bounded, monotonic issue
// time on the agent's side).

// Capabilities and features of the job key set.
const (
	// CapJobKeys is announced in HeartbeatRequest.Caps by an agent that
	// understands the hand-over and the cut-over; the server sends them only
	// to such an agent (ADR-0009).
	CapJobKeys = "jobkeys.v1"
	// FeatureInstructionLog is listed in HeartbeatResponse.Features by a
	// server that takes the agent's instruction log and acknowledges it.
	FeatureInstructionLog = "instruction-log"
)

// Limits shared by both sides.
const (
	// MaxTrustedKeys is how many keys an agent trusts at most: the ring's two,
	// a key the server never held, and one more a hand-over may add.
	MaxTrustedKeys = 4
	// MaxDroppedKeys is how many dropped keys an agent remembers, to name them
	// when a job signed by one arrives.
	MaxDroppedKeys = 8
	// KeyStatementValid is how long a signed statement stays valid.
	KeyStatementValid = 10 * time.Minute
	// MaxKeyStatementPayload bounds a statement's payload (base64) as an agent
	// reads it.
	MaxKeyStatementPayload = 2048
	// MaxKeyReportAuthorities bounds the authorities a heartbeat reports.
	MaxKeyReportAuthorities = 16
	// MaxInstructionLog is how many entries the agent keeps.
	MaxInstructionLog = 1000
	// MaxInstructionBatch is how many entries one heartbeat carries.
	MaxInstructionBatch = 100
	// MaxKeyRefusal bounds the reason of a refusal.
	MaxKeyRefusal = 200
)

// The kinds of instruction an agent logs and the server records.
const (
	InstructionJob       = "job"
	InstructionUpdate    = "update"
	InstructionUninstall = "uninstall"
	InstructionEasyPatch = "easypatch"
	InstructionDownload  = "download"
	InstructionRepair    = "repair"
	InstructionTrust     = "trust"
	InstructionHandover  = "handover"
	InstructionCutover   = "cutover"
)

// Keys is the set of job-signing public keys an agent trusts. A signature by
// any of them verifies. An empty set verifies nothing: an agent with no
// pinned key refuses every instruction.
type Keys []ed25519.PublicKey

// KeyArg is what a verifier takes as its key: one public key, or Keys.
type KeyArg interface{ ed25519.PublicKey | Keys }

func keysOf[K KeyArg](k K) Keys {
	switch v := any(k).(type) {
	case ed25519.PublicKey:
		if v == nil {
			return nil
		}
		return Keys{v}
	case Keys:
		return v
	}
	return nil
}

// verify reports whether sig is a signature of msg by any key of the set.
func (k Keys) verify(msg, sig []byte) bool {
	ok := false
	for _, key := range k {
		if len(key) == ed25519.PublicKeySize && ed25519.Verify(key, msg, sig) {
			ok = true
		}
	}
	return ok
}

// SignerOf returns the fingerprint of the first key of the set for which
// verify reports true, "" when none does: how an agent names the key that
// signed an instruction, by verifying it again under one key at a time.
func (k Keys) SignerOf(verify func(ed25519.PublicKey) bool) string {
	for _, key := range k {
		if len(key) == ed25519.PublicKeySize && verify(key) {
			return Fingerprint(key)
		}
	}
	return ""
}

// InstructionRecorder is what an agent package calls for an instruction it
// accepted: its kind, its ID and the fingerprint of the key that signed it
// (ADR-0057's instruction log).
type InstructionRecorder func(kind, id, signer string)

// Contains reports whether key is in the set.
func (k Keys) Contains(key ed25519.PublicKey) bool {
	for _, have := range k {
		if bytes.Equal(have, key) {
			return true
		}
	}
	return false
}

// Fingerprint is a key's name wherever a person reads it: the first 32
// hexadecimal digits of the SHA-256 of its public key. FormatFingerprint
// groups it in fours.
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:16])
}

// FormatFingerprint groups a fingerprint in fours, as the console prints it.
func FormatFingerprint(fp string) string {
	var b strings.Builder
	for i := 0; i < len(fp); i += 4 {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(fp[i:min(i+4, len(fp))])
	}
	return b.String()
}

// InstallID names one install of an agent: the SHA-256 of the device's public
// key, in hex. A device enrolled again has a new key, so a statement made for
// its earlier enrollment is for another install.
func InstallID(devicePub ed25519.PublicKey) string {
	sum := sha256.Sum256(devicePub)
	return hex.EncodeToString(sum[:])
}

// TrustedKey is one key an agent trusts, as its heartbeats and job polls
// report it. Generation 0 is unknown: a key from before generations.
type TrustedKey struct {
	Key        string `json:"key"`
	Generation int64  `json:"generation,omitempty"`
}

// KeyRefusal is a statement an agent refused, with the reason, reported in its
// next heartbeats until an answer no longer carries that statement.
type KeyRefusal struct {
	// Statement is InstructionHandover or InstructionCutover.
	Statement string `json:"statement"`
	ID        string `json:"id"`
	Reason    string `json:"reason"`
}

// LoggedInstruction is one entry of the agent's instruction log: an
// instruction it accepted.
type LoggedInstruction struct {
	// Seq numbers the entries of one install from 1.
	Seq  uint64 `json:"seq"`
	Kind string `json:"kind"`
	// ID is the run, attempt, uninstall or statement ID; for a download, the
	// nonce of the request it answered.
	ID string `json:"id"`
	// Signer is the fingerprint of the key that signed it.
	Signer string    `json:"signer"`
	At     time.Time `json:"at"`
}

// InstructionLogReport is the agent's instruction log as a heartbeat carries
// it: the entries the server has not acknowledged, and the sequence of the
// last one it did. Sent only to a server that lists FeatureInstructionLog.
type InstructionLogReport struct {
	Acked   uint64              `json:"acked"`
	Entries []LoggedInstruction `json:"entries,omitempty"`
}

// Valid reports whether an entry is well formed; the server drops one that
// is not.
func (e LoggedInstruction) Valid() bool {
	return e.Seq > 0 && e.Kind != "" && len(e.Kind) <= 16 && e.ID != "" && len(e.ID) <= 200 && len(e.Signer) == 32 && !e.At.IsZero()
}

// KeyStatementVersion is the version of KeyStatement.
const KeyStatementVersion = 1

// KeyStatement is the payload of a hand-over ("the server's newer key is
// Key, generation Generation") and of a cut-over ("trust only Key").
type KeyStatement struct {
	V        int    `json:"v"`
	ID       string `json:"id"`
	DeviceID string `json:"deviceId"`
	// Install is InstallID of the device's key: the statement is for this
	// install and no other.
	Install    string    `json:"install"`
	Key        string    `json:"key"`
	Generation int64     `json:"generation"`
	IssuedAt   time.Time `json:"issuedAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

// SignedKeyStatement is a KeyStatement with the signature that makes it a
// hand-over or a cut-over: the two differ in the context they are signed
// under, and the field that carries them.
type SignedKeyStatement struct {
	// Payload is the KeyStatement JSON, base64 (standard, padded).
	Payload string `json:"payload"`
	// Signature is the Ed25519 signature, base64 (standard, padded).
	Signature string `json:"signature"`
}

const (
	handoverSigContext = "EASYRMM-JOB-KEY-HANDOVER-V1\n"
	cutoverSigContext  = "EASYRMM-JOB-KEY-CUTOVER-V1\n"
)

// Errors from the statements' verifiers.
var (
	ErrKeyStatementSignature = errors.New("agentproto: the statement's signature does not verify with a server key this agent trusts")
	ErrKeyStatementMalformed = errors.New("agentproto: the key statement is malformed")
	ErrKeyStatementDevice    = errors.New("agentproto: the key statement is for another device")
	ErrKeyStatementInstall   = errors.New("agentproto: the key statement is for another install of the agent")
	ErrKeyStatementExpired   = errors.New("agentproto: the key statement has expired")
	ErrKeyStatementFuture    = errors.New("agentproto: the key statement was issued in the future")
)

// SignHandover signs a hand-over with a key the device already trusts. It
// refuses a payload the agent would refuse as malformed.
func SignHandover(key ed25519.PrivateKey, p KeyStatement) (SignedKeyStatement, error) {
	return signKeyStatement(key, handoverSigContext, p)
}

// SignCutover signs a cut-over with the key that is to stay: p.Key is its
// public half.
func SignCutover(key ed25519.PrivateKey, p KeyStatement) (SignedKeyStatement, error) {
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok || p.Key != EncodeKey(pub) {
		return SignedKeyStatement{}, fmt.Errorf("%w: a cut-over is signed with the key it names", ErrKeyStatementMalformed)
	}
	return signKeyStatement(key, cutoverSigContext, p)
}

func signKeyStatement(key ed25519.PrivateKey, context string, p KeyStatement) (SignedKeyStatement, error) {
	if err := p.validate(); err != nil {
		return SignedKeyStatement{}, err
	}
	b, err := json.Marshal(p)
	if err != nil {
		return SignedKeyStatement{}, err
	}
	sig := ed25519.Sign(key, append([]byte(context), b...))
	return SignedKeyStatement{Payload: base64.StdEncoding.EncodeToString(b), Signature: base64.StdEncoding.EncodeToString(sig)}, nil
}

// VerifyHandover checks a hand-over: signed under the hand-over context by a
// key of keys, for this device and install, not expired, not issued after
// now plus MaxSkew, valid for no longer than KeyStatementValid, with no
// unknown fields. It returns the payload; whether the key it introduces is
// acceptable (its generation, the count) is the agent's trust store's to say.
func VerifyHandover[K KeyArg](key K, s SignedKeyStatement, deviceID, install string, now time.Time) (KeyStatement, error) {
	b, err := openSigned(s.Payload, MaxKeyStatementPayload)
	if err != nil {
		return KeyStatement{}, err
	}
	sig, err := base64.StdEncoding.DecodeString(s.Signature)
	if err != nil || !keysOf(key).verify(append([]byte(handoverSigContext), b...), sig) {
		return peek(b), ErrKeyStatementSignature
	}
	return checkKeyStatement(b, deviceID, install, now)
}

// VerifyCutover checks a cut-over: signed under the cut-over context by the
// key it names, which must be one of keys, and otherwise as VerifyHandover.
func VerifyCutover[K KeyArg](key K, s SignedKeyStatement, deviceID, install string, now time.Time) (KeyStatement, error) {
	b, err := openSigned(s.Payload, MaxKeyStatementPayload)
	if err != nil {
		return KeyStatement{}, err
	}
	p := peek(b)
	named, derr := DecodeKey(p.Key)
	sig, serr := base64.StdEncoding.DecodeString(s.Signature)
	if derr != nil || serr != nil || !keysOf(key).Contains(named) || !ed25519.Verify(named, append([]byte(cutoverSigContext), b...), sig) {
		return p, ErrKeyStatementSignature
	}
	return checkKeyStatement(b, deviceID, install, now)
}

// peek reads what it can of a payload that did not verify, so that a refusal
// can name its ID. Nothing in it is authentic.
func peek(b []byte) KeyStatement {
	var p KeyStatement
	_ = json.Unmarshal(b, &p)
	if len(p.ID) > 64 {
		p.ID = ""
	}
	return p
}

func checkKeyStatement(b []byte, deviceID, install string, now time.Time) (KeyStatement, error) {
	var p KeyStatement
	if err := decodeStrict(b, &p); err != nil {
		// The signature held, so the ID is the server's: a refusal can name it.
		return peek(b), ErrKeyStatementMalformed
	}
	if err := p.validate(); err != nil {
		return p, err
	}
	switch {
	case p.DeviceID != deviceID:
		return p, ErrKeyStatementDevice
	case p.Install != install:
		return p, ErrKeyStatementInstall
	case !now.Before(p.ExpiresAt):
		return p, ErrKeyStatementExpired
	case p.IssuedAt.After(now.Add(MaxSkew)):
		return p, ErrKeyStatementFuture
	}
	return p, nil
}

func (p KeyStatement) validate() error {
	bad := func(what string) error { return fmt.Errorf("%w: %s", ErrKeyStatementMalformed, what) }
	switch {
	case p.V != KeyStatementVersion:
		return bad("version")
	case p.ID == "" || len(p.ID) > 64:
		return bad("id")
	case p.DeviceID == "" || len(p.DeviceID) > 64:
		return bad("device")
	case len(p.Install) != 64:
		return bad("install")
	case p.Generation < 1:
		return bad("generation")
	case p.IssuedAt.IsZero() || p.ExpiresAt.IsZero() || !p.ExpiresAt.After(p.IssuedAt) || p.ExpiresAt.Sub(p.IssuedAt) > KeyStatementValid:
		return bad("validity")
	}
	if _, err := DecodeKey(p.Key); err != nil {
		return bad("key")
	}
	return nil
}

// openSigned decodes a payload's base64 within a size bound.
func openSigned(payload string, max int) ([]byte, error) {
	if len(payload) > max {
		return nil, ErrKeyStatementMalformed
	}
	b, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, ErrKeyStatementMalformed
	}
	return b, nil
}

// decodeStrict reads one JSON document into v, refusing unknown fields and
// anything after it: signed instructions stay strict on the agent (ADR-0009).
func decodeStrict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil || dec.More() {
		return errors.New("agentproto: not exactly one document of known fields")
	}
	return nil
}
