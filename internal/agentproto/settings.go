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
	"time"
)

// Signed settings (ADR-0058, slice 2). The server computes a device's
// effective settings for the keys its agent reported, signs the whole
// document with the job key, and carries it in a heartbeat answer when the
// agent holds an older version. A setting is state, not an instruction: it
// does not expire, and the version, not the time, keeps an old document from
// replacing a newer one. The agent keeps what it applied and acknowledges it
// in its next heartbeat.

// Capabilities, limits and signing domain of settings documents.
const (
	// CapSettings is what an agent lists in SettingsCapabilities.Accepts when
	// it takes a settings document. The server issues documents only to a
	// device whose last report lists it.
	CapSettings = "settings.v1"
	// InstructionSettings is the kind of a settings document in the agents'
	// instruction logs.
	InstructionSettings = "settings"
	// SettingsPayloadVersion is the version of SettingsPayload.
	SettingsPayloadVersion = 1
	// MaxSettingsDocument bounds a document's payload (JSON) in bytes.
	MaxSettingsDocument = 64 << 10
	// MaxSettingsVersion is the highest document version: JSON carries
	// integers up to 2^53 - 1 exactly. The lowest is 1.
	MaxSettingsVersion = 1<<53 - 1
	// MinSettingsHeartbeat is the catalog's lowest heartbeat interval: an
	// agent holding a document never checks in more often (ADR-0058).
	MinSettingsHeartbeat = 30
	// MaxCapabilityKeys bounds the keys an agent reports, MaxSettingProblems
	// the problems, and MaxSettingsReason a problem's text.
	MaxCapabilityKeys  = 64
	MaxSettingProblems = 64
	MaxSettingsReason  = 200
	// MaxSettingsKey bounds a key's name.
	MaxSettingsKey = 64
)

// SettingsDocumentKey is the name under which an agent reports a problem with
// the whole document (a refusal) rather than with one key.
const SettingsDocumentKey = "document"

// The states of one key in SettingsReport.Problems.
const (
	ProblemInvalid = "invalid"
	ProblemClamped = "clamped"
	// ProblemRefused is the prefix of a refusal: "refused: <reason>".
	ProblemRefused = "refused"
)

const settingsSigContext = "EASYRMM-SETTINGS-SIG-V1\n"

// SettingsCapabilities is what the agent understands, in its signed
// heartbeat: the signed messages it takes, and each key of its catalog with
// the version of that key's schema (it rises whenever the key accepts more).
type SettingsCapabilities struct {
	Accepts  []string       `json:"accepts"`
	Settings map[string]int `json:"settings"`
}

// Takes reports whether the agent lists the capability.
func (c *SettingsCapabilities) Takes(name string) bool {
	if c == nil {
		return false
	}
	for _, a := range c.Accepts {
		if a == name {
			return true
		}
	}
	return false
}

// Check bounds a report an agent sent.
func (c *SettingsCapabilities) Check() error {
	if len(c.Settings) > MaxCapabilityKeys || len(c.Accepts) > MaxCapabilityKeys {
		return errors.New("too many capabilities")
	}
	for _, a := range c.Accepts {
		if len(a) == 0 || len(a) > MaxSettingsKey {
			return errors.New("a capability is empty or too long")
		}
	}
	for k, v := range c.Settings {
		if len(k) == 0 || len(k) > MaxSettingsKey || v < 0 || v > 1<<20 {
			return fmt.Errorf("key %q: not a valid name or schema version", k)
		}
	}
	return nil
}

// SettingsReport is what the agent holds, in its signed heartbeat: the
// version applied (0 for none) and, per key, "invalid", "clamped" or
// "refused: <reason>"; a refusal of the whole document is under
// SettingsDocumentKey.
type SettingsReport struct {
	Version  int64             `json:"version"`
	Problems map[string]string `json:"problems,omitempty"`
}

// Check bounds a report an agent sent.
func (r *SettingsReport) Check() error {
	if len(r.Problems) > MaxSettingProblems {
		return errors.New("too many problems")
	}
	for k, v := range r.Problems {
		if len(k) == 0 || len(k) > MaxSettingsKey || len(v) > MaxSettingsReason {
			return errors.New("a problem is too long")
		}
	}
	return nil
}

// SettingsPayload is the document: the device's effective settings, for
// every key both sides know.
type SettingsPayload struct {
	V        int       `json:"v"`
	DeviceID string    `json:"deviceId"`
	Version  int64     `json:"version"`
	IssuedAt time.Time `json:"issuedAt"`
	// Settings maps a key to its value, held as the key's schema writes it.
	Settings map[string]json.RawMessage `json:"settings"`
}

// SignedSettings is a SettingsPayload with the server's signature.
type SignedSettings struct {
	// Payload is the SettingsPayload JSON, base64 (standard, padded).
	Payload string `json:"payload"`
	// Signature is the Ed25519 signature, base64 (standard, padded), over
	// the context "EASYRMM-SETTINGS-SIG-V1\n" and the payload's JSON.
	Signature string `json:"signature"`
}

// Errors from VerifySettings.
var (
	ErrSettingsSignature = errors.New("agentproto: the settings document's signature does not verify with the server key this agent trusts")
	ErrSettingsMalformed = errors.New("agentproto: the settings document is malformed")
	ErrSettingsDevice    = errors.New("agentproto: the settings document is for another device")
	ErrSettingsVersion   = errors.New("agentproto: the settings document's version is outside 1 to 2^53 - 1")
	ErrSettingsTooBig    = errors.New("agentproto: the settings document is too big")
)

// SettingsHash is the hash of a document's content, its settings: the same
// settings give the same hash whoever wrote them, and the version and issue
// time are not part of it.
func SettingsHash(settings map[string]json.RawMessage) string {
	// A map of raw messages always encodes, with its keys in order.
	b, _ := json.Marshal(settings)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// SignSettings signs a settings document with the server's job key.
func SignSettings(key ed25519.PrivateKey, p SettingsPayload) (SignedSettings, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return SignedSettings{}, err
	}
	if len(b) > MaxSettingsDocument {
		return SignedSettings{}, ErrSettingsTooBig
	}
	sig := ed25519.Sign(key, append([]byte(settingsSigContext), b...))
	return SignedSettings{Payload: base64.StdEncoding.EncodeToString(b), Signature: base64.StdEncoding.EncodeToString(sig)}, nil
}

// VerifySettings checks a signed document with the keys the agent trusts and
// returns its payload. It refuses a signature that does not verify, an
// envelope with a field it does not know (ADR-0009: signed instructions stay
// strict), a document for another device and a version outside 1 to 2^53 - 1.
// Whether the version is newer than the one applied, and whether every key was
// reported, is for the agent, which knows what it holds.
func VerifySettings[K KeyArg](key K, s SignedSettings, deviceID string) (SettingsPayload, error) {
	if len(s.Payload) > base64.StdEncoding.EncodedLen(MaxSettingsDocument) {
		return SettingsPayload{}, ErrSettingsTooBig
	}
	b, err := base64.StdEncoding.DecodeString(s.Payload)
	if err != nil {
		return SettingsPayload{}, ErrSettingsMalformed
	}
	sig, err := base64.StdEncoding.DecodeString(s.Signature)
	if err != nil || !keysOf(key).verify(append([]byte(settingsSigContext), b...), sig) {
		return SettingsPayload{}, ErrSettingsSignature
	}
	var p SettingsPayload
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return SettingsPayload{}, fmt.Errorf("%w: %w", ErrSettingsMalformed, err)
	}
	switch {
	case p.V != SettingsPayloadVersion || p.Settings == nil || p.IssuedAt.IsZero():
		return p, ErrSettingsMalformed
	case p.DeviceID != deviceID:
		return p, ErrSettingsDevice
	case p.Version < 1 || p.Version > MaxSettingsVersion:
		return p, ErrSettingsVersion
	}
	return p, nil
}
