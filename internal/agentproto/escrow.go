package agentproto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"time"
)

// Recovery-key escrow (ADR-0081). The server hands an agent its
// organization's escrow public key in a heartbeat answer, signed with the job
// key (ADR-0057); the agent reads its BitLocker recovery passwords itself,
// seals each to that key and uploads the record on a route of its own. The
// server stores the record and has the keystore check it; it never holds a
// plaintext key.

// Escrow routes, signed with the device key like every agent request.
const (
	// PathEscrowVolumes receives the volumes and recovery-password
	// protectors the agent found: IDs only, never a password.
	PathEscrowVolumes = "/api/agent/v1/escrow/volumes"
	// PathEscrow receives one sealed record.
	PathEscrow = "/api/agent/v1/escrow"
	// MaxEscrowBody is the largest record the server reads (ADR-0081).
	MaxEscrowBody = 2 << 10
	// MaxEscrowVolumesBody is the largest volume report the server reads.
	MaxEscrowVolumesBody = 16 << 10
)

// CapEscrow is announced in HeartbeatRequest.Caps by an agent that can escrow
// recovery keys; the server sends the escrow key only to such agents.
const CapEscrow = "escrow.v1"

// EscrowKeyPayloadVersion is the version of EscrowKeyPayload.
const EscrowKeyPayloadVersion = 1

// EscrowKeyValid is how long a signed escrow key stays valid; the heartbeat
// carries a fresh one each time.
const EscrowKeyValid = 24 * time.Hour

// Limits on an escrow upload.
const (
	MaxEscrowVolumes    = 32
	MaxEscrowProtectors = 16
	escrowIDLen         = 128
)

// Kinds of escrowed key.
const (
	EscrowBitLocker = "bitlocker"
)

// Escrow record states, as the server and agent name them.
const (
	EscrowMissing    = "missing"
	EscrowPending    = "pending"
	EscrowVerified   = "verified"
	EscrowStale      = "stale"
	EscrowConflict   = "conflict"
	EscrowSuperseded = "superseded"
)

// EscrowKeyPayload gives one device's agent its organization's escrow key.
type EscrowKeyPayload struct {
	V        int    `json:"v"`
	DeviceID string `json:"deviceId"`
	OrgID    string `json:"orgId"`
	// KeyID is the escrow key's ID; the agent binds it into every record.
	KeyID string `json:"keyId"`
	// KeyVersion rises with each new key of the organization. The agent keeps
	// the newest it has verified and never goes back.
	KeyVersion int `json:"keyVersion"`
	// PublicKey is the HPKE X25519 public key, base64 (standard, padded).
	PublicKey string    `json:"publicKey"`
	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// SignedEscrowKey is an EscrowKeyPayload with the server's signature.
type SignedEscrowKey struct {
	// Payload is the EscrowKeyPayload JSON, base64 (standard, padded).
	Payload string `json:"payload"`
	// Signature is the Ed25519 signature, base64 (standard, padded).
	Signature string `json:"signature"`
}

// The context of the signature (ADR-0081): a signature made for another
// instruction never verifies as an escrow key.
const escrowKeySigContext = "easyrmm-escrow-key-v1\n"

// Errors from VerifyEscrowKey.
var (
	ErrEscrowKeySignature = errors.New("agentproto: the escrow key's signature does not verify with the server key this agent trusts")
	ErrEscrowKeyMalformed = errors.New("agentproto: the escrow key is malformed")
	ErrEscrowKeyDevice    = errors.New("agentproto: the escrow key is for another device")
	ErrEscrowKeyExpired   = errors.New("agentproto: the escrow key has expired")
)

// SignEscrowKey signs an escrow key instruction with the server's job key.
func SignEscrowKey(key ed25519.PrivateKey, p EscrowKeyPayload) (SignedEscrowKey, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return SignedEscrowKey{}, err
	}
	sig := ed25519.Sign(key, append([]byte(escrowKeySigContext), b...))
	return SignedEscrowKey{Payload: base64.StdEncoding.EncodeToString(b), Signature: base64.StdEncoding.EncodeToString(sig)}, nil
}

// VerifyEscrowKey checks a signed escrow key with the pinned server key and
// returns its payload and the decoded public key. It refuses another
// device's and an expired instruction.
func VerifyEscrowKey(key ed25519.PublicKey, s SignedEscrowKey, deviceID string, now time.Time) (EscrowKeyPayload, []byte, error) {
	b, err := base64.StdEncoding.DecodeString(s.Payload)
	if err != nil {
		return EscrowKeyPayload{}, nil, ErrEscrowKeyMalformed
	}
	sig, err := base64.StdEncoding.DecodeString(s.Signature)
	if err != nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, append([]byte(escrowKeySigContext), b...), sig) {
		return EscrowKeyPayload{}, nil, ErrEscrowKeySignature
	}
	var p EscrowKeyPayload
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return p, nil, ErrEscrowKeyMalformed
	}
	pub, err := base64.StdEncoding.DecodeString(p.PublicKey)
	switch {
	case p.V != EscrowKeyPayloadVersion || p.KeyVersion < 1 || err != nil || len(pub) != 32 ||
		!validEscrowID(p.KeyID) || !validEscrowID(p.OrgID) || p.ExpiresAt.IsZero():
		return p, nil, ErrEscrowKeyMalformed
	case p.DeviceID != deviceID:
		return p, nil, ErrEscrowKeyDevice
	case !now.Before(p.ExpiresAt):
		return p, nil, ErrEscrowKeyExpired
	}
	return p, pub, nil
}

var escrowIDPattern = regexp.MustCompile(`^[A-Za-z0-9{}\-_.:\\? /]{1,128}$`)

func validEscrowID(s string) bool { return escrowIDPattern.MatchString(s) }

// EscrowProtector is a BitLocker recovery-password protector. Only its ID is
// reported.
type EscrowProtector struct {
	ID string `json:"id"`
}

// EscrowVolume is a volume the agent found with BitLocker on it.
type EscrowVolume struct {
	// ID is the volume's stable ID (its device ID path).
	ID    string `json:"id"`
	Mount string `json:"mount,omitempty"`
	// Status is BitLocker's conversion status in words: "encrypted",
	// "encrypting", "decrypted", ...
	Status string `json:"status"`
	// Protectors are the volume's numerical-password protectors.
	Protectors []EscrowProtector `json:"protectors"`
}

// EscrowVolumesReport is what the agent sends to PathEscrowVolumes.
type EscrowVolumesReport struct {
	Volumes []EscrowVolume `json:"volumes"`
}

// Check refuses a report that is oversized or has an ID that is not one.
func (r EscrowVolumesReport) Check() error {
	if len(r.Volumes) > MaxEscrowVolumes {
		return errors.New("too many volumes")
	}
	for _, v := range r.Volumes {
		if !validEscrowID(v.ID) || len(v.Mount) > 16 || len(v.Status) > 32 || len(v.Protectors) > MaxEscrowProtectors {
			return errors.New("a volume is not valid")
		}
		for _, p := range v.Protectors {
			if !validEscrowID(p.ID) {
				return errors.New("a protector is not valid")
			}
		}
	}
	return nil
}

// EscrowNeed names a protector whose escrow the server wants (again).
type EscrowNeed struct {
	VolumeID    string `json:"volumeId"`
	ProtectorID string `json:"protectorId"`
}

// EscrowVolumesAnswer is the server's answer: what to escrow now.
type EscrowVolumesAnswer struct {
	Need []EscrowNeed `json:"need"`
}

// EscrowRecord is one sealed recovery key (PathEscrow).
type EscrowRecord struct {
	VolumeID    string `json:"volumeId"`
	ProtectorID string `json:"protectorId"`
	Kind        string `json:"kind"`
	// KeyID is the escrow key it was sealed to.
	KeyID string `json:"keyId"`
	// Enc is the HPKE encapsulated key and Ciphertext the sealed secret,
	// both base64 (standard, padded).
	Enc        string `json:"enc"`
	Ciphertext string `json:"ciphertext"`
	// Fingerprint is the 16-byte fingerprint, hex.
	Fingerprint string `json:"fingerprint"`
}

// Check refuses a record with a field that is not one.
func (r EscrowRecord) Check() error {
	if !validEscrowID(r.VolumeID) || !validEscrowID(r.ProtectorID) || !validEscrowID(r.KeyID) || r.Kind != EscrowBitLocker {
		return errors.New("an identifier is not valid")
	}
	enc, err := base64.StdEncoding.DecodeString(r.Enc)
	if err != nil || len(enc) != 32 {
		return errors.New("enc is not valid")
	}
	ct, err := base64.StdEncoding.DecodeString(r.Ciphertext)
	if err != nil || len(ct) == 0 || len(ct) > 512 {
		return errors.New("ciphertext is not valid")
	}
	if len(r.Fingerprint) != 32 {
		return errors.New("fingerprint is not valid")
	}
	return nil
}

// EscrowAnswer is the server's answer to an upload.
type EscrowAnswer struct {
	// State is the record's state: pending, verified, stale or conflict.
	State string `json:"state"`
	// Again says the agent must read, seal and send the record again: it did
	// not match what the keystore computed.
	Again bool `json:"again,omitempty"`
}
