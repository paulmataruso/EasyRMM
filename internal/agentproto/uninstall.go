package agentproto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

// Removing a device (ADR-0050). The server tells a device's agent in a
// heartbeat answer to uninstall itself; the instruction is signed with the
// job key, so only the server the agent pinned can remove it. The agent
// uninstalls from outside its own service and reports with its device key
// how that went.

// PathRemoved is where an agent reports that it uninstalled itself, or why
// it could not.
const PathRemoved = "/api/agent/v1/removed"

// UninstallPayloadVersion is the version of UninstallPayload.
const UninstallPayloadVersion = 1

// MaxRemovalError bounds the error an agent reports for a removal.
const MaxRemovalError = 500

// UninstallRunning is how long an agent that started its uninstaller
// ignores the same instruction again: the uninstaller stops the agent long
// before. After that the agent starts it again.
const UninstallRunning = 10 * time.Minute

// UninstallPayload tells one device's agent to uninstall itself.
type UninstallPayload struct {
	V int `json:"v"`
	// ID names the removal; the agent reports against it.
	ID        string    `json:"id"`
	DeviceID  string    `json:"deviceId"`
	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// SignedUninstall is an UninstallPayload with the server's signature.
type SignedUninstall struct {
	// Payload is the UninstallPayload JSON, base64 (standard, padded).
	Payload string `json:"payload"`
	// Signature is the Ed25519 signature, base64 (standard, padded).
	Signature string `json:"signature"`
}

// RemovedReport is what the agent sends to PathRemoved, signed with its
// device key, once it has stopped for good or failed to.
type RemovedReport struct {
	// ID is the removal's, from the instruction.
	ID string `json:"id"`
	// Removed is true once the agent's service is gone: the agent does not
	// run again, whatever else failed.
	Removed bool `json:"removed"`
	// Error says what failed: why the service could not be removed when
	// Removed is false, what was left behind (MeshAgent) when it is true.
	Error string `json:"error"`
}

const uninstallSigContext = "EASYRMM-UNINSTALL-SIG-V1\n"

// Errors from VerifyUninstall.
var (
	ErrUninstallSignature = errors.New("agentproto: the uninstall instruction's signature does not verify with the server key this agent trusts")
	ErrUninstallMalformed = errors.New("agentproto: the uninstall instruction is malformed")
	ErrUninstallDevice    = errors.New("agentproto: the uninstall instruction is for another device")
	ErrUninstallExpired   = errors.New("agentproto: the uninstall instruction has expired")
)

// SignUninstall signs an uninstall instruction with the server's job key.
func SignUninstall(key ed25519.PrivateKey, p UninstallPayload) (SignedUninstall, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return SignedUninstall{}, err
	}
	sig := ed25519.Sign(key, append([]byte(uninstallSigContext), b...))
	return SignedUninstall{Payload: base64.StdEncoding.EncodeToString(b), Signature: base64.StdEncoding.EncodeToString(sig)}, nil
}

// VerifyUninstall checks a signed uninstall instruction with the pinned
// server key and returns its payload. It refuses instructions for other
// devices and expired ones.
func VerifyUninstall(key ed25519.PublicKey, u SignedUninstall, deviceID string, now time.Time) (UninstallPayload, error) {
	b, err := base64.StdEncoding.DecodeString(u.Payload)
	if err != nil {
		return UninstallPayload{}, ErrUninstallMalformed
	}
	sig, err := base64.StdEncoding.DecodeString(u.Signature)
	if err != nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, append([]byte(uninstallSigContext), b...), sig) {
		return UninstallPayload{}, ErrUninstallSignature
	}
	var p UninstallPayload
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return UninstallPayload{}, ErrUninstallMalformed
	}
	switch {
	case p.V != UninstallPayloadVersion || p.ID == "" || len(p.ID) > 64 || p.ExpiresAt.IsZero():
		return p, ErrUninstallMalformed
	case p.DeviceID != deviceID:
		return p, ErrUninstallDevice
	case !now.Before(p.ExpiresAt):
		return p, ErrUninstallExpired
	}
	return p, nil
}
