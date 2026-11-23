package agentproto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"
)

// Recovery (ADR-0069, Part R). The agent tells the server in each heartbeat
// what state MeshAgent is in, and the server tells it in a heartbeat answer
// to restart MeshAgent or repair it. An instruction names a target and a
// step from the fixed lists below, never a command; like an update it is
// signed with the job key and bound to the device. The agent reports how the
// step went in its next heartbeats.

// Repair targets and steps (ADR-0069, "Part R").
const (
	TargetEasyRMMAgent   = "easyrmm-agent"
	TargetMeshAgent      = "meshagent"
	TargetEasyPatchAgent = "easypatch-agent"

	// StepRestart restarts the target's service, or its child process.
	StepRestart = "restart"
	// StepRepair puts the target's program and service back in place without
	// losing its identity.
	StepRepair = "repair"
)

// ValidTarget reports whether t is a repair target.
func ValidTarget(t string) bool {
	return t == TargetEasyRMMAgent || t == TargetMeshAgent || t == TargetEasyPatchAgent
}

// ValidStep reports whether s is a repair step.
func ValidStep(s string) bool { return s == StepRestart || s == StepRepair }

// RepairPayloadVersion is the version of RepairPayload.
const RepairPayloadVersion = 1

// MaxRepairError bounds the error an agent reports for a repair step.
const MaxRepairError = 500

// MaxMeshAgentError bounds the last error reported with MeshAgent's state.
const MaxMeshAgentError = 300

// MaxMeshHost bounds the host reported with MeshAgent's state.
const MaxMeshHost = 255

// RepairReported is how long an agent keeps reporting a step's outcome in
// its heartbeats, unless another step starts first.
const RepairReported = time.Hour

// MeshAgentState is what an agent reports about MeshAgent with each
// heartbeat. Its node id is in the facts.
type MeshAgentState struct {
	// Installed: MeshAgent's program and settings are in place.
	Installed bool `json:"installed"`
	// Running: its service, or the child process the agent supervises, runs.
	Running bool `json:"running"`
	// Host is the MeshCentral host (and port) its settings name, "" when
	// they name none or cannot be read.
	Host string `json:"host,omitempty"`
	// Error is the last error the agent read: a failed start, restart or
	// repair.
	Error string `json:"error,omitempty"`
}

// MeshServerHost returns the host (with the port, when the settings give
// one) of the MeshServer line in MeshAgent's settings (.msh), lowercase, or
// "" when there is none. The settings the server hands out and the ones on
// the device are compared by this.
func MeshServerHost(settings []byte) string {
	for line := range strings.Lines(string(settings)) {
		k, v, ok := strings.Cut(line, "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(k), "MeshServer") {
			continue
		}
		u, err := url.Parse(strings.TrimSpace(v))
		if err != nil || u.Host == "" {
			return ""
		}
		return strings.ToLower(u.Host)
	}
	return ""
}

// RepairPayload tells one device's agent to carry out one repair step.
type RepairPayload struct {
	V int `json:"v"`
	// ID names this step; the agent reports its outcome against it.
	ID        string    `json:"id"`
	DeviceID  string    `json:"deviceId"`
	Target    string    `json:"target"`
	Step      string    `json:"step"`
	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// SignedRepair is a RepairPayload with the server's signature.
type SignedRepair struct {
	// Payload is the RepairPayload JSON, base64 (standard, padded).
	Payload string `json:"payload"`
	// Signature is the Ed25519 signature, base64 (standard, padded).
	Signature string `json:"signature"`
}

// RepairReport is the outcome of one repair step, sent with heartbeats.
type RepairReport struct {
	// ID is the step's, from the instruction.
	ID string `json:"id"`
	OK bool   `json:"ok"`
	// Error says what failed, never with secrets.
	Error string `json:"error,omitempty"`
}

const repairSigContext = "EASYRMM-REPAIR-SIG-V1\n"

// Errors from VerifyRepair.
var (
	ErrRepairSignature = errors.New("agentproto: the repair instruction's signature does not verify with the server key this agent trusts")
	ErrRepairMalformed = errors.New("agentproto: the repair instruction is malformed")
	ErrRepairDevice    = errors.New("agentproto: the repair instruction is for another device")
	ErrRepairExpired   = errors.New("agentproto: the repair instruction has expired")
)

// SignRepair signs a repair instruction with the server's job key.
func SignRepair(key ed25519.PrivateKey, p RepairPayload) (SignedRepair, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return SignedRepair{}, err
	}
	sig := ed25519.Sign(key, append([]byte(repairSigContext), b...))
	return SignedRepair{Payload: base64.StdEncoding.EncodeToString(b), Signature: base64.StdEncoding.EncodeToString(sig)}, nil
}

// VerifyRepair checks a signed repair instruction with the pinned server key
// and returns its payload. It refuses instructions for other devices,
// expired ones, and any whose target or step is not on the fixed lists.
func VerifyRepair(key ed25519.PublicKey, s SignedRepair, deviceID string, now time.Time) (RepairPayload, error) {
	b, err := base64.StdEncoding.DecodeString(s.Payload)
	if err != nil {
		return RepairPayload{}, ErrRepairMalformed
	}
	sig, err := base64.StdEncoding.DecodeString(s.Signature)
	if err != nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, append([]byte(repairSigContext), b...), sig) {
		return RepairPayload{}, ErrRepairSignature
	}
	var p RepairPayload
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return RepairPayload{}, ErrRepairMalformed
	}
	switch {
	case p.V != RepairPayloadVersion || p.ID == "" || len(p.ID) > 64 || !ValidTarget(p.Target) || !ValidStep(p.Step) || p.ExpiresAt.IsZero():
		return p, ErrRepairMalformed
	case p.DeviceID != deviceID:
		return p, ErrRepairDevice
	case !now.Before(p.ExpiresAt):
		return p, ErrRepairExpired
	}
	return p, nil
}
