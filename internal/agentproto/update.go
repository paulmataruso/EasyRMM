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

// Agent self-update (ADR-0027). The server tells an agent in a heartbeat
// answer to replace itself with one of the builds it serves; the
// instruction is signed with the job key, so only the server the agent
// pinned can start an update, and it binds the build's size and SHA-256.

// PathAgentDownload is where the server serves its agent builds, by file
// name, and SHA256SUMS.
func PathAgentDownload(file string) string { return "/api/agent/v1/download/" + file }

// UpdatePayloadVersion is the version of UpdatePayload.
const UpdatePayloadVersion = 1

// MaxAgentBuild bounds the size of an agent build.
const MaxAgentBuild = 256 << 20

// MaxUpdateError bounds the error an agent reports for a failed update.
const MaxUpdateError = 500

// UpdatePayload tells one device's agent to replace itself with a build.
type UpdatePayload struct {
	V int `json:"v"`
	// ID names this attempt; the agent reports a failure against it.
	ID       string `json:"id"`
	DeviceID string `json:"deviceId"`
	// File is the build's name at PathAgentDownload.
	File   string `json:"file"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	// Version is the build's version as its "version" command prints it,
	// empty when the server does not know it.
	Version   string    `json:"version"`
	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// SignedUpdate is an UpdatePayload with the server's signature.
type SignedUpdate struct {
	// Payload is the UpdatePayload JSON, base64 (standard, padded).
	Payload string `json:"payload"`
	// Signature is the Ed25519 signature, base64 (standard, padded).
	Signature string `json:"signature"`
}

// UpdateReport tells the server that an update attempt failed. The agent
// sends it with each heartbeat until the server sends another attempt.
type UpdateReport struct {
	ID    string `json:"id"`
	Error string `json:"error"`
}

const updateSigContext = "EASYRMM-UPDATE-SIG-V1\n"

// Errors from VerifyUpdate.
var (
	ErrUpdateSignature = errors.New("agentproto: the update's signature does not verify with the server key this agent trusts")
	ErrUpdateMalformed = errors.New("agentproto: the update is malformed")
	ErrUpdateDevice    = errors.New("agentproto: the update is for another device")
	ErrUpdateExpired   = errors.New("agentproto: the update has expired")
)

var (
	buildFile  = regexp.MustCompile(`^easyrmm-agent-(linux|windows)-(amd64|arm64|386|arm)(\.exe)?$`)
	sha256Hex  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	versionStr = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._+~-]{0,63}$`)
)

// BuildFile parses an agent build's file name, as the server serves it:
// easyrmm-agent-<os>-<arch>, with .exe for Windows.
func BuildFile(name string) (goos, goarch string, ok bool) {
	m := buildFile.FindStringSubmatch(name)
	if m == nil || (m[1] == "windows") != (m[3] == ".exe") {
		return "", "", false
	}
	return m[1], m[2], true
}

// ValidSHA256 reports whether s is a SHA-256 in lowercase hex.
func ValidSHA256(s string) bool { return sha256Hex.MatchString(s) }

// ValidVersion reports whether s can be an agent version: what "git
// describe" prints, a release number or "dev".
func ValidVersion(s string) bool { return versionStr.MatchString(s) }

// SignUpdate signs an update with the server's job key.
func SignUpdate(key ed25519.PrivateKey, p UpdatePayload) (SignedUpdate, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return SignedUpdate{}, err
	}
	sig := ed25519.Sign(key, append([]byte(updateSigContext), b...))
	return SignedUpdate{Payload: base64.StdEncoding.EncodeToString(b), Signature: base64.StdEncoding.EncodeToString(sig)}, nil
}

// VerifyUpdate checks a signed update with the pinned server key and
// returns its payload. It refuses updates for other devices, expired ones
// and ones that do not name a build properly.
func VerifyUpdate[K KeyArg](key K, u SignedUpdate, deviceID string, now time.Time) (UpdatePayload, error) {
	b, err := base64.StdEncoding.DecodeString(u.Payload)
	if err != nil {
		return UpdatePayload{}, ErrUpdateMalformed
	}
	sig, err := base64.StdEncoding.DecodeString(u.Signature)
	if err != nil || !keysOf(key).verify(append([]byte(updateSigContext), b...), sig) {
		return UpdatePayload{}, ErrUpdateSignature
	}
	var p UpdatePayload
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return UpdatePayload{}, ErrUpdateMalformed
	}
	_, _, okFile := BuildFile(p.File)
	switch {
	case p.V != UpdatePayloadVersion || p.ID == "" || len(p.ID) > 64 || !okFile || p.Size < 1 || p.Size > MaxAgentBuild ||
		!ValidSHA256(p.SHA256) || (p.Version != "" && !ValidVersion(p.Version)):
		return p, ErrUpdateMalformed
	case p.DeviceID != deviceID:
		return p, ErrUpdateDevice
	case !now.Before(p.ExpiresAt):
		return p, ErrUpdateExpired
	}
	return p, nil
}
