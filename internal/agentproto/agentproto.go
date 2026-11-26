// Package agentproto is the wire protocol between the EasyRMM agent and the
// server (ADR-0009, ADR-0015, ADR-0017): enrollment messages, heartbeats,
// the Ed25519 request signatures that authenticate an enrolled device, and
// signed jobs.
//
// It is shared by the server and the agent so both sides build the signed
// string the same way.
package agentproto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Paths of the agent API, relative to the server's public URL.
const (
	PathEnroll       = "/api/agent/v1/enroll"
	PathHeartbeat    = "/api/agent/v1/heartbeat"
	PathMeshAgent    = "/api/agent/v1/meshagent/binary"
	PathMeshSettings = "/api/agent/v1/meshagent/settings"
	// PathCA serves the server's own certificate authority, for servers
	// reached by IP address (ADR-0016).
	PathCA = "/api/agent/v1/ca.pem"
	// PathCACert serves the same certificate in DER as a .crt file, which
	// Windows and macOS install with a double click.
	PathCACert = "/api/agent/v1/easyrmm-ca.crt"
	PathPrefix = "/api/agent/"
)

// Scheme is the Authorization scheme of signed requests.
const Scheme = "EasyRMM-Agent"

// Limits shared by both sides.
const (
	// MaxSkew is how far a request's timestamp may be from the server's clock.
	MaxSkew = 5 * time.Minute
	// MaxBody is the largest request body the server reads.
	MaxBody = 1 << 20
	// NonceBytes is the size of a request nonce before encoding.
	NonceBytes = 18
	// TokenPrefix starts every deployment token.
	TokenPrefix = "ert_"
)

const sigContext = "EASYRMM-AGENT-SIG-V1"

// Facts describe a device. The agent sends them at enrollment and with every
// heartbeat.
type Facts struct {
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`       // human description, "Ubuntu 24.04.3 LTS"
	Platform     string `json:"platform"` // windows, linux, macos
	Arch         string `json:"arch"`     // GOARCH of the agent
	AgentVersion string `json:"agentVersion"`
	// AgentSHA256 is the SHA-256 of the agent's executable, in lowercase
	// hex. Agents that can update themselves report it (ADR-0027); the
	// server compares it with the build it serves.
	AgentSHA256 string `json:"agentSha256,omitempty"`
	// MeshNodeID is MeshAgent's node identifier as `meshagent -nodeid`
	// prints it (96 hex digits), once MeshAgent is installed.
	MeshNodeID string `json:"meshNodeId,omitempty"`
	// MeshSettingsSHA256 is the SHA-256 of the MeshAgent settings the agent
	// last applied from the server, in lowercase hex (ADR-0069).
	MeshSettingsSHA256 string `json:"meshSettingsSha256,omitempty"`
	// Roles are the Windows roles and features detected (ADR-0073). Nil
	// (absent or null) means the agent could not or did not detect them, which
	// the server reads as unknown; an empty list means none were found.
	Roles []Role `json:"roles"`
}

// EnrollRequest exchanges a deployment token for a device identity.
type EnrollRequest struct {
	Token string `json:"token"`
	// PublicKey is the device's Ed25519 public key, base64 (standard, padded).
	PublicKey string `json:"publicKey"`
	Facts     Facts  `json:"facts"`
}

// EnrollResponse identifies the new device, or says that it waits for
// approval.
type EnrollResponse struct {
	// DeviceID is empty while the device waits for approval.
	DeviceID         string `json:"deviceId"`
	HeartbeatSeconds int    `json:"heartbeatSeconds"`
	// MeshAgent says whether the agent should install MeshAgent now.
	MeshAgent MeshAgentInfo `json:"meshAgent"`
	// JobKey is the server's job-signing public key (EncodeKey), which the
	// agent pins (ADR-0017).
	JobKey string `json:"jobKey,omitempty"`
	// Pending is set, with the server answering 202 Accepted, when the
	// token was an approval token and nobody has approved the device yet
	// (ADR-0024). The agent asks again with the same token and key.
	Pending *EnrollPending `json:"pending,omitempty"`
}

// EnrollPending describes a device waiting for approval.
type EnrollPending struct {
	// Code is the device's code, the same in the console (DeviceCode).
	Code string `json:"code"`
	// RetrySeconds is how long to wait before asking again. The server
	// holds each request open for up to ApprovalWait first.
	RetrySeconds int `json:"retrySeconds"`
}

// ApprovalWait is how long the server holds an enrollment that waits for
// approval open before answering that it still waits.
const ApprovalWait = 25 * time.Second

// CodeEnrollmentRejected is the error code of an enrollment that was
// rejected in the console. The agent stops asking.
const CodeEnrollmentRejected = "enrollment_rejected"

// DeviceCode is the short code that tells a device waiting for approval
// apart from others with the same name: the first 40 bits of the SHA-256 of
// its public key in base32, as "ABCD-EFGH". The agent prints it, the
// console shows it.
func DeviceCode(publicKey []byte) string {
	sum := sha256.Sum256(publicKey)
	s := base32.StdEncoding.EncodeToString(sum[:5])
	return s[:4] + "-" + s[4:]
}

// HeartbeatRequest reports that the agent is alive.
type HeartbeatRequest struct {
	Facts Facts `json:"facts"`
	// Metrics are the device's current measurements (ADR-0018); older
	// agents send none.
	Metrics *Metrics `json:"metrics,omitempty"`
	// Update reports a failed update attempt (ADR-0027).
	Update *UpdateReport `json:"update,omitempty"`
	// EasyPatch says the agent can install the EasyPatch agent, and how its
	// last install went (ADR-0031). Older agents send none.
	EasyPatch *EasyPatchInstallStatus `json:"easyPatch,omitempty"`
	// MeshAgent is MeshAgent's state on the device (ADR-0069); older agents
	// send none, and the server ignores the field at protocol level 2.
	MeshAgent *MeshAgentState `json:"meshAgent,omitempty"`
	// Repair is the outcome of the last repair step the agent carried out
	// (ADR-0069), sent until RepairReported after it ended.
	Repair *RepairReport `json:"repair,omitempty"`
	// Defender is the state of the agent's Microsoft Defender exclusions
	// (ADR-0070); Windows agents send it only where the server's last
	// answer allowed it.
	Defender *DefenderReport `json:"defender,omitempty"`
	// InstalledFiles are the hashes of what is installed on the device
	// (ADR-0070), sent when something changed, and once a day.
	InstalledFiles *InstalledFiles `json:"installedFiles,omitempty"`
	// Channel lists the channel versions the agent speaks, ["v1"]
	// (ADR-0059). Older servers ignore it.
	Channel []string `json:"channel,omitempty"`
	// Transport names the connection the agent holds, which confirms it
	// (ADR-0059). An agent without one sends none.
	Transport *ChannelReport `json:"transport,omitempty"`
}

// The agent keeps the server's heartbeat interval within these bounds, so
// that an answer changed on the way cannot silence it.
const (
	MinHeartbeatSeconds = 10
	MaxHeartbeatSeconds = 600
)

// Protocol is the level of the agent protocol this server speaks (ADR-0009,
// "Evolving the protocol"). At level 2 the server ignores request fields it
// does not know. A server whose heartbeat answer has no level is level 1 and
// refuses them with 400, so an agent sends a request field added after
// level 2 only while its last heartbeat answer came from a server of level 2
// or higher.
//
// Level 3 adds job params (ADR-0073): JobPayload.Params, signed with the
// script's hash, for an agent whose poll lists CapJobParams.
const Protocol = 3

// HeartbeatResponse carries the server's current instructions.
type HeartbeatResponse struct {
	// Protocol is the server's protocol level: Protocol, or 0 from a server
	// older than levels (level 1).
	Protocol         int           `json:"protocol,omitempty"`
	HeartbeatSeconds int           `json:"heartbeatSeconds"`
	MeshAgent        MeshAgentInfo `json:"meshAgent"`
	// JobKey is the server's job-signing public key, as in EnrollResponse.
	JobKey string `json:"jobKey,omitempty"`
	// InventoryHash is the hash of the inventory the server holds for the
	// device, empty when it holds none. The agent uploads its inventory
	// when its own hash differs (ADR-0018).
	InventoryHash string `json:"inventoryHash"`
	// Update tells the agent to replace itself with another build
	// (ADR-0027).
	Update *SignedUpdate `json:"update,omitempty"`
	// EasyPatchInstall tells the agent to install the EasyPatch agent
	// (ADR-0031).
	EasyPatchInstall *SignedEasyPatchInstall `json:"easyPatchInstall,omitempty"`
	// Uninstall tells the agent to uninstall itself (ADR-0050). An answer
	// that carries it carries no other instruction.
	Uninstall *SignedUninstall `json:"uninstall,omitempty"`
	// Repair tells the agent to carry out a repair step (ADR-0069).
	Repair *SignedRepair `json:"repair,omitempty"`
	// Logs says how the agent logs: verbose, and whether someone watches
	// (ADR-0069).
	Logs *LogInstructions `json:"logs,omitempty"`
	// Defender says whether the agent may manage Defender exclusions and
	// report installed-file hashes on this device (ADR-0070). Absent from
	// older servers, which means no.
	Defender *DefenderPolicy `json:"defender,omitempty"`
	// Features lists what this server offers beyond the protocol level, such
	// as "channel" (ADR-0059). An agent ignores names it does not know.
	Features []string `json:"features,omitempty"`
	// Instance is the ID this server process drew at its start, so that an
	// agent can tell a restarted server from one still serving.
	Instance string `json:"instance,omitempty"`
	// JobsWaiting says that work is waiting that the channel did not carry,
	// such as a jobs frame over its cap: the agent makes an ordinary poll.
	JobsWaiting bool `json:"jobsWaiting,omitempty"`
	// RescanRoles asks the agent to detect its roles again at once
	// (ADR-0073).
	RescanRoles bool `json:"rescanRoles,omitempty"`
}

// MeshAgentInfo tells the agent about remote access.
type MeshAgentInfo struct {
	// Available is false when the server runs without remote access, or
	// MeshCentral has no device group for the device's site yet.
	Available bool `json:"available"`
	// SettingsSHA256 is set while the device's site has changed: the
	// SHA-256 of the settings for its new site's device group. An agent
	// whose applied settings differ fetches them (PathMeshSettings, signed
	// like every download), rewrites MeshAgent's settings and restarts it
	// (ADR-0069).
	SettingsSHA256 string `json:"settingsSha256,omitempty"`
}

// MeshArch is MeshCentral's agent identifier for a platform, or 0 when it has
// none. It selects the binary /meshagents serves.
func MeshArch(goos, goarch string) int {
	switch goos + "/" + goarch {
	case "windows/386":
		return 3
	case "windows/amd64":
		return 4
	case "windows/arm64":
		return 43
	case "linux/386":
		return 5
	case "linux/amd64":
		return 6
	case "linux/arm":
		return 25 // armhf
	case "linux/arm64":
		return 26
	}
	return 0
}

// MeshNodeKey converts `meshagent -nodeid` output into MeshCentral's node
// identifier (node//<base64 with @ and $>).
func MeshNodeKey(hexID string) (string, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(hexID))
	if err != nil || len(raw) != 48 {
		return "", errors.New("agentproto: a MeshAgent node id is 96 hex digits")
	}
	b := base64.StdEncoding.EncodeToString(raw)
	return "node//" + strings.NewReplacer("+", "@", "/", "$").Replace(b), nil
}

// Auth is a parsed Authorization header.
type Auth struct {
	Device    string
	Timestamp int64
	Nonce     string
	Signature []byte
}

// ErrMalformed reports an Authorization header that cannot be parsed.
var ErrMalformed = errors.New("agentproto: malformed authorization")

// message is the byte string a device signs.
func message(method, target string, ts int64, nonce string, body []byte) []byte {
	sum := sha256.Sum256(body)
	return []byte(strings.Join([]string{
		sigContext, strings.ToUpper(method), target, strconv.FormatInt(ts, 10), nonce, hex.EncodeToString(sum[:]),
	}, "\n"))
}

// Sign returns the Authorization header for a request. target is the
// request's path and query exactly as sent ("/api/agent/v1/heartbeat").
func Sign(key ed25519.PrivateKey, device, method, target string, body []byte, now time.Time) (string, error) {
	n := make([]byte, NonceBytes)
	if _, err := rand.Read(n); err != nil {
		return "", fmt.Errorf("agentproto: nonce: %w", err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(n)
	ts := now.Unix()
	sig := ed25519.Sign(key, message(method, target, ts, nonce, body))
	return fmt.Sprintf("%s device=%s, ts=%d, nonce=%s, sig=%s", Scheme, device, ts, nonce, base64.RawURLEncoding.EncodeToString(sig)), nil
}

// Parse reads an Authorization header.
func Parse(header string) (Auth, error) {
	rest, ok := strings.CutPrefix(header, Scheme+" ")
	if !ok {
		return Auth{}, ErrMalformed
	}
	var a Auth
	seen := map[string]bool{}
	for part := range strings.SplitSeq(rest, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || seen[k] || v == "" {
			return Auth{}, ErrMalformed
		}
		seen[k] = true
		switch k {
		case "device":
			a.Device = v
		case "ts":
			ts, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return Auth{}, ErrMalformed
			}
			a.Timestamp = ts
		case "nonce":
			raw, err := base64.RawURLEncoding.DecodeString(v)
			if err != nil || len(raw) != NonceBytes {
				return Auth{}, ErrMalformed
			}
			a.Nonce = v
		case "sig":
			sig, err := base64.RawURLEncoding.DecodeString(v)
			if err != nil || len(sig) != ed25519.SignatureSize {
				return Auth{}, ErrMalformed
			}
			a.Signature = sig
		default:
			return Auth{}, ErrMalformed
		}
	}
	if len(seen) != 4 {
		return Auth{}, ErrMalformed
	}
	return a, nil
}

// Verify checks a's signature over the request with the device's key.
func (a Auth) Verify(key ed25519.PublicKey, method, target string, body []byte) bool {
	return len(key) == ed25519.PublicKeySize && ed25519.Verify(key, message(method, target, a.Timestamp, a.Nonce, body), a.Signature)
}

// Fresh reports whether a's timestamp is within MaxSkew of now.
func (a Auth) Fresh(now time.Time) bool {
	d := now.Sub(time.Unix(a.Timestamp, 0))
	return d < MaxSkew && d > -MaxSkew
}
