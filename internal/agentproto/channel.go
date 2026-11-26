package agentproto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"time"
)

// The agent's WebSocket channel, channel.v1 (ADR-0059). This file is the
// contract both sides build on: the route, the envelope, the messages, the
// signing domains and the limits. It reads no instruction and knows nothing
// of how the server or the agent uses it.

// PathChannel is the channel's route: an HTTP/1.1 upgrade to a WebSocket,
// signed like every agent request (a GET with an empty body).
const PathChannel = "/api/agent/v1/channel"

// ChannelSubprotocol is the WebSocket subprotocol of channel.v1. The server
// refuses an upgrade that does not offer it.
const ChannelSubprotocol = "easyrmm-agent.v1"

// ChannelCapability is what an agent lists in HeartbeatRequest.Channel, and
// FeatureChannel what a server lists in HeartbeatResponse.Features and in
// its hello.
const (
	ChannelCapability = "v1"
	FeatureChannel    = "channel"
)

// Signing domains. The server signs every frame with the job key; the agent
// signs the frames it sends with the device key.
const (
	ChannelServerContext = "EASYRMM-CHANNEL-SIG-V1\n"
	ChannelAgentContext  = "EASYRMM-CHANNEL-AGENT-V1\n"
)

// ChannelVersion is the "v" of every message.
const ChannelVersion = 1

// Message types. Server to agent: hello, tick, wake, closing, jobs, logs,
// repair, settings, logs.ack. Agent to server: logs.batch, and nothing else.
const (
	TypeHello     = "hello"
	TypeTick      = "tick"
	TypeWake      = "wake"
	TypeClosing   = "closing"
	TypeJobs      = "jobs"
	TypeLogs      = "logs"
	TypeRepair    = "repair"
	TypeSettings  = "settings"
	TypeLogsAck   = "logs.ack"
	TypeLogsBatch = "logs.batch"
)

// Values of ChannelMessage.What and ChannelMessage.Reason.
const (
	WakeCheckin = "checkin"
	WakeJobs    = "jobs"

	ClosingRestart  = "restart"
	ClosingRefresh  = "refresh"
	ClosingReplaced = "replaced"
	ClosingRemoved  = "removed"
)

// Limits of the channel (ADR-0059, "Reconnects, backoff and limits").
const (
	// MaxChannelFrame is what the agent accepts for the types without a
	// bigger allowance; MaxChannelBigFrame is for jobs, repair and settings.
	MaxChannelFrame    = 16 << 10
	MaxChannelBigFrame = 1 << 20
	// MaxChannelAgentFrame is what the server reads from the agent.
	MaxChannelAgentFrame = 64 << 10

	// ChannelTickEvery is the server's keepalive; ChannelIdle is how long
	// either side waits to hear from the other before it closes.
	ChannelTickEvery = 30 * time.Second
	ChannelIdle      = 75 * time.Second
	// ChannelHelloWithin is how long the agent waits for the hello after the
	// 101; ChannelWriteWithin bounds a write of the server's.
	ChannelHelloWithin = 10 * time.Second
	ChannelWriteWithin = 10 * time.Second
	// ChannelMaxAge is how long a connection lives before the server sends
	// closing (refresh).
	ChannelMaxAge = 12 * time.Hour

	// Frames per second, and bursts, in each direction and per device.
	ChannelServerFrameRate  = 20
	ChannelServerFrameBurst = 50
	ChannelAgentFrameRate   = 1
	ChannelAgentFrameBurst  = 3

	// A device's upgrades: one every ChannelUpgradeEvery after a burst of
	// ChannelUpgradeBurst. The server takes ChannelUpgradesPerSecond
	// verified upgrades a second and ChannelConnectionsMax connections.
	ChannelUpgradeEvery      = 10 * time.Second
	ChannelUpgradeBurst      = 6
	ChannelUpgradesPerSecond = 200
	ChannelConnectionsMax    = 10_000

	// ChannelContradictAfter is how long after an upgrade request a
	// heartbeat that does not name the connection contradicts it, on the
	// agent's own clock.
	ChannelContradictAfter = 60 * time.Second
)

// ChannelEnvelope is a frame on the wire: a text frame of JSON. Payload is
// the message's JSON, base64 (standard, padded); Signature is the Ed25519
// signature, base64.
type ChannelEnvelope struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// ChannelMessage is the payload of a server frame. Which fields are set
// depends on Type.
type ChannelMessage struct {
	V        int       `json:"v"`
	Type     string    `json:"type"`
	DeviceID string    `json:"deviceId"`
	ConnID   string    `json:"connId"`
	Seq      uint64    `json:"seq"`
	SentAt   time.Time `json:"sentAt"`

	// hello
	Nonce    string   `json:"nonce,omitempty"`
	Features []string `json:"features,omitempty"`
	Instance string   `json:"instance,omitempty"`

	// wake
	What string `json:"what,omitempty"`
	// wake, closing
	Reason string `json:"reason,omitempty"`
	// closing
	ReconnectWithin int `json:"reconnectWithin,omitempty"`

	// jobs, logs, repair, settings, logs.ack
	Jobs     *PollResponse    `json:"jobs,omitempty"`
	Logs     *LogInstructions `json:"logs,omitempty"`
	Repair   *SignedRepair    `json:"repair,omitempty"`
	Settings *ChannelSettings `json:"settings,omitempty"`
	Ack      *LogAck          `json:"ack,omitempty"`
}

// ChannelSettings is what a settings push carries: the fields of the
// heartbeat answer the agent applies.
type ChannelSettings struct {
	HeartbeatSeconds int           `json:"heartbeatSeconds,omitempty"`
	MeshAgent        MeshAgentInfo `json:"meshAgent"`
}

// ChannelAgentFrame is the payload of an agent frame. Only TypeLogsBatch
// exists. ConnID is the connection's id from the hello, Seq counts the
// agent's frames from 1.
type ChannelAgentFrame struct {
	V      int       `json:"v"`
	Type   string    `json:"type"`
	ConnID string    `json:"connId"`
	Seq    uint64    `json:"seq"`
	Batch  *LogBatch `json:"batch,omitempty"`
}

// ChannelReport is what an agent says of the connection it holds, in its
// signed heartbeat (ADR-0059, "Presence confirmed by the heartbeat").
type ChannelReport struct {
	ConnID string `json:"connId"`
	// Since is when the connection began, in Unix seconds on the agent's
	// clock.
	Since int64 `json:"since"`
	// LastReplayed is when, in Unix seconds on the agent's clock, an upgrade
	// of the agent's was answered 401 replayed: someone else used its
	// request. Zero for never. A report with no ConnID says only this.
	LastReplayed int64 `json:"lastReplayed,omitempty"`
}

// Errors from the channel's verification.
var (
	ErrChannelFrame     = errors.New("agentproto: the channel frame is malformed")
	ErrChannelSignature = errors.New("agentproto: the channel frame's signature does not verify")
	ErrChannelBinding   = errors.New("agentproto: the channel frame names another device or connection, or breaks the sequence")
)

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// SignChannelMessage signs a server message with the job key and returns
// the frame to send.
func SignChannelMessage(key ed25519.PrivateKey, m ChannelMessage) ([]byte, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(key, append([]byte(ChannelServerContext), b...))
	return json.Marshal(ChannelEnvelope{Payload: b64(b), Signature: b64(sig)})
}

// VerifyChannelMessage checks a server frame's size against max and its
// signature against key, and returns the message. It does not check that
// the message is the one expected: see ChannelMessage.Check.
func VerifyChannelMessage(key ed25519.PublicKey, frame []byte, max int) (ChannelMessage, error) {
	var m ChannelMessage
	payload, sig, err := openEnvelope(frame, max)
	if err != nil {
		return m, err
	}
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, append([]byte(ChannelServerContext), payload...), sig) {
		return m, ErrChannelSignature
	}
	if err := json.Unmarshal(payload, &m); err != nil || m.V != ChannelVersion {
		return ChannelMessage{}, ErrChannelFrame
	}
	return m, nil
}

// Check says whether m is for this device and connection and is the next in
// the sequence (wantSeq starts at 1).
func (m ChannelMessage) Check(deviceID, connID string, wantSeq uint64) error {
	if m.DeviceID != deviceID || m.ConnID != connID || m.Seq != wantSeq {
		return ErrChannelBinding
	}
	return nil
}

func openEnvelope(frame []byte, max int) (payload, sig []byte, err error) {
	if len(frame) > max {
		return nil, nil, ErrChannelFrame
	}
	var e ChannelEnvelope
	if json.Unmarshal(frame, &e) != nil {
		return nil, nil, ErrChannelFrame
	}
	if payload, err = base64.StdEncoding.DecodeString(e.Payload); err != nil {
		return nil, nil, ErrChannelFrame
	}
	if sig, err = base64.StdEncoding.DecodeString(e.Signature); err != nil {
		return nil, nil, ErrChannelFrame
	}
	return payload, sig, nil
}

// agentMessage is what the device key signs: the domain, the connection id,
// the sequence number and the payload, so a frame cannot be moved to
// another connection or position.
func agentMessage(connID string, seq uint64, payload []byte) []byte {
	m := append([]byte(ChannelAgentContext), connID...)
	m = append(m, '\n')
	m = strconv.AppendUint(m, seq, 10)
	m = append(m, '\n')
	return append(m, payload...)
}

// SignChannelAgentFrame signs a frame the agent sends. f.V is set to
// ChannelVersion.
func SignChannelAgentFrame(key ed25519.PrivateKey, f ChannelAgentFrame) ([]byte, error) {
	f.V = ChannelVersion
	b, err := json.Marshal(f)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(key, agentMessage(f.ConnID, f.Seq, b))
	return json.Marshal(ChannelEnvelope{Payload: b64(b), Signature: b64(sig)})
}

// VerifyChannelAgentFrame checks an agent frame's size against
// MaxChannelAgentFrame and its signature against the device's key, and
// returns the frame. The caller checks its connection id and sequence.
func VerifyChannelAgentFrame(key ed25519.PublicKey, frame []byte) (ChannelAgentFrame, error) {
	var f ChannelAgentFrame
	payload, sig, err := openEnvelope(frame, MaxChannelAgentFrame)
	if err != nil {
		return f, err
	}
	if err := json.Unmarshal(payload, &f); err != nil || f.V != ChannelVersion {
		return ChannelAgentFrame{}, ErrChannelFrame
	}
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, agentMessage(f.ConnID, f.Seq, payload), sig) {
		return ChannelAgentFrame{}, ErrChannelSignature
	}
	return f, nil
}
