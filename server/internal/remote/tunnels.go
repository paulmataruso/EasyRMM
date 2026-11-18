package remote

import (
	"context"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// MeshCentral pairs the two ends of a relay by the tunnel id alone, and the
// browser asks for the agent's end over its control channel: a "tunnel"
// message names a device and the relay address the agent is to join. A
// browser holding a grant for one device could therefore open a relay it
// was granted and have another device's agent join it, or name another
// session type in the address. The gateway binds the two ends (security
// review, Phase 9):
//
//   - a tunnel request on the control channel must be for this server's
//     relay, name the same device as the message, and be for a device and
//     session type the EasyRMM session holds a grant on; its tunnel id is
//     then recorded for that session, device and protocol;
//   - a browser's relay connection records its tunnel id the same way, and
//     may not reuse one recorded for another session, device or protocol;
//   - an agent's relay connection that names a device must join a recorded
//     tunnel, for that device and protocol. Relays MeshCentral asks for
//     itself (web RDP, device file downloads) name no device and are
//     reached only through their own checks;
//   - the browser's first relay message, from which MeshAgent takes the
//     session type, must be the protocol the relay was admitted for.

const (
	// tunnelTTL is how long a recorded tunnel waits for its agent; agents
	// join within seconds.
	tunnelTTL = 2 * time.Minute
	// maxTunnelsPerSession bounds the tunnels one session may have waiting.
	maxTunnelsPerSession = 64
)

// tunnelIDPattern is what a tunnel id may look like: MeshCentral's page
// uses base-36 random strings, its server base64 with @ and $.
var tunnelIDPattern = regexp.MustCompile(`^[A-Za-z0-9@$_-]{1,64}$`)

// admittedTunnel is a tunnel a session was allowed to open.
type admittedTunnel struct {
	session uuid.UUID
	node    string
	proto   string
	until   time.Time
}

// admitTunnel records that a session may open tunnel id to a device with a
// relay protocol, or refuses an id already recorded otherwise.
func (g *Gateway) admitTunnel(session uuid.UUID, id, node, proto string) error {
	if !tunnelIDPattern.MatchString(id) {
		return refused("tunnel id %q", short(id))
	}
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	if a, ok := g.admitted[id]; ok {
		if now.Before(a.until) && (a.session != session || a.node != node || a.proto != proto) {
			return refused("tunnel id already in use for another session, device or protocol")
		}
		if a.session == session {
			a.node, a.proto, a.until = node, proto, now.Add(tunnelTTL)
			g.admitted[id] = a
			return nil
		}
		g.forgetTunnel(id, a)
	}
	if g.admittedBy[session] >= maxTunnelsPerSession {
		g.pruneTunnels(now)
		if g.admittedBy[session] >= maxTunnelsPerSession {
			return refused("more than %d tunnels waiting for agents", maxTunnelsPerSession)
		}
	}
	g.admitted[id] = admittedTunnel{session: session, node: node, proto: proto, until: now.Add(tunnelTTL)}
	g.admittedBy[session]++
	return nil
}

// forgetTunnel removes a recorded tunnel; g.mu is held.
func (g *Gateway) forgetTunnel(id string, a admittedTunnel) {
	delete(g.admitted, id)
	if g.admittedBy[a.session]--; g.admittedBy[a.session] <= 0 {
		delete(g.admittedBy, a.session)
	}
}

// pruneTunnels removes expired tunnels; g.mu is held.
func (g *Gateway) pruneTunnels(now time.Time) {
	for id, a := range g.admitted {
		if now.After(a.until) {
			g.forgetTunnel(id, a)
		}
	}
}

// forgetSessionTunnels removes an ended session's tunnels; g.mu is held.
func (g *Gateway) forgetSessionTunnels(session uuid.UUID) {
	for id, a := range g.admitted {
		if a.session == session {
			g.forgetTunnel(id, a)
		}
	}
}

// checkAgentRelay checks an agent's relay connection: no user credentials
// or routing instructions, and, when it names a device, a tunnel recorded
// for that device and protocol.
func (g *Gateway) checkAgentRelay(q url.Values) error {
	if err := agentRelayRefused(q); err != nil {
		return err
	}
	nodes, named := q["nodeid"]
	if !named {
		return nil
	}
	ids, protos := q["id"], q["p"]
	if len(nodes) != 1 || len(ids) != 1 || len(protos) != 1 {
		return refused("agent relay naming a device without one tunnel id and protocol")
	}
	node, err := normalizeNodeID(nodes[0])
	if err != nil {
		return err
	}
	g.mu.Lock()
	a, ok := g.admitted[ids[0]]
	g.mu.Unlock()
	switch {
	case !ok || time.Now().After(a.until):
		return refused("agent relay for a tunnel no session opened")
	case a.node != node || a.proto != protos[0]:
		return refused("agent relay for another device or protocol than its tunnel's")
	}
	return nil
}

// tunnelValue parses the relay address in a tunnel request: this server's
// relay ("*/meshrelay.ashx?…", as MeshCentral's page sends it) with exactly
// a protocol, a device, a tunnel id and optionally a relay cookie. Another
// server's address would make the agent connect there instead; an address
// that names no device would not be bound to the request's device.
func tunnelValue(v string) (proto, node, id string, err error) {
	const prefix = "*/meshrelay.ashx?"
	if !strings.HasPrefix(v, prefix) {
		return "", "", "", refused("tunnel request for %q", short(v))
	}
	raw := v[len(prefix):]
	for i := range len(raw) {
		if c := raw[i]; c <= ' ' || c >= 0x7f || c == '#' || c == '\\' {
			return "", "", "", refused("tunnel request with unusual characters")
		}
	}
	q, perr := url.ParseQuery(raw)
	if perr != nil {
		return "", "", "", refused("tunnel request that cannot be parsed")
	}
	for k, vals := range q {
		switch k {
		case "p", "nodeid", "id", "rauth":
			if len(vals) != 1 {
				return "", "", "", refused("tunnel request with %d values for %s", len(vals), k)
			}
		default:
			return "", "", "", refused("tunnel request with %q", short(k))
		}
	}
	proto = q.Get("p")
	if relayKinds[proto] == "" {
		return "", "", "", refused("tunnel request for relay protocol %q", short(proto))
	}
	if _, ok := q["nodeid"]; !ok {
		return "", "", "", refused("tunnel request that names no device")
	}
	if node, err = normalizeNodeID(q.Get("nodeid")); err != nil {
		return "", "", "", err
	}
	if id = q.Get("id"); !tunnelIDPattern.MatchString(id) {
		return "", "", "", refused("tunnel id %q", short(id))
	}
	return proto, node, id, nil
}

// desktopMessages are the device messages MeshCentral's page sends during a
// remote desktop session: the clipboard, the wallpaper switch and the list
// of signed-in users to connect to.
var desktopMessages = map[string]bool{"getclip": true, "setclip": true, "deskBackground": true, "userSessions": true}

// controlCheck returns the check for a browser's MeshCentral control
// channel. Besides refusing routing instructions (checkControlMessage), it
// looks at the messages MeshCentral routes to an agent ("action": "msg"),
// which MeshCentral and MeshAgent allow for anyone with remote control
// rights on the device:
//
//   - tunnel requests must be for a device and session type the session
//     holds a grant on (and are recorded, see above); others close the
//     channel;
//   - clipboard, wallpaper and signed-in user messages need a desktop
//     grant on the device;
//   - every other device message (process and service control, opening
//     web pages, message boxes, system details) is none of EasyRMM's
//     session types and is dropped.
//
// Dropped messages are logged and not forwarded; the channel stays open.
func (g *Gateway) controlCheck(ctx context.Context, session uuid.UUID) func([]byte) error {
	return func(payload []byte) error {
		if err := checkControlMessage(payload); err != nil {
			return err
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(payload, &m); err != nil {
			return refused("control message that is not a JSON object")
		}
		if action, _ := jsonString(m["action"]); action != "msg" {
			return nil
		}
		typ, ok := jsonString(m["type"])
		if !ok {
			return dropped("device message without a type")
		}
		nodeRaw, _ := jsonString(m["nodeid"])
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		switch {
		case typ == "tunnel":
			return g.checkTunnelRequest(cctx, session, nodeRaw, m["value"])
		case desktopMessages[typ]:
			node, err := normalizeNodeID(nodeRaw)
			if err != nil {
				return dropped("%s for device %q", typ, short(nodeRaw))
			}
			ok, err := g.desktopGranted(cctx, session, node)
			if err != nil {
				return dropped("checking the desktop grant for %s failed: %v", typ, err)
			}
			if !ok {
				return dropped("%s for a device the session opened no desktop session on", typ)
			}
			return nil
		}
		return dropped("device message %q, which is not part of EasyRMM's remote sessions", short(typ))
	}
}

// checkTunnelRequest checks a control channel tunnel request and records
// its tunnel.
func (g *Gateway) checkTunnelRequest(ctx context.Context, session uuid.UUID, nodeRaw string, value json.RawMessage) error {
	v, ok := jsonString(value)
	if !ok {
		return refused("tunnel request without a relay address")
	}
	proto, node, id, err := tunnelValue(v)
	if err != nil {
		return err
	}
	target, err := normalizeNodeID(nodeRaw)
	if err != nil {
		return err
	}
	if target != node {
		return refused("tunnel request whose relay names another device")
	}
	if g.granted == nil {
		return refused("no grant check")
	}
	kind := relayKinds[proto]
	granted, err := g.granted(ctx, session, node, kind)
	if err != nil {
		return refused("checking the tunnel's grant failed: %v", err)
	}
	if !granted {
		return refused("%s tunnel to a device the session opened no %s session on", kind, kind)
	}
	return g.admitTunnel(session, id, node, proto)
}

// relayProtocolCheck returns the check for the browser's side of a relay.
// MeshAgent takes the session type from the first message that is not a
// JSON object ("1", "2", "5"…), whatever the relay's address said, so that
// message must be the protocol the relay was admitted for. JSON messages
// before it (terminal options, pings) pass; everything after it passes
// unread.
func relayProtocolCheck(proto string) func([]byte) error {
	return func(msg []byte) error {
		if len(msg) > 3 && msg[0] == '{' {
			return nil
		}
		if string(msg) != proto {
			return refused("relay protocol %q on a relay opened for protocol %s", short(string(msg)), proto)
		}
		return errPassRest
	}
}

// jsonString returns a JSON value as a string, if it is one.
func jsonString(raw json.RawMessage) (string, bool) {
	var s string
	if raw == nil || json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

// short cuts a value for a log message.
func short(s string) string {
	if len(s) > 64 {
		return s[:64] + "…"
	}
	return s
}
