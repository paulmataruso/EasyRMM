package remote

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
)

// MeshCentral relays bytes between a browser and an agent. Besides the
// desktop, terminal and file sessions EasyRMM offers, a MeshCentral user with
// remote control rights can ask an agent to open a TCP or UDP connection to
// any port on the device or on its network, and relay that instead (the
// feature behind MeshCentral Router). MeshCentral checks no session-type
// right for it, and EasyRMM grants none of it, so the gateway refuses every
// way of asking (ADR-0022):
//
//   - relay connections whose address carries routing instructions
//     (tcpport, tcpaddr, udpport, udpaddr);
//   - control channel commands that carry them: a tunnel request routed to an
//     agent, or a request for a relay cookie that encodes them;
//   - relay connections on the agent path that authenticate as a user, which
//     would skip the browser checks altogether.

// routingKeys are MeshCentral's routing instructions.
var routingKeys = map[string]bool{"tcpport": true, "tcpaddr": true, "udpport": true, "udpaddr": true}

// relayProtocols are the relay protocols of the session types EasyRMM offers:
// terminal (1; 6, 8 and 9 are its PowerShell and logged-in user variants),
// desktop (2) and files (5).
var relayProtocols = map[string]bool{"1": true, "2": true, "5": true, "6": true, "8": true, "9": true}

// errRefused is a request the gateway does not forward.
var errRefused = errors.New("remote gateway: refused")

func refused(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{errRefused}, args...)...)
}

// hasRoutingKey reports whether a query carries routing instructions.
// MeshCentral reads query keys case-sensitively; the check does not, so
// that no spelling slips through.
func hasRoutingKey(q url.Values) bool {
	for k := range q {
		if routingKeys[strings.ToLower(k)] {
			return true
		}
	}
	return false
}

// browserRelay checks a browser's relay connection and returns the device it
// is for: one of EasyRMM's session protocols, for a named device, with no
// routing instructions.
func browserRelay(q url.Values) (nodeID string, err error) {
	if hasRoutingKey(q) {
		return "", refused("relay with routing instructions")
	}
	if p := q["p"]; len(p) != 1 || !relayProtocols[p[0]] {
		return "", refused("relay protocol %q", q.Get("p"))
	}
	nodes := q["nodeid"]
	if len(nodes) != 1 {
		return "", refused("relay without a device")
	}
	return normalizeNodeID(nodes[0])
}

// normalizeNodeID turns the forms MeshCentral accepts ("node//id",
// "node/domain/id" or the bare id) into EasyRMM's stored form.
func normalizeNodeID(v string) (string, error) {
	id := v
	if strings.HasPrefix(v, "node/") {
		id = v[strings.LastIndex(v, "/")+1:]
		if parts := strings.Split(v, "/"); len(parts) != 3 || parts[1] != "" {
			return "", refused("relay for device %q", v)
		}
	}
	if !meshNodeID.MatchString(id) {
		return "", refused("relay for device %q", v)
	}
	return "node//" + id, nil
}

// agentRelayRefused reports why an agent-path relay connection is refused:
// agents join relays with the tunnel id and a relay cookie, never as a
// signed-in user and never with routing instructions.
func agentRelayRefused(q url.Values) error {
	if hasRoutingKey(q) {
		return refused("agent relay with routing instructions")
	}
	for k := range q {
		switch strings.ToLower(k) {
		case "auth", "user", "pass", "key", "token":
			return refused("agent relay with user credentials")
		}
	}
	return nil
}

// checkControlMessage accepts a message from the browser on MeshCentral's
// control channel unless it carries routing instructions. MeshCentral parses
// each message as JSON; anything this check cannot parse as a JSON object is
// refused rather than guessed at.
func checkControlMessage(payload []byte) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(payload, &m); err != nil || m == nil {
		return refused("control message that is not a JSON object")
	}
	for k, v := range m {
		if routingKeys[strings.ToLower(k)] {
			return refused("control message with routing instructions")
		}
		// A tunnel request names the relay address the agent joins; keep
		// routing instructions out of it too.
		if strings.EqualFold(k, "value") {
			var s string
			if json.Unmarshal(v, &s) == nil {
				lower := strings.ToLower(s)
				for key := range routingKeys {
					if strings.Contains(lower, key) {
						return refused("tunnel request with routing instructions")
					}
				}
			}
		}
	}
	return nil
}

// maxControlMessage bounds one control channel message; MeshCentral's own are
// far smaller (clipboard text is the largest).
const maxControlMessage = 8 << 20

// wsGuard reads the browser's side of a WebSocket and passes each message on
// only once check has accepted it whole. Control frames pass straight
// through; compressed frames are refused, since the gateway asks for no
// compression.
type wsGuard struct {
	src   *bufio.Reader
	check func([]byte) error

	out       []byte // checked bytes ready for the reader
	inMessage bool   // between the first and the final frame of a message
	held      []byte // the message's frames as received
	payload   []byte // and its unmasked payload
	err       error
	headerBuf [14]byte
}

func newWSGuard(r io.Reader, check func([]byte) error) *wsGuard {
	return &wsGuard{src: bufio.NewReaderSize(r, 32<<10), check: check}
}

func (g *wsGuard) Read(p []byte) (int, error) {
	for len(g.out) == 0 {
		if g.err != nil {
			return 0, g.err
		}
		g.err = g.next()
	}
	n := copy(p, g.out)
	g.out = g.out[n:]
	return n, nil
}

// next reads one frame.
func (g *wsGuard) next() error {
	h := g.headerBuf[:]
	if _, err := io.ReadFull(g.src, h[:2]); err != nil {
		return err
	}
	fin := h[0]&0x80 != 0
	if h[0]&0x70 != 0 {
		return refused("WebSocket frame with reserved bits (compression)")
	}
	op := h[0] & 0x0f
	if h[1]&0x80 == 0 {
		return refused("unmasked WebSocket frame from a browser")
	}
	size := uint64(h[1] & 0x7f)
	hl := 2
	switch size {
	case 126:
		if _, err := io.ReadFull(g.src, h[2:4]); err != nil {
			return err
		}
		size, hl = uint64(binary.BigEndian.Uint16(h[2:4])), 4
	case 127:
		if _, err := io.ReadFull(g.src, h[2:10]); err != nil {
			return err
		}
		size, hl = binary.BigEndian.Uint64(h[2:10]), 10
	}
	if _, err := io.ReadFull(g.src, h[hl:hl+4]); err != nil {
		return err
	}
	key := h[hl : hl+4]
	hl += 4

	if op >= 0x8 { // close, ping, pong
		if size > 125 || !fin {
			return refused("malformed WebSocket control frame")
		}
		frame := make([]byte, hl+int(size))
		copy(frame, h[:hl])
		if _, err := io.ReadFull(g.src, frame[hl:]); err != nil {
			return err
		}
		g.out = append(g.out, frame...)
		return nil
	}
	switch {
	case op == 0x0 && !g.inMessage:
		return refused("WebSocket continuation outside a message")
	case op != 0x0 && g.inMessage:
		return refused("WebSocket message inside another")
	case op != 0x0 && op != 0x1 && op != 0x2:
		return refused("WebSocket frame type %d", op)
	}
	if size > maxControlMessage || uint64(len(g.payload))+size > maxControlMessage {
		return refused("control message over %d bytes", maxControlMessage)
	}
	g.inMessage = true
	start := len(g.held)
	g.held = append(g.held, h[:hl]...)
	g.held = append(g.held, make([]byte, size)...)
	data := g.held[start+hl:]
	if _, err := io.ReadFull(g.src, data); err != nil {
		return err
	}
	at := len(g.payload)
	g.payload = append(g.payload, data...)
	for i := range data {
		g.payload[at+i] ^= key[i&3]
	}
	if !fin {
		return nil
	}
	if err := g.check(g.payload); err != nil {
		return err
	}
	g.out = append(g.out, g.held...)
	g.held, g.payload, g.inMessage = nil, nil, false
	return nil
}
