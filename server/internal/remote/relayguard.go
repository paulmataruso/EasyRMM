package remote

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
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

// relayKinds maps the relay protocols of the session types EasyRMM offers to
// those types: terminal (1; 6, 8 and 9 are its PowerShell and logged-in user
// variants), desktop (2) and files (5). A relay is allowed only for the kind
// of session the console opened, so the audit log's kind is what was used.
var relayKinds = map[string]Kind{
	"1": KindTerminal, "2": KindDesktop, "5": KindFiles, "6": KindTerminal, "8": KindTerminal, "9": KindTerminal,
}

// errRefused is a request the gateway does not forward.
var errRefused = errors.New("remote gateway: refused")

func refused(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{errRefused}, args...)...)
}

// errDropped is a WebSocket message the gateway does not forward, while
// keeping the connection open.
var errDropped = errors.New("remote gateway: dropped")

func dropped(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{errDropped}, args...)...)
}

// errPassRest accepts a WebSocket message and everything after it unread.
var errPassRest = errors.New("remote gateway: rest of the connection passes")

// queryKey is the name MeshCentral reads a query key as. Its web server
// (Express 4) parses queries with qs, which reads "tcpport[]=22" and
// "tcpport[0]=22" as tcpport; the check compares the name before any
// bracket, without case, so that no spelling slips through.
func queryKey(k string) string {
	if i := strings.IndexByte(k, '['); i >= 0 {
		k = k[:i]
	}
	return strings.ToLower(k)
}

// hasRoutingKey reports whether a query carries routing instructions.
func hasRoutingKey(q url.Values) bool {
	for k := range q {
		if routingKeys[queryKey(k)] {
			return true
		}
	}
	return false
}

// hasBracketKey reports whether a query has a key qs would read as an array
// or object. MeshCentral's own pages and agents never send one, and where
// the gateway reads a value it must read the one MeshCentral reads.
func hasBracketKey(q url.Values) bool {
	for k := range q {
		if strings.ContainsAny(k, "[]") {
			return true
		}
	}
	return false
}

// browserRelay checks a browser's relay connection and returns the device
// and the kind of session it is for: one of EasyRMM's session protocols, for
// a named device, with no routing instructions.
func browserRelay(q url.Values) (nodeID string, kind Kind, err error) {
	if hasRoutingKey(q) {
		return "", "", refused("relay with routing instructions")
	}
	if hasBracketKey(q) {
		return "", "", refused("relay with an array or object in its address")
	}
	p := q["p"]
	if len(p) == 1 {
		kind = relayKinds[p[0]]
	}
	if kind == "" {
		return "", "", refused("relay protocol %q", q.Get("p"))
	}
	nodes := q["nodeid"]
	if len(nodes) != 1 {
		return "", "", refused("relay without a device")
	}
	nodeID, err = normalizeNodeID(nodes[0])
	return nodeID, kind, err
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
	if hasBracketKey(q) {
		return refused("agent relay with an array or object in its address")
	}
	for k := range q {
		switch queryKey(k) {
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
		if routingKeys[queryKey(k)] {
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
// only once check has accepted it whole. A check may also drop a message
// (errDropped) or let the rest of the connection through (errPassRest).
// Control frames pass straight through; compressed frames are refused,
// since the gateway asks for no compression.
type wsGuard struct {
	src   *bufio.Reader
	check func([]byte) error
	// transform, when set, is called once, with the first message the check
	// admits; the bytes it returns are forwarded in a rebuilt frame instead
	// of the browser's own (ADR-0079).
	transform func([]byte) ([]byte, error)

	out       []byte // checked bytes ready for the reader
	pass      bool   // the check let the rest of the connection through
	inMessage bool   // between the first and the final frame of a message
	held      []byte // the message's frames as received
	payload   []byte // and its unmasked payload
	err       error
	headerBuf [14]byte
}

func newWSGuard(r io.Reader, check func([]byte) error) *wsGuard {
	return &wsGuard{src: bufio.NewReaderSize(r, 32<<10), check: check}
}

// withTransform sets the transform of the first admitted message.
func (g *wsGuard) withTransform(t func([]byte) ([]byte, error)) *wsGuard {
	g.transform = t
	return g
}

func (g *wsGuard) Read(p []byte) (int, error) {
	for len(g.out) == 0 {
		if g.pass {
			return g.src.Read(p)
		}
		if g.err != nil {
			return 0, g.err
		}
		g.err = g.next()
	}
	n := copy(p, g.out)
	// The bytes are on their way; do not leave a rebuilt frame lying about.
	clear(g.out[:n])
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
	err := g.check(g.payload)
	switch {
	case errors.Is(err, errDropped):
		// Not forwarded; frames are masked one by one, so leaving a whole
		// message out keeps the stream intact.
	case errors.Is(err, errPassRest):
		g.out = append(g.out, g.held...)
		g.pass = true
	case err != nil:
		return err
	default:
		if t := g.transform; t != nil {
			g.transform = nil
			repl, terr := t(g.payload)
			if terr != nil {
				g.scrub()
				return terr
			}
			frame, ferr := buildTextFrame(repl)
			clear(repl)
			if ferr != nil {
				g.scrub()
				return ferr
			}
			g.out = append(g.out, frame...)
			clear(frame)
		} else {
			g.out = append(g.out, g.held...)
		}
	}
	g.scrub()
	return nil
}

// scrub ends the current message, overwriting what was kept of it.
func (g *wsGuard) scrub() {
	clear(g.held)
	clear(g.payload)
	g.held, g.payload, g.inMessage = nil, nil, false
}

// rdpCheck returns the check for the browser's side of MeshCentral's web RDP
// relay (ADR-0026). Its first message names the device and carries the
// credentials (["infos", {"ip": "node//…", …}]); MeshCentral then connects
// to that device's RDP port through its agent. The check admits it only for
// a device the session holds an RDP grant on, named by its node ID: an
// "ip" that is not one is an encoded cookie, which can name any address.
// MeshCentral ignores the port the browser sends for a node ID. Later
// messages (input, clipboard, pong) pass; a second "infos" does not.
func (g *Gateway) rdpCheck(ctx context.Context, session uuid.UUID) func([]byte) error {
	started := false
	return func(msg []byte) error {
		var m []json.RawMessage
		if err := json.Unmarshal(msg, &m); err != nil || len(m) == 0 {
			return refused("RDP message that is not a JSON array")
		}
		var action string
		if err := json.Unmarshal(m[0], &action); err != nil {
			return refused("RDP message without an action")
		}
		if action != "infos" {
			if !started {
				return refused("RDP message before the connection request")
			}
			return nil
		}
		if started {
			return refused("second RDP connection request")
		}
		var infos struct {
			IP string `json:"ip"`
		}
		if len(m) < 2 || json.Unmarshal(m[1], &infos) != nil {
			return refused("RDP connection request without details")
		}
		if !strings.HasPrefix(infos.IP, "node/") {
			return refused("RDP connection by cookie")
		}
		node, err := normalizeNodeID(infos.IP)
		if err != nil {
			return err
		}
		if g.granted == nil {
			return refused("no grant check")
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		ok, err := g.granted(cctx, session, node, KindRDP)
		if err != nil {
			return refused("checking the RDP grant failed: %v", err)
		}
		if !ok {
			return refused("RDP relay for a device the session opened no RDP session on")
		}
		started = true
		return nil
	}
}
