package remote

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestBrowserRelay(t *testing.T) {
	ok := map[string]struct {
		node string
		kind Kind
	}{
		"browser=1&p=2&nodeid=node//abc$@9&id=t1&auth=x": {"node//abc$@9", KindDesktop},
		"p=1&nodeid=node/domain/abc&id=t1":               {},
		"p=1&nodeid=node//abc&id=t1":                     {"node//abc", KindTerminal},
		"p=5&nodeid=abc&id=t1":                           {"node//abc", KindFiles},
		"p=6&nodeid=node//abc&id=t1":                     {"node//abc", KindTerminal},
		"p=8&nodeid=node//abc&id=t1":                     {"node//abc", KindTerminal},
		"p=9&nodeid=node//abc&id=t1":                     {"node//abc", KindTerminal},
	}
	for q, want := range ok {
		v, _ := url.ParseQuery(q)
		node, kind, err := browserRelay(v)
		if want.node == "" {
			if err == nil {
				t.Errorf("%s: accepted a node id with a domain", q)
			}
			continue
		}
		if err != nil || node != want.node || kind != want.kind {
			t.Errorf("%s: %q %q, %v", q, node, kind, err)
		}
	}
	for _, q := range []string{
		"p=2&nodeid=node//abc&tcpport=3389",
		"p=2&nodeid=node//abc&TcpPort=3389",
		"p=2&nodeid=node//abc&tcpaddr=10.0.0.5",
		"p=2&nodeid=node//abc&udpport=53",
		"nodeid=node//abc&id=t1",
		"p=2&p=10&nodeid=node//abc",
		"p=10&nodeid=node//abc",
		"p=4&nodeid=node//abc",
		"p=2",
		"p=2&nodeid=node//abc&nodeid=node//def",
		"p=2&nodeid=node//a/b",
		"p=2&nodeid=node//a%25b",
		// MeshCentral's query parser (qs) reads these as tcpport and p.
		"p=2&nodeid=node//abc&tcpport[]=22",
		"p=2&nodeid=node//abc&TcpAddr[0]=10.0.0.5",
		"p=2&nodeid=node//abc&p[]=1",
	} {
		v, _ := url.ParseQuery(q)
		if _, _, err := browserRelay(v); !errors.Is(err, errRefused) {
			t.Errorf("%s: accepted (%v)", q, err)
		}
	}
}

func TestAgentRelayRefused(t *testing.T) {
	v, _ := url.ParseQuery("p=1&nodeid=node//abc&id=t1&rauth=r")
	if err := agentRelayRefused(v); err != nil {
		t.Errorf("agent joining a relay refused: %v", err)
	}
	for _, q := range []string{"id=t1&auth=x", "id=t1&Auth=x", "id=t1&tcpport=22", "id=t1&user=a&pass=b", "id=t1&key=k", "id=t1&auth[x]=y", "id=t1&udpport[]=53"} {
		v, _ := url.ParseQuery(q)
		if err := agentRelayRefused(v); !errors.Is(err, errRefused) {
			t.Errorf("%s: accepted", q)
		}
	}
}

func TestCheckControlMessage(t *testing.T) {
	for _, m := range []string{
		`{"action":"authcookie"}`,
		`{"action":"msg","type":"tunnel","nodeid":"node//abc","value":"*/meshrelay.ashx?p=1&nodeid=node//abc&id=t&rauth=r","usage":1}`,
		`{"action":"getcookie","nodeid":"node//abc","tag":"files"}`,
		`{"action":"msg","type":"setclip","data":"tcpport is just text here"}`,
	} {
		if err := checkControlMessage([]byte(m)); err != nil {
			t.Errorf("%s: %v", m, err)
		}
	}
	for _, m := range []string{
		`{"action":"msg","type":"tunnel","nodeid":"node//abc","value":"*/meshrelay.ashx?id=t","tcpport":3389,"tcpaddr":"10.0.0.5"}`,
		`{"action":"getcookie","nodeid":"node//abc","tcpport":445}`,
		`{"action":"getcookie","nodeid":"node//abc","TCPADDR":"10.0.0.5"}`,
		`{"action":"msg","type":"tunnel","value":"*/meshrelay.ashx?id=t&tcpport=22"}`,
		`{"action":"msg","type":"tunnel","value":"*/meshrelay.ashx?id=t&UdpPort=53"}`,
		`[{"action":"authcookie"}]`,
		`null`,
		`not json`,
		``,
	} {
		if err := checkControlMessage([]byte(m)); !errors.Is(err, errRefused) {
			t.Errorf("%s: accepted", m)
		}
	}
}

// frame builds a masked client frame.
func frame(fin bool, op byte, payload []byte, rsv byte) []byte {
	var b bytes.Buffer
	first := op | rsv<<4
	if fin {
		first |= 0x80
	}
	b.WriteByte(first)
	switch n := len(payload); {
	case n < 126:
		b.WriteByte(0x80 | byte(n))
	case n < 1<<16:
		b.WriteByte(0x80 | 126)
		_ = binary.Write(&b, binary.BigEndian, uint16(n))
	default:
		b.WriteByte(0x80 | 127)
		_ = binary.Write(&b, binary.BigEndian, uint64(n))
	}
	key := []byte{0x12, 0x34, 0x56, 0x78}
	b.Write(key)
	for i, c := range payload {
		b.WriteByte(c ^ key[i%4])
	}
	return b.Bytes()
}

func readAllGuarded(in []byte) ([]byte, error) {
	g := newWSGuard(bytes.NewReader(in), checkControlMessage)
	out, err := io.ReadAll(g)
	return out, err
}

func TestWSGuardPassesCheckedMessagesUnchanged(t *testing.T) {
	big := []byte(`{"action":"msg","type":"setclip","data":"` + strings.Repeat("x", 70000) + `"}`)
	part := []byte(`{"action":"authcookie"}`)
	var in bytes.Buffer
	in.Write(frame(true, 0x1, []byte(`{"action":"serverinfo"}`), 0))
	// A fragmented message with a ping between its frames.
	in.Write(frame(false, 0x1, part[:8], 0))
	ping := frame(true, 0x9, []byte("hi"), 0)
	in.Write(ping)
	in.Write(frame(true, 0x0, part[8:], 0))
	in.Write(frame(true, 0x2, big, 0))
	medium := []byte(`{"action":"x","pad":"` + strings.Repeat("y", 300) + `"}`)
	in.Write(frame(true, 0x1, medium, 0))
	in.Write(frame(true, 0x8, []byte{0x03, 0xe8}, 0))

	out, err := readAllGuarded(in.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	// Same bytes, except that the ping no longer waits behind the message
	// it arrived in the middle of.
	want := append([]byte{}, frame(true, 0x1, []byte(`{"action":"serverinfo"}`), 0)...)
	want = append(want, ping...)
	want = append(want, frame(false, 0x1, part[:8], 0)...)
	want = append(want, frame(true, 0x0, part[8:], 0)...)
	want = append(want, frame(true, 0x2, big, 0)...)
	want = append(want, frame(true, 0x1, medium, 0)...)
	want = append(want, frame(true, 0x8, []byte{0x03, 0xe8}, 0)...)
	if !bytes.Equal(out, want) {
		t.Fatalf("guarded stream differs: %d bytes, want %d", len(out), len(want))
	}
}

func TestWSGuardStopsRefusedMessages(t *testing.T) {
	ok := frame(true, 0x1, []byte(`{"action":"serverinfo"}`), 0)
	cases := map[string][]byte{
		"routing":        frame(true, 0x1, []byte(`{"action":"getcookie","tcpport":22}`), 0),
		"fragmented":     append(frame(false, 0x1, []byte(`{"action":"getcookie",`), 0), frame(true, 0x0, []byte(`"tcpport":22}`), 0)...),
		"compressed":     frame(true, 0x1, []byte(`{"action":"x"}`), 0x4),
		"stray continue": frame(true, 0x0, []byte(`{"action":"x"}`), 0),
		"nested start":   append(frame(false, 0x1, []byte(`{"a":`), 0), frame(true, 0x1, []byte(`{}`), 0)...),
		"opcode":         frame(true, 0x3, []byte(`{}`), 0),
		"long ping":      frame(true, 0x9, bytes.Repeat([]byte("p"), 126), 0),
		"split ping":     frame(false, 0x9, []byte("p"), 0),
	}
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			out, err := readAllGuarded(append(append([]byte{}, ok...), bad...))
			if !errors.Is(err, errRefused) {
				t.Fatalf("err = %v", err)
			}
			if !bytes.Equal(out, ok) {
				t.Fatalf("passed on %d bytes, want only the first message", len(out))
			}
		})
	}
	// Unmasked frames never come from a browser.
	unmasked := []byte{0x81, 0x02, '{', '}'}
	if _, err := readAllGuarded(unmasked); !errors.Is(err, errRefused) {
		t.Errorf("unmasked frame: %v", err)
	}
	// A message larger than the limit is refused before it is read.
	huge := []byte{0x82, 0x80 | 127, 0, 0, 0, 0, 0x7f, 0, 0, 0, 1, 2, 3, 4}
	if _, err := readAllGuarded(huge); !errors.Is(err, errRefused) {
		t.Errorf("oversized message: %v", err)
	}
	// A stream that ends inside a frame is an error, not a message.
	cut := frame(true, 0x1, []byte(`{"action":"x"}`), 0)
	if _, err := readAllGuarded(cut[:len(cut)-3]); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("truncated frame: %v", err)
	}
}

func TestGatewayAgentPathCarriesNoUserCredentials(t *testing.T) {
	up := newUpstream(t)
	g := newTestGateway(t, up.URL, true)
	if err := g.admitTunnel(uuid.New(), "t1", "node//abc", "1"); err != nil {
		t.Fatal(err)
	}
	r := agentRequest(http.MethodGet, "https://mesh.example.com/meshrelay.ashx?p=1&nodeid=node//abc&id=t1&rauth=r")
	r.Header.Set("Cookie", "xid=meshcentral-session; xid.sig=s")
	r.Header.Set("X-MeshAuth", "dXNlcg==,cGFzcw==")
	if w := serve(g, r); w.Code != http.StatusOK {
		t.Fatalf("agent joining a relay: %d %q", w.Code, w.Body.String())
	}
	in := <-up.got
	if in.Header.Get("Cookie") != "" || in.Header.Get("X-MeshAuth") != "" {
		t.Errorf("forwarded credentials: %v", in.Header)
	}
	for _, q := range []string{"id=t1&auth=cookie", "p=1&nodeid=node//abc&tcpport=3389", "id=t1&rauth=r&tcpport[]=22", "id=t1&rauth=r&TCPADDR%5B0%5D=10.0.0.1", "id=t1&auth[]=cookie"} {
		w := serve(g, agentRequest(http.MethodGet, "https://mesh.example.com/meshrelay.ashx?"+q))
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "Not available") {
			t.Errorf("%s: %d", q, w.Code)
		}
	}
	// Local relays make MeshCentral itself connect somewhere; never offered.
	r = httptest.NewRequest(http.MethodGet, "https://mesh.example.com/localrelay.ashx?id=1", nil)
	r.Header.Set("Origin", "https://mesh.example.com")
	if w := serve(g, r); w.Code != http.StatusForbidden {
		t.Errorf("local relay: %d", w.Code)
	}
	select {
	case r := <-up.got:
		t.Fatalf("forwarded %s", r.URL)
	default:
	}
}

func TestGatewayRelaysOnlyToGrantedDevices(t *testing.T) {
	up := newUpstream(t)
	g := newTestGateway(t, up.URL, true)
	session := uuid.New()
	g.remember("grant-cookie", session)
	var asked []string
	g.granted = func(_ context.Context, s uuid.UUID, nodeID string, kind Kind) (bool, error) {
		asked = append(asked, nodeID+" "+string(kind))
		if nodeID == "node//broken" {
			return false, errors.New("database down")
		}
		return s == session && nodeID == "node//granted" && kind == KindDesktop, nil
	}
	relay := func(q string) int {
		r := httptest.NewRequest(http.MethodGet, "https://mesh.example.com/MeshRelay.ashx/?"+q, nil)
		r.Header.Set("Origin", "https://mesh.example.com")
		r.AddCookie(&http.Cookie{Name: g.CookieName(), Value: "grant-cookie"})
		return serve(g, r).Code
	}
	if c := relay("browser=1&p=2&nodeid=node//granted&id=t1"); c != http.StatusOK {
		t.Errorf("granted device: %d", c)
	}
	if c := relay("browser=1&p=2&nodeid=node//other&id=t1"); c != http.StatusForbidden {
		t.Errorf("device without a grant: %d", c)
	}
	if c := relay("browser=1&p=5&nodeid=node//granted&id=t1"); c != http.StatusForbidden {
		t.Errorf("files on a desktop grant: %d", c)
	}
	if c := relay("browser=1&p=2&nodeid=node//granted&id=t1&tcpport=3389"); c != http.StatusForbidden {
		t.Errorf("routing instructions: %d", c)
	}
	if c := relay("browser=1&p=2&nodeid=node//broken&id=t1"); c != http.StatusInternalServerError {
		t.Errorf("failed grant check: %d", c)
	}
	if strings.Join(asked, ",") != "node//granted desktop,node//other desktop,node//granted files,node//broken desktop" {
		t.Errorf("grant checks = %v", asked)
	}
	// Without a grant check (no remote service), relays are refused.
	g.granted = nil
	if c := relay("browser=1&p=2&nodeid=node//granted&id=t1"); c != http.StatusForbidden {
		t.Errorf("no grant check: %d", c)
	}
}

func TestTunnelValue(t *testing.T) {
	proto, node, id, err := tunnelValue("*/meshrelay.ashx?p=2&nodeid=node//abc&id=k3x9&rauth=r$@")
	if err != nil || proto != "2" || node != "node//abc" || id != "k3x9" {
		t.Fatalf("%q %q %q %v", proto, node, id, err)
	}
	if _, _, _, err := tunnelValue("*/meshrelay.ashx?p=1&nodeid=abc&id=t"); err != nil {
		t.Errorf("without a relay cookie: %v", err)
	}
	for _, v := range []string{
		"wss://elsewhere.example/meshrelay.ashx?p=1&nodeid=node//abc&id=t",
		"*/agenttransfer.ashx?p=1&nodeid=node//abc&id=t",
		"*/meshrelay.ashx?p=1&id=t&rauth=r",
		"*/meshrelay.ashx?p=1&nodeid=node//abc&id=t&tcpport=22",
		"*/meshrelay.ashx?p=1&nodeid=node//abc&id=t&browser=1",
		"*/meshrelay.ashx?p=1&nodeid=node//abc&id=t&nodeid=node//def",
		"*/meshrelay.ashx?p=1&nodeid=node//abc&id=t#&nodeid=node//def",
		"*/meshrelay.ashx?p=1&nodeid=node//abc&id=t;nodeid=node//def",
		"*/meshrelay.ashx?p=1&nodeid=node//abc&id=t\n",
		"*/meshrelay.ashx?p=1&nodeid=node//abc&id=a b",
		"*/meshrelay.ashx?p=1&nodeid=node//abc&id=" + strings.Repeat("x", 65),
		"*/meshrelay.ashx?p=1&nodeid=node//abc",
		"*/meshrelay.ashx?p=10&nodeid=node//abc&id=t",
		"*/meshrelay.ashx?p=1&nodeid=node//abc&id=t&p[]=2",
		"*/meshrelay.ashx?p=1&nodeid=node/x/abc&id=t",
		"*/meshrelay.ashx?p=1&nodeid=node//abc&id=%zz",
	} {
		if _, _, _, err := tunnelValue(v); !errors.Is(err, errRefused) {
			t.Errorf("%s: accepted (%v)", v, err)
		}
	}
}

// grantsFor answers grant checks from a list of "node kind" pairs.
func grantsFor(session uuid.UUID, grants ...string) func(context.Context, uuid.UUID, string, Kind) (bool, error) {
	return func(_ context.Context, s uuid.UUID, node string, kind Kind) (bool, error) {
		if node == "node//broken" {
			return false, errors.New("database down")
		}
		for _, g := range grants {
			if s == session && g == node+" "+string(kind) {
				return true, nil
			}
		}
		return false, nil
	}
}

func TestControlCheck(t *testing.T) {
	g := newTestGateway(t, "http://127.0.0.1:1", true)
	session := uuid.New()
	g.granted = grantsFor(session, "node//term terminal", "node//desk desktop")
	check := g.controlCheck(context.Background(), session)
	tunnel := func(node, value string) string {
		return `{"action":"msg","type":"tunnel","nodeid":"` + node + `","usage":1,"value":"` + value + `"}`
	}
	accepted := []string{
		`{"action":"authcookie"}`,
		`{"action":"nodes"}`,
		tunnel("node//term", "*/meshrelay.ashx?p=1&nodeid=node//term&id=t1&rauth=r"),
		tunnel("term", "*/meshrelay.ashx?p=8&nodeid=node//term&id=t2&rauth=r"),
		tunnel("node//desk", "*/meshrelay.ashx?p=2&nodeid=node//desk&id=t3&rauth=r"),
		`{"action":"msg","type":"setclip","nodeid":"node//desk","data":"copied"}`,
		`{"action":"msg","type":"getclip","nodeid":"desk"}`,
		`{"action":"msg","type":"userSessions","nodeid":"node//desk","tag":1}`,
		`{"action":"msg","type":"deskBackground","nodeid":"node//desk"}`,
	}
	for _, m := range accepted {
		if err := check([]byte(m)); err != nil {
			t.Errorf("%s: %v", m, err)
		}
	}
	// The tunnels are recorded for the agents to join.
	for _, q := range []string{"p=1&nodeid=node//term&id=t1&rauth=r", "p=8&nodeid=node//term&id=t2", "p=2&nodeid=node//desk&id=t3"} {
		v, _ := url.ParseQuery(q)
		if err := g.checkAgentRelay(v); err != nil {
			t.Errorf("agent joining %s: %v", q, err)
		}
	}
	closed := []string{
		// A device or session type the session holds no grant for.
		tunnel("node//other", "*/meshrelay.ashx?p=1&nodeid=node//other&id=t4&rauth=r"),
		tunnel("node//term", "*/meshrelay.ashx?p=2&nodeid=node//term&id=t5&rauth=r"),
		tunnel("node//desk", "*/meshrelay.ashx?p=5&nodeid=node//desk&id=t6&rauth=r"),
		// The relay names another device than the message, or none.
		tunnel("node//other", "*/meshrelay.ashx?p=1&nodeid=node//term&id=t7&rauth=r"),
		tunnel("node//other", "*/meshrelay.ashx?p=1&id=t8&rauth=r"),
		// Another server.
		tunnel("node//term", "wss://elsewhere.example/meshrelay.ashx?p=1&nodeid=node//term&id=t9"),
		// A tunnel id already recorded for another device.
		tunnel("node//desk", "*/meshrelay.ashx?p=2&nodeid=node//desk&id=t1&rauth=r"),
		`{"action":"msg","type":"tunnel","nodeid":"node//term","value":["*/meshrelay.ashx?p=1&nodeid=node//term&id=t10"]}`,
		`{"action":"msg","type":"tunnel","nodeid":"node//broken","value":"*/meshrelay.ashx?p=1&nodeid=node//broken&id=t11"}`,
		`{"action":"msg","type":"tunnel","nodeid":"node//term","value":"*/meshrelay.ashx?p=1&nodeid=node//term&id=t12","tcpport":22}`,
		`not json`,
	}
	for _, m := range closed {
		if err := check([]byte(m)); !errors.Is(err, errRefused) {
			t.Errorf("%s: %v, want the channel closed", m, err)
		}
	}
	dropped := []string{
		`{"action":"msg","type":"pskill","nodeid":"node//term","value":1234}`,
		`{"action":"msg","type":"serviceStop","nodeid":"node//term","serviceName":"wuauserv"}`,
		`{"action":"msg","type":"openUrl","nodeid":"node//desk","url":"https://example.com"}`,
		`{"action":"msg","type":"ps","nodeid":"node//desk"}`,
		`{"action":"msg","type":"endtunnel","nodeid":"node//desk"}`,
		`{"action":"msg","type":"console","nodeid":"node//term","value":"help"}`,
		`{"action":"msg","type":["tunnel"],"nodeid":"node//term"}`,
		`{"action":"msg","nodeid":"node//term"}`,
		// The clipboard belongs to desktop sessions only.
		`{"action":"msg","type":"getclip","nodeid":"node//term"}`,
		`{"action":"msg","type":"setclip","nodeid":"node//broken"}`,
		`{"action":"msg","type":"setclip","nodeid":"node/x/desk"}`,
	}
	for _, m := range dropped {
		if err := check([]byte(m)); !errors.Is(err, errDropped) {
			t.Errorf("%s: %v, want it dropped", m, err)
		}
	}
	// Nothing was recorded for the refused requests.
	for _, id := range []string{"t4", "t5", "t6", "t7", "t8", "t9", "t10", "t11", "t12"} {
		if _, ok := g.admitted[id]; ok {
			t.Errorf("tunnel %s recorded", id)
		}
	}
}

func TestAdmittedTunnels(t *testing.T) {
	g := newTestGateway(t, "http://127.0.0.1:1", true)
	alice, bob := uuid.New(), uuid.New()
	if err := g.admitTunnel(alice, "t1", "node//a", "2"); err != nil {
		t.Fatal(err)
	}
	// The browser's relay and the tunnel request record the same tunnel.
	if err := g.admitTunnel(alice, "t1", "node//a", "2"); err != nil {
		t.Errorf("the same tunnel again: %v", err)
	}
	for _, c := range []struct {
		session     uuid.UUID
		node, proto string
	}{{bob, "node//a", "2"}, {alice, "node//b", "2"}, {alice, "node//a", "1"}} {
		if err := g.admitTunnel(c.session, "t1", c.node, c.proto); !errors.Is(err, errRefused) {
			t.Errorf("t1 for %v %s %s: %v", c.session == bob, c.node, c.proto, err)
		}
	}
	if err := g.admitTunnel(alice, "bad id", "node//a", "2"); !errors.Is(err, errRefused) {
		t.Errorf("unusual tunnel id: %v", err)
	}

	agent := func(q string) error {
		v, _ := url.ParseQuery(q)
		return g.checkAgentRelay(v)
	}
	if err := agent("p=2&nodeid=node//a&id=t1&rauth=r"); err != nil {
		t.Errorf("agent joining its tunnel: %v", err)
	}
	if err := agent("p=10&id=x&rauth=r"); err != nil {
		t.Errorf("a relay MeshCentral asked for itself (web RDP): %v", err)
	}
	for _, q := range []string{
		"p=2&nodeid=node//b&id=t1&rauth=r",  // another device's agent
		"p=1&nodeid=node//a&id=t1&rauth=r",  // another protocol
		"p=2&nodeid=node//a&id=t2&rauth=r",  // a tunnel no one opened
		"nodeid=node//a&id=t1&rauth=r",      // no protocol
		"p=2&nodeid=node//a&rauth=r",        // no tunnel id
		"p=2&nodeid=node//a&id=t1&id=t2",    // two
		"p=2&nodeid=node//a&id=t1&auth=x",   // signed in as a user
		"p=2&nodeid=node/x/a&id=t1&rauth=r", // another domain
	} {
		if err := agent(q); !errors.Is(err, errRefused) {
			t.Errorf("agent relay %s: %v", q, err)
		}
	}

	// Each session may have a bounded number waiting; expired ones go.
	for i := range maxTunnelsPerSession - 1 {
		if err := g.admitTunnel(alice, "n"+strconv.Itoa(i), "node//a", "1"); err != nil {
			t.Fatal(err)
		}
	}
	if err := g.admitTunnel(alice, "over", "node//a", "1"); !errors.Is(err, errRefused) {
		t.Errorf("tunnel over the limit: %v", err)
	}
	if err := g.admitTunnel(bob, "bobs", "node//a", "1"); err != nil {
		t.Errorf("another session's tunnel: %v", err)
	}
	g.mu.Lock()
	for id, a := range g.admitted {
		if a.session == alice {
			a.until = time.Now().Add(-time.Second)
			g.admitted[id] = a
		}
	}
	g.mu.Unlock()
	if err := agent("p=2&nodeid=node//a&id=t1&rauth=r"); !errors.Is(err, errRefused) {
		t.Errorf("agent joining an expired tunnel: %v", err)
	}
	if err := g.admitTunnel(alice, "over", "node//a", "1"); err != nil {
		t.Errorf("after the others expired: %v", err)
	}
	// An expired id can be another session's.
	if err := g.admitTunnel(bob, "t1", "node//b", "5"); err != nil {
		t.Errorf("reusing an expired tunnel id: %v", err)
	}
	g.mu.Lock()
	g.forgetSessionTunnels(bob)
	_, left := g.admitted["bobs"]
	n := g.admittedBy[bob]
	g.mu.Unlock()
	if left || n != 0 {
		t.Errorf("ended session's tunnels kept: %v %d", left, n)
	}
}

func TestRelayProtocolCheck(t *testing.T) {
	check := relayProtocolCheck("1")
	var in []byte
	for _, m := range []string{`{"type":"options","cols":80}`, `{"ctrlChannel":"102938","type":"rtt"}`, "1", "anything", "2", "\x00\x01"} {
		in = append(in, frame(true, 0x1, []byte(m), 0)...)
	}
	out, err := io.ReadAll(newWSGuard(bytes.NewReader(in), check))
	if err != nil || !bytes.Equal(out, in) {
		t.Fatalf("a terminal relay: %v (%d of %d bytes)", err, len(out), len(in))
	}
	for _, first := range []string{"2", "5", " 1", "1 ", "01", "{}"} {
		in := append(frame(true, 0x1, []byte(`{"type":"options"}`), 0), frame(true, 0x2, []byte(first), 0)...)
		out, err := io.ReadAll(newWSGuard(bytes.NewReader(in), check))
		if !errors.Is(err, errRefused) {
			t.Errorf("first protocol %q on a terminal relay: %v", first, err)
		}
		if !bytes.Equal(out, frame(true, 0x1, []byte(`{"type":"options"}`), 0)) {
			t.Errorf("first protocol %q: forwarded %q", first, out)
		}
	}
}

func TestWSGuardDropsMessages(t *testing.T) {
	keep, drop := frame(true, 0x1, []byte("keep"), 0), frame(true, 0x1, []byte("drop"), 0)
	ping := frame(true, 0x9, nil, 0)
	// A dropped message split over frames goes whole; a ping inside it stays.
	in := append(append(append(append([]byte{}, keep...), frame(false, 0x1, []byte("dr"), 0)...), ping...), frame(true, 0x0, []byte("op"), 0)...)
	in = append(append(in, drop...), keep...)
	g := newWSGuard(bytes.NewReader(in), func(m []byte) error {
		if string(m) == "drop" {
			return dropped("test")
		}
		return nil
	})
	out, err := io.ReadAll(g)
	if err != nil {
		t.Fatal(err)
	}
	if want := append(append(append([]byte{}, keep...), ping...), keep...); !bytes.Equal(out, want) {
		t.Errorf("forwarded %q, want %q", out, want)
	}
}

func TestGatewayBindsRelaysToSessions(t *testing.T) {
	up := newUpstream(t)
	g := newTestGateway(t, up.URL, true)
	alice, bob := uuid.New(), uuid.New()
	g.remember("alice-cookie", alice)
	g.remember("bob-cookie", bob)
	g.granted = func(_ context.Context, s uuid.UUID, node string, kind Kind) (bool, error) {
		return node == "node//shared" && kind == KindDesktop, nil
	}
	relay := func(cookie, q string) int {
		r := httptest.NewRequest(http.MethodGet, "https://mesh.example.com/meshrelay.ashx?"+q, nil)
		r.Header.Set("Origin", "https://mesh.example.com")
		r.AddCookie(&http.Cookie{Name: g.CookieName(), Value: cookie})
		return serve(g, r).Code
	}
	if c := relay("alice-cookie", "browser=1&p=2&nodeid=node//shared&id=t1"); c != http.StatusOK {
		t.Fatalf("alice's relay: %d", c)
	}
	<-up.got
	// Bob holds a grant on the same device but cannot take Alice's tunnel.
	if c := relay("bob-cookie", "browser=1&p=2&nodeid=node//shared&id=t1"); c != http.StatusForbidden {
		t.Errorf("bob joining alice's tunnel: %d", c)
	}
	if c := relay("bob-cookie", "browser=1&p=2&nodeid=node//shared"); c != http.StatusForbidden {
		t.Errorf("relay without a tunnel id: %d", c)
	}
	// Alice's relay recorded the tunnel her device's agent joins.
	r := agentRequest(http.MethodGet, "https://mesh.example.com/meshrelay.ashx?p=2&nodeid=node//shared&id=t1&rauth=r")
	if w := serve(g, r); w.Code != http.StatusOK {
		t.Errorf("agent joining: %d", w.Code)
	}
	<-up.got
}

func TestGatewayDeviceFilesNeedAFilesGrant(t *testing.T) {
	up := newUpstream(t)
	g := newTestGateway(t, up.URL, true)
	session := uuid.New()
	g.remember("grant-cookie", session)
	g.granted = grantsFor(session, "node//files files", "node//desk desktop")
	get := func(method, q string, upgrade bool) int {
		r := httptest.NewRequest(method, "https://mesh.example.com/devicefile.ashx?"+q, nil)
		r.Header.Set("Sec-Fetch-Mode", "cors")
		if upgrade {
			r.Header.Set("Connection", "Upgrade")
			r.Header.Set("Upgrade", "websocket")
		}
		r.AddCookie(&http.Cookie{Name: g.CookieName(), Value: "grant-cookie"})
		return serve(g, r).Code
	}
	if c := get(http.MethodGet, "c=cookie&m=mesh&n=files&f=/etc/hostname", false); c != http.StatusOK {
		t.Errorf("download with a files grant: %d", c)
	}
	<-up.got
	for _, c := range []struct {
		method, q string
		upgrade   bool
		want      int
	}{
		{http.MethodGet, "c=cookie&n=desk&f=/etc/hostname", false, http.StatusForbidden},
		{http.MethodGet, "c=cookie&n=other&f=/etc/hostname", false, http.StatusForbidden},
		{http.MethodGet, "c=cookie&f=/etc/hostname", false, http.StatusForbidden},
		{http.MethodGet, "c=cookie&n=files&n=desk&f=/x", false, http.StatusForbidden},
		{http.MethodGet, "c=cookie&n=files&n[]=desk&f=/x", false, http.StatusForbidden},
		{http.MethodGet, "c=cookie&n=node/x/files&f=/x", false, http.StatusForbidden},
		{http.MethodGet, "id=t1&n=files", true, http.StatusForbidden},
		{http.MethodPost, "c=cookie&n=files&f=/x", false, http.StatusForbidden},
		{http.MethodGet, "c=cookie&n=broken&f=/x", false, http.StatusInternalServerError},
	} {
		if got := get(c.method, c.q, c.upgrade); got != c.want {
			t.Errorf("%s %s (WebSocket %v): %d, want %d", c.method, c.q, c.upgrade, got, c.want)
		}
	}
	// Uploads to devices are never forwarded.
	for _, p := range []string{"/uploadfilebatch.ashx", "/uploadfile.ashx", "/UploadFileBatch.ashx"} {
		r := httptest.NewRequest(http.MethodPost, "https://mesh.example.com"+p, nil)
		r.AddCookie(&http.Cookie{Name: g.CookieName(), Value: "grant-cookie"})
		if c := serve(g, r).Code; c != http.StatusForbidden {
			t.Errorf("%s: %d", p, c)
		}
	}
	select {
	case r := <-up.got:
		t.Fatalf("forwarded %s", r.URL)
	default:
	}
}
