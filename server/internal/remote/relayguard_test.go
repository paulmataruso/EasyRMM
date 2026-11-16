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
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestBrowserRelay(t *testing.T) {
	ok := map[string]string{
		"browser=1&p=2&nodeid=node//abc$@9&id=t1&auth=x": "node//abc$@9",
		"p=1&nodeid=node/domain/abc&id=t1":               "",
		"p=5&nodeid=abc&id=t1":                           "node//abc",
		"p=8&nodeid=node//abc&id=t1":                     "node//abc",
	}
	for q, want := range ok {
		v, _ := url.ParseQuery(q)
		got, err := browserRelay(v)
		if want == "" {
			if err == nil {
				t.Errorf("%s: accepted a node id with a domain", q)
			}
			continue
		}
		if err != nil || got != want {
			t.Errorf("%s: %q, %v", q, got, err)
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
	} {
		v, _ := url.ParseQuery(q)
		if _, err := browserRelay(v); !errors.Is(err, errRefused) {
			t.Errorf("%s: accepted (%v)", q, err)
		}
	}
}

func TestAgentRelayRefused(t *testing.T) {
	v, _ := url.ParseQuery("p=1&nodeid=node//abc&id=t1&rauth=r")
	if err := agentRelayRefused(v); err != nil {
		t.Errorf("agent joining a relay refused: %v", err)
	}
	for _, q := range []string{"id=t1&auth=x", "id=t1&Auth=x", "id=t1&tcpport=22", "id=t1&user=a&pass=b", "id=t1&key=k"} {
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
	r := httptest.NewRequest(http.MethodGet, "https://mesh.example.com/meshrelay.ashx?p=1&nodeid=node//abc&id=t1&rauth=r", nil)
	r.Header.Set("Cookie", "xid=meshcentral-session; xid.sig=s")
	r.Header.Set("X-MeshAuth", "dXNlcg==,cGFzcw==")
	if w := serve(g, r); w.Code != http.StatusOK {
		t.Fatalf("agent joining a relay: %d %q", w.Code, w.Body.String())
	}
	in := <-up.got
	if in.Header.Get("Cookie") != "" || in.Header.Get("X-MeshAuth") != "" {
		t.Errorf("forwarded credentials: %v", in.Header)
	}
	for _, q := range []string{"id=t1&auth=cookie", "p=1&nodeid=node//abc&tcpport=3389"} {
		w := serve(g, httptest.NewRequest(http.MethodGet, "https://mesh.example.com/meshrelay.ashx?"+q, nil))
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
	g.granted = func(_ context.Context, s uuid.UUID, nodeID string) (bool, error) {
		asked = append(asked, nodeID)
		if nodeID == "node//broken" {
			return false, errors.New("database down")
		}
		return s == session && nodeID == "node//granted", nil
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
	if c := relay("browser=1&p=2&nodeid=node//granted&id=t1&tcpport=3389"); c != http.StatusForbidden {
		t.Errorf("routing instructions: %d", c)
	}
	if c := relay("browser=1&p=2&nodeid=node//broken&id=t1"); c != http.StatusInternalServerError {
		t.Errorf("failed grant check: %d", c)
	}
	if strings.Join(asked, ",") != "node//granted,node//other,node//broken" {
		t.Errorf("grant checks = %v", asked)
	}
	// Without a grant check (no remote service), relays are refused.
	g.granted = nil
	if c := relay("browser=1&p=2&nodeid=node//granted&id=t1"); c != http.StatusForbidden {
		t.Errorf("no grant check: %d", c)
	}
}
