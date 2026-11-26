package remote

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
)

// wsFrame is one frame of a client's WebSocket stream, as a server reads it.
type wsFrame struct {
	fin     bool
	op      byte
	key     [4]byte
	payload []byte // unmasked
	raw     []byte
	form    int // 7, 16 or 64: the length form the sender used
}

// readClientFrames parses a client's stream strictly: reserved bits clear,
// masked, and the shortest length form for the size.
func readClientFrames(b []byte) ([]wsFrame, error) {
	var out []wsFrame
	for len(b) > 0 {
		start := b
		if len(b) < 2 {
			return nil, errors.New("short header")
		}
		f := wsFrame{fin: b[0]&0x80 != 0, op: b[0] & 0xf}
		if b[0]&0x70 != 0 {
			return nil, errors.New("reserved bits")
		}
		if b[1]&0x80 == 0 {
			return nil, errors.New("unmasked")
		}
		n, hl := uint64(b[1]&0x7f), 2
		f.form = 7
		switch n {
		case 126:
			if len(b) < 4 {
				return nil, errors.New("short")
			}
			n, hl, f.form = uint64(binary.BigEndian.Uint16(b[2:4])), 4, 16
			if n <= 125 {
				return nil, errors.New("16-bit form for a small frame")
			}
		case 127:
			if len(b) < 10 {
				return nil, errors.New("short")
			}
			n, hl, f.form = binary.BigEndian.Uint64(b[2:10]), 10, 64
			if n <= 0xffff {
				return nil, errors.New("64-bit form for a small frame")
			}
		}
		if uint64(len(b)) < uint64(hl)+4+n {
			return nil, errors.New("short payload")
		}
		copy(f.key[:], b[hl:hl+4])
		body := b[hl+4 : hl+4+int(n)]
		f.payload = make([]byte, n)
		for i := range body {
			f.payload[i] = body[i] ^ f.key[i&3]
		}
		f.raw = start[:hl+4+int(n)]
		b = b[hl+4+int(n):]
		out = append(out, f)
	}
	return out, nil
}

// maskedFrame builds a client frame with the given key and length form.
func maskedFrame(fin bool, op byte, payload []byte, key [4]byte) []byte {
	var b bytes.Buffer
	first := op
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
	b.Write(key[:])
	for i, c := range payload {
		b.WriteByte(c ^ key[i&3])
	}
	return b.Bytes()
}

// savedOpener opens one credential for the tests.
type savedOpener struct {
	mu   sync.Mutex
	cred OpenedCredential
	err  error
	uses []CredentialUse
}

func (o *savedOpener) OpenRDPCredential(_ context.Context, u CredentialUse) (*OpenedCredential, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.uses = append(o.uses, u)
	if o.err != nil {
		return nil, o.err
	}
	c := o.cred
	c.Password = append([]byte(nil), o.cred.Password...)
	return &c, nil
}

func (o *savedOpener) set(pw string, err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.cred.Password, o.err = []byte(pw), err
}

func (o *savedOpener) used() []CredentialUse {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]CredentialUse(nil), o.uses...)
}

const savedID = "0d3b8a52-6f0e-4a7e-9c0a-0b5f3a1d2e44"

func infosWith(ip, user, pass, options string) string {
	return fmt.Sprintf(`["infos",{"ip":%q,"port":3389,"screen":{"width":1280,"height":720},"domain":"","username":%q,"password":%q,"options":%s,"locale":"en-US"}]`,
		ip, user, pass, options)
}

func openSaved(pass string) func(uuid.UUID, string) (*OpenedCredential, error) {
	return func(uuid.UUID, string) (*OpenedCredential, error) {
		return &OpenedCredential{Domain: "CORP", Username: "admin", Password: []byte(pass)}, nil
	}
}

func TestRewriteInfosForcesMeshCentralSavingOff(t *testing.T) {
	noOpen := func(uuid.UUID, string) (*OpenedCredential, error) { return nil, errors.New("must not open") }
	for _, options := range []string{`{}`, `null`, `{"savepass":true}`, `{"useServerCreds":true,"savepass":true,"flags":8}`} {
		out, err := rewriteInfos([]byte(infosWith("node//n1", "tech", "typed pw", options)), noOpen)
		if err != nil {
			t.Fatalf("%s: %v", options, err)
		}
		var m []json.RawMessage
		if err := json.Unmarshal(out, &m); err != nil {
			t.Fatalf("%s: %v", options, err)
		}
		var obj struct {
			Password string `json:"password"`
			Username string `json:"username"`
			Port     int    `json:"port"`
			Options  struct {
				Savepass       *bool `json:"savepass"`
				UseServerCreds *bool `json:"useServerCreds"`
				Flags          int   `json:"flags"`
			} `json:"options"`
		}
		if err := json.Unmarshal(m[1], &obj); err != nil {
			t.Fatal(err)
		}
		o := obj.Options
		if o.Savepass == nil || *o.Savepass || o.UseServerCreds == nil || *o.UseServerCreds {
			t.Errorf("%s: saving not forced off: %s", options, out)
		}
		// A typed credential passes through.
		if obj.Password != "typed pw" || obj.Username != "tech" || obj.Port != 3389 {
			t.Errorf("%s: typed credential changed: %s", options, out)
		}
		if strings.Contains(options, "flags") && o.Flags != 8 {
			t.Errorf("other options lost: %s", out)
		}
	}
	if _, err := rewriteInfos([]byte(`["infos",{"ip":"node//n","options":[1]}]`), noOpen); !errors.Is(err, errRefused) {
		t.Errorf("options that are not an object: %v", err)
	}
}

func TestRewriteInfosInjectsTheSavedCredential(t *testing.T) {
	pass := "p\"a\\ss\né世\x01</script>"
	var gotNode string
	var gotID uuid.UUID
	out, err := rewriteInfos([]byte(infosWith("node//n1", "", "", `{"useSavedCredential":"`+savedID+`","savepass":true}`)),
		func(id uuid.UUID, node string) (*OpenedCredential, error) {
			gotID, gotNode = id, node
			return &OpenedCredential{Domain: "CORP", Username: "admin", Password: []byte(pass)}, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if gotID.String() != savedID || gotNode != "node//n1" {
		t.Errorf("opened %s for %q", gotID, gotNode)
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(out, &arr); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	var obj struct {
		Domain, Username, Password string
		IP                         string `json:"ip"`
		Options                    map[string]any
	}
	if err := json.Unmarshal(arr[1], &obj); err != nil {
		t.Fatal(err)
	}
	if obj.Password != pass || obj.Domain != "CORP" || obj.Username != "admin" || obj.IP != "node//n1" {
		t.Errorf("credential not injected: %s", out)
	}
	if _, ok := obj.Options[useSavedKey]; ok {
		t.Error("the saved credential id was forwarded")
	}
	if obj.Options["savepass"] != false || obj.Options["useServerCreds"] != false {
		t.Errorf("saving not forced off: %v", obj.Options)
	}
	for _, bad := range []string{`"nope"`, `5`, `""`} {
		if _, err := rewriteInfos([]byte(infosWith("node//n1", "", "", `{"useSavedCredential":`+bad+`}`)), openSaved("x")); !errors.Is(err, errRefused) {
			t.Errorf("id %s: %v", bad, err)
		}
	}
	if _, err := rewriteInfos([]byte(infosWith("eyJjb29raWUi", "", "", `{"useSavedCredential":"`+savedID+`"}`)), openSaved("x")); !errors.Is(err, errRefused) {
		t.Errorf("a cookie as the address: %v", err)
	}
}

func TestBuildTextFrameLengthForms(t *testing.T) {
	for _, n := range []int{0, 1, 124, 125, 126, 127, 65534, 65535, 65536, 65537, 200000} {
		payload := bytes.Repeat([]byte("a"), n)
		f, err := buildTextFrame(payload)
		if err != nil {
			t.Fatal(err)
		}
		frames, err := readClientFrames(f)
		if err != nil || len(frames) != 1 {
			t.Fatalf("%d: %v", n, err)
		}
		want := 7
		switch {
		case n > 0xffff:
			want = 64
		case n > 125:
			want = 16
		}
		got := frames[0]
		if !got.fin || got.op != 1 || got.form != want || !bytes.Equal(got.payload, payload) {
			t.Errorf("%d: fin %v op %d form %d (want %d)", n, got.fin, got.op, got.form, want)
		}
	}
	if _, err := buildTextFrame(make([]byte, maxControlMessage+1)); !errors.Is(err, errRefused) {
		t.Errorf("a replacement over the cap: %v", err)
	}
	a, _ := buildTextFrame([]byte("same payload"))
	seen := map[[4]byte]bool{}
	for range 64 {
		b, _ := buildTextFrame([]byte("same payload"))
		seen[[4]byte(b[2:6])] = true
	}
	if len(seen) < 60 || bytes.Equal(a[2:6], []byte{0, 0, 0, 0}) {
		t.Errorf("mask keys repeat: %d distinct in 64", len(seen))
	}
}

// A saved password that moves the message across the length boundaries is
// read back correctly by a standard WebSocket reader behind the gateway.
func TestGatewayRDPSavedCredentialSizes(t *testing.T) {
	got := make(chan string, 8)
	g, srv := rdpRig(t, got)
	opener := &savedOpener{cred: OpenedCredential{Domain: "CORP", Username: "admin"}}
	g.SetCredentialOpener(opener)

	base := len(mustRewrite(t, "")) // the message with an empty password
	for _, target := range []int{base, base + 1, 65534, 65535, 65536, 65537, 300000} {
		pw := strings.Repeat("p", target-base)
		opener.set(pw, nil)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		ws := dialRDP(t, ctx, srv, g)
		if err := ws.Write(ctx, websocket.MessageText, []byte(infosWith("node//granted", "", "", `{"useSavedCredential":"`+savedID+`"}`))); err != nil {
			t.Fatal(err)
		}
		select {
		case m := <-got:
			var arr []json.RawMessage
			if err := json.Unmarshal([]byte(m), &arr); err != nil {
				t.Fatalf("%d (base %d): %v (%d uses, got %.60q)", target, base, err, len(opener.used()), m)
			}
			var obj struct{ Password string }
			_ = json.Unmarshal(arr[1], &obj)
			if obj.Password != pw {
				t.Errorf("target %d: password of %d bytes arrived as %d", target, len(pw), len(obj.Password))
			}
			if want := target; len(m) != want {
				t.Errorf("message of %d bytes, want %d", len(m), want)
			}
		case <-ctx.Done():
			t.Fatalf("target %d: nothing arrived", target)
		}
		_ = ws.CloseNow()
		select { // the upstream reports the end of the connection
		case <-got:
		case <-ctx.Done():
		}
		cancel()
	}
	use := opener.used()[0]
	if use.Device == uuid.Nil || use.User == uuid.Nil || use.Organization == uuid.Nil || use.Session == uuid.Nil {
		t.Errorf("the use lacks the grant's identity: %+v", use)
	}
}

func mustRewrite(t *testing.T, pass string) []byte {
	t.Helper()
	out, err := rewriteInfos([]byte(infosWith("node//granted", "", "", `{"useSavedCredential":"`+savedID+`"}`)), func(uuid.UUID, string) (*OpenedCredential, error) {
		return &OpenedCredential{Domain: "CORP", Username: "admin", Password: []byte(pass)}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func rdpRig(t *testing.T, got chan string) (*Gateway, *httptest.Server) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = ws.CloseNow() }()
		ws.SetReadLimit(-1)
		for {
			_, data, err := ws.Read(context.Background())
			if err != nil {
				got <- "closed"
				return
			}
			got <- string(data)
		}
	}))
	t.Cleanup(upstream.Close)
	g := newTestGateway(t, upstream.URL, false)
	g.log = slog.New(slog.NewTextHandler(testWriter{t}, nil))
	session := uuid.New()
	g.remember("grant-cookie", session)
	grant := rdpGrant{Grant: uuid.New(), User: uuid.New(), Organization: uuid.New(), Site: uuid.New(), Device: uuid.New(), ClientIP: "192.0.2.7"}
	g.granted = func(_ context.Context, s uuid.UUID, node string, kind Kind) (bool, error) {
		return s == session && node == "node//granted" && kind == KindRDP, nil
	}
	g.rdpGrantFor = func(_ context.Context, s uuid.UUID, node string) (rdpGrant, error) {
		if s != session || node != "node//granted" {
			return rdpGrant{}, errors.New("no grant")
		}
		return grant, nil
	}
	srv := httptest.NewServer(g)
	t.Cleanup(srv.Close)
	return g, srv
}

func dialRDP(t *testing.T, ctx context.Context, srv *httptest.Server, g *Gateway) *websocket.Conn {
	t.Helper()
	h := http.Header{"Origin": {srv.URL}, "Cookie": {g.CookieName() + "=grant-cookie"}}
	//nolint:bodyclose // coder/websocket owns the handshake response body
	ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/mstscrelay.ashx", &websocket.DialOptions{HTTPHeader: h})
	if err != nil {
		t.Fatal(err)
	}
	ws.SetReadLimit(-1)
	return ws
}

func TestGatewayRDPSavedCredentialRules(t *testing.T) {
	got := make(chan string, 8)
	g, srv := rdpRig(t, got)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	next := func() string {
		select {
		case m := <-got:
			return m
		case <-ctx.Done():
			t.Fatal("nothing arrived")
			return ""
		}
	}
	saved := infosWith("node//granted", "", "", `{"useSavedCredential":"`+savedID+`"}`)

	// Without an opener a saved credential is refused and nothing reaches
	// MeshCentral.
	ws := dialRDP(t, ctx, srv, g)
	_ = ws.Write(ctx, websocket.MessageText, []byte(saved))
	if m := next(); m != "closed" {
		t.Errorf("a saved credential without an opener reached MeshCentral: %s", m)
	}

	// An opener that refuses (another person's credential, no step-up).
	opener := &savedOpener{err: errors.New("not yours")}
	g.SetCredentialOpener(opener)
	ws = dialRDP(t, ctx, srv, g)
	_ = ws.Write(ctx, websocket.MessageText, []byte(saved))
	if m := next(); m != "closed" {
		t.Errorf("a refused credential reached MeshCentral: %s", m)
	}
	if u := opener.used(); len(u) != 1 || u[0].CredentialID.String() != savedID {
		t.Errorf("uses: %+v", u)
	}

	// A typed credential passes with saving forced off, and later messages
	// pass untouched. The browser's own savepass is overridden.
	opener.set("", nil)
	ws = dialRDP(t, ctx, srv, g)
	_ = ws.Write(ctx, websocket.MessageText, []byte(infosWith("node//granted", "tech", "typed", `{"savepass":true,"useServerCreds":true}`)))
	m := next()
	if !strings.Contains(m, `"savepass":false`) || !strings.Contains(m, `"useServerCreds":false`) || !strings.Contains(m, `"password":"typed"`) {
		t.Errorf("typed credential forwarded as %s", m)
	}
	_ = ws.Write(ctx, websocket.MessageText, []byte(`["scancode",29,true]`))
	if m := next(); m != `["scancode",29,true]` {
		t.Errorf("later message changed: %s", m)
	}
	// A second connection request is refused.
	_ = ws.Write(ctx, websocket.MessageText, []byte(saved))
	if m := next(); m != "closed" {
		t.Errorf("a second infos reached MeshCentral: %s", m)
	}
	if n := len(opener.used()); n != 1 {
		t.Errorf("the second request opened a credential: %d uses", n)
	}
}

// The browser sends the first message in fragments, with a ping between
// them; MeshCentral gets one message, and what follows it is untouched.
func TestWSGuardFragmentedInfos(t *testing.T) {
	msg := []byte(infosWith("node//granted", "", "", `{"useSavedCredential":"`+savedID+`"}`))
	rest := maskedFrame(true, 0x1, []byte(`["scancode",29,true]`), [4]byte{9, 8, 7, 6})
	var in bytes.Buffer
	in.Write(maskedFrame(false, 0x1, msg[:20], [4]byte{1, 2, 3, 4}))
	in.Write(maskedFrame(true, 0x9, []byte("hi"), [4]byte{5, 5, 5, 5}))
	in.Write(maskedFrame(false, 0x0, msg[20:90], [4]byte{4, 3, 2, 1}))
	in.Write(maskedFrame(true, 0x0, msg[90:], [4]byte{0, 0, 0, 1}))
	in.Write(rest)

	pw := strings.Repeat("s3cret!", 40)
	g := newWSGuard(bytes.NewReader(in.Bytes()), func([]byte) error { return nil }).
		withTransform(func(m []byte) ([]byte, error) { return rewriteInfos(m, openSaved(pw)) })
	out, err := io.ReadAll(g)
	if err != nil {
		t.Fatal(err)
	}
	frames, err := readClientFrames(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 3 || frames[0].op != 9 || frames[1].op != 1 || !frames[1].fin {
		t.Fatalf("frames: %d, first ops %v", len(frames), frames[0].op)
	}
	if !bytes.Contains(frames[1].payload, []byte(pw)) || bytes.Contains(frames[1].payload, []byte(savedID)) {
		t.Errorf("rewritten message: %s", frames[1].payload)
	}
	if !bytes.Equal(frames[2].raw, rest) {
		t.Error("the stream after the first message changed")
	}
	if bytes.Contains(out[:len(out)-len(rest)], []byte(pw)) && !bytes.Contains(frames[1].payload, []byte(pw)) {
		t.Error("password outside the rewritten frame")
	}
}

func TestWSGuardTransformRefusalClosesAndOversizeIsRefused(t *testing.T) {
	msg := []byte(infosWith("node//granted", "", "", `{"useSavedCredential":"`+savedID+`"}`))
	in := maskedFrame(true, 0x1, msg, [4]byte{1, 2, 3, 4})
	g := newWSGuard(bytes.NewReader(in), func([]byte) error { return nil }).
		withTransform(func(m []byte) ([]byte, error) {
			return rewriteInfos(m, func(uuid.UUID, string) (*OpenedCredential, error) {
				return &OpenedCredential{Username: "u", Password: make([]byte, maxControlMessage)}, nil
			})
		})
	out, err := io.ReadAll(g)
	if !errors.Is(err, errRefused) || len(out) != 0 {
		t.Errorf("an oversize replacement: %d bytes out, %v", len(out), err)
	}
}

// Whatever the frame splits, mask keys and bodies, the output is a valid
// stream, the stream after the first message is byte-identical, and the
// password appears only in the rewritten frame.
func FuzzWSGuardRewrite(f *testing.F) {
	f.Add(int64(1), uint8(3), "p@ss", "tech", 20)
	f.Add(int64(2), uint8(1), strings.Repeat("x", 70000), "u", 0)
	f.Add(int64(3), uint8(9), "\"\\\né", "", 126)
	f.Fuzz(func(t *testing.T, seed int64, parts uint8, pw, user string, padLen int) {
		if len(pw) > 200000 || len(user) > 1000 || padLen < 0 || padLen > 70000 {
			t.Skip()
		}
		rng := rand.New(rand.NewSource(seed))
		secret := "SECRET-" + strings.ToValidUTF8(pw, "?")
		extra, _ := json.Marshal(strings.Repeat("e", padLen))
		msg := []byte(`["infos",{"ip":"node//granted","port":3389,"extra":` + string(extra) +
			`,"username":` + quoteJSON(user) + `,"password":"","options":{"useSavedCredential":"` + savedID + `"}}]`)
		// Split the message into fragments with random keys and pings between.
		var in bytes.Buffer
		cuts := []int{0}
		for i := 0; i < int(parts%6); i++ {
			cuts = append(cuts, rng.Intn(len(msg)+1))
		}
		cuts = append(cuts, len(msg))
		sortInts(cuts)
		op := byte(1)
		for i := 0; i+1 < len(cuts); i++ {
			var key [4]byte
			rng.Read(key[:])
			in.Write(maskedFrame(i+2 == len(cuts), op, msg[cuts[i]:cuts[i+1]], key))
			op = 0
			if rng.Intn(3) == 0 && i+2 < len(cuts) {
				in.Write(maskedFrame(true, 0x9, []byte("p"), key))
			}
		}
		var restKey [4]byte
		rng.Read(restKey[:])
		rest := append(maskedFrame(true, 0x1, []byte(`["mouse",1,2,0,false]`), restKey), maskedFrame(true, 0x2, bytes.Repeat([]byte{7}, rng.Intn(300)), restKey)...)
		in.Write(rest)
		inBytes := in.Bytes()

		g := newWSGuard(bytes.NewReader(inBytes), func([]byte) error { return nil }).
			withTransform(func(m []byte) ([]byte, error) { return rewriteInfos(m, openSaved(secret)) })
		out, err := io.ReadAll(g)
		if err != nil {
			t.Fatal(err)
		}
		frames, err := readClientFrames(out)
		if err != nil {
			t.Fatalf("output is not a valid stream: %v", err)
		}
		var first *wsFrame
		var firstEnd int
		off := 0
		for i := range frames {
			off += len(frames[i].raw)
			if frames[i].op == 1 && first == nil {
				first, firstEnd = &frames[i], off
			}
		}
		if first == nil || !first.fin {
			t.Fatal("no rewritten message")
		}
		var arr []json.RawMessage
		if err := json.Unmarshal(first.payload, &arr); err != nil {
			t.Fatalf("rewritten message is not JSON: %v", err)
		}
		var obj struct{ Password string }
		_ = json.Unmarshal(arr[1], &obj)
		if obj.Password != secret {
			t.Fatal("password did not survive the rewrite")
		}
		// The tail after the first message is the input's, byte for byte.
		if !bytes.HasSuffix(out, rest) || len(out)-firstEnd < len(rest) {
			t.Fatal("the stream after the first message changed")
		}
		if bytes.Contains(out[firstEnd:], []byte(secret)) || bytes.Contains(inBytes, []byte(secret)) {
			t.Fatal("password outside the rewritten frame")
		}
	})
}

func quoteJSON(s string) string {
	b, _ := json.Marshal(strings.ToValidUTF8(s, "?"))
	return string(b)
}

func sortInts(a []int) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}

func TestAppendJSONString(t *testing.T) {
	for _, s := range []string{"", "plain", "q\"uote", `back\slash`, "tab\tnl\n\x00\x1f", "é世\U0001F600", "  ", "</script>"} {
		got := appendJSONString(nil, []byte(s))
		var back string
		if err := json.Unmarshal(got, &back); err != nil || back != s {
			t.Errorf("%q: %s -> %q, %v", s, got, back, err)
		}
	}
	got := appendJSONString(nil, []byte{'a', 0xff, 'b'})
	var back string
	if err := json.Unmarshal(got, &back); err != nil || back != "a�b" {
		t.Errorf("invalid UTF-8: %s %v", got, err)
	}
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimSpace(string(p)))
	return len(p), nil
}

func TestWithSavedCredential(t *testing.T) {
	const rdp = "/?gotonode=abc&viewmode=11&hide=63&rdp=1&login=tok"
	const id = "0D3B8A52-6F0E-4A7E-9C0A-0B5F3A1D2E44"
	if got := withSavedCredential(rdp, id); got != rdp+"&rdpcred=0d3b8a52-6f0e-4a7e-9c0a-0b5f3a1d2e44" {
		t.Errorf("rdp: %s", got)
	}
	const desktop = "/?gotonode=abc&viewmode=11&hide=63&login=tok"
	for name, c := range map[string][2]string{
		"not RDP":       {desktop, id},
		"no id":         {rdp, ""},
		"not an id":     {rdp, "abc&x=1"},
		"braces":        {rdp, "{" + id + "}"},
		"urn":           {rdp, "urn:uuid:" + id},
		"no hyphens":    {rdp, strings.ReplaceAll(id, "-", "")},
		"extra content": {rdp, id + "&a=b"},
	} {
		if got := withSavedCredential(c[0], c[1]); got != c[0] {
			t.Errorf("%s: %s", name, got)
		}
	}
}
