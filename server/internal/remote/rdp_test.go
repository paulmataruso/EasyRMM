package remote

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
)

func TestRDPCheck(t *testing.T) {
	g := newTestGateway(t, "http://127.0.0.1:1", true)
	session := uuid.New()
	g.granted = func(_ context.Context, s uuid.UUID, node string, kind Kind) (bool, error) {
		if node == "node//broken" {
			return false, errors.New("database down")
		}
		return s == session && node == "node//granted" && kind == KindRDP, nil
	}
	infos := func(ip string) string {
		return `["infos",{"ip":"` + ip + `","port":3389,"screen":{"width":1280,"height":720},"domain":"","username":"admin","password":"x","options":{}}]`
	}
	for name, msgs := range map[string][]string{
		"granted device, then input": {infos("node//granted"), `["mouse",10,10,0,false]`, `["scancode",29,true]`, `["clipboard","x"]`, `["pong"]`},
		"device id without a prefix": {infos("node/node//granted")},
	} {
		check := g.rdpCheck(context.Background(), session)
		for _, m := range msgs {
			if err := check([]byte(m)); err != nil && name == "granted device, then input" {
				t.Errorf("%s: %s refused: %v", name, m, err)
			}
		}
	}
	for name, msgs := range map[string][]string{
		"not JSON":          {`hello`},
		"empty array":       {`[]`},
		"no action":         {`[1,{}]`},
		"input first":       {`["mouse",1,1,0,false]`},
		"no details":        {`["infos"]`},
		"cookie":            {infos("eyJjb29raWUiOnRydWV9")},
		"malformed node":    {infos("node//a/b")},
		"no grant":          {infos("node//other")},
		"other session":     {infos("node//granted")},
		"grant check fails": {infos("node//broken")},
		"second request":    {infos("node//granted"), infos("node//granted")},
	} {
		s := session
		if name == "other session" {
			s = uuid.New()
		}
		check := g.rdpCheck(context.Background(), s)
		var err error
		for _, m := range msgs {
			if err = check([]byte(m)); err != nil {
				break
			}
		}
		if !errors.Is(err, errRefused) {
			t.Errorf("%s: %v, want refused", name, err)
		}
	}
	g.granted = nil
	if err := g.rdpCheck(context.Background(), session)([]byte(infos("node//granted"))); !errors.Is(err, errRefused) {
		t.Errorf("without a grant check: %v", err)
	}
}

// Through the gateway: MeshCentral's RDP relay is reached only with a grant
// cookie, as a WebSocket, and hears only a request for a device with an RDP
// grant.
func TestGatewayRDPRelay(t *testing.T) {
	got := make(chan string, 8)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = ws.CloseNow() }()
		for {
			_, data, err := ws.Read(context.Background())
			if err != nil {
				got <- "closed"
				return
			}
			got <- string(data)
		}
	}))
	defer upstream.Close()
	g := newTestGateway(t, upstream.URL, false)
	session := uuid.New()
	g.remember("grant-cookie", session)
	g.granted = func(_ context.Context, s uuid.UUID, node string, kind Kind) (bool, error) {
		return s == session && node == "node//granted" && kind == KindRDP, nil
	}
	srv := httptest.NewServer(g)
	defer srv.Close()

	// A plain request, and one without a grant cookie, never reach it.
	r := httptest.NewRequest(http.MethodGet, "https://mesh.example.com/mstscrelay.ashx", nil)
	r.Header.Set("Origin", "https://mesh.example.com")
	r.AddCookie(&http.Cookie{Name: g.CookieName(), Value: "grant-cookie"})
	if w := serve(g, r); w.Code != http.StatusForbidden {
		t.Errorf("RDP relay without a WebSocket: %d", w.Code)
	}
	dial := func(cookie bool) (*websocket.Conn, error) {
		h := http.Header{"Origin": {srv.URL}}
		if cookie {
			h.Set("Cookie", g.CookieName()+"=grant-cookie")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		//nolint:bodyclose // coder/websocket owns the handshake response body
		ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/mstscrelay.ashx", &websocket.DialOptions{HTTPHeader: h})
		return ws, err
	}
	if ws, err := dial(false); err == nil {
		_ = ws.CloseNow()
		t.Error("RDP relay without a grant cookie connected")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ws, err := dial(true)
	if err != nil {
		t.Fatal(err)
	}
	ok := `["infos",{"ip":"node//granted","port":3389}]`
	_ = ws.Write(ctx, websocket.MessageText, []byte(ok))
	_ = ws.Write(ctx, websocket.MessageText, []byte(`["scancode",29,true]`))
	for _, want := range []string{ok, `["scancode",29,true]`} {
		select {
		case m := <-got:
			if m != want {
				t.Fatalf("MeshCentral got %q, want %q", m, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("MeshCentral never got %q", want)
		}
	}
	_ = ws.CloseNow()
	<-got // closed

	ws, err = dial(true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ws.CloseNow() }()
	_ = ws.Write(ctx, websocket.MessageText, []byte(`["infos",{"ip":"node//other","port":3389}]`))
	select {
	case m := <-got:
		if m != "closed" {
			t.Fatalf("MeshCentral got %q for a device without an RDP grant", m)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the relay stayed open")
	}
}
