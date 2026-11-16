package remote

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPressureEndpoint(t *testing.T) {
	g := newTestGateway(t, "http://127.0.0.1:1", true)
	session := uuid.New()
	g.remember("grant-cookie", session)
	asked := 0
	g.granted = func(_ context.Context, s uuid.UUID, node string, kind Kind) (bool, error) {
		asked++
		if node == "node//broken" {
			return false, errors.New("database down")
		}
		return s == session && node == "node//abc" && kind == KindDesktop, nil
	}
	get := func(method, query string, cookie bool) (int, map[string]any) {
		r := httptest.NewRequest(method, "https://mesh.example.com"+PressurePath+"?"+query, nil)
		if cookie {
			r.AddCookie(&http.Cookie{Name: g.CookieName(), Value: "grant-cookie"})
		}
		w := serve(g, r)
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: Cache-Control %q", query, w.Header().Get("Cache-Control"))
		}
		var body map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		return w.Code, body
	}

	if c, _ := get(http.MethodGet, "node=node//abc", false); c != http.StatusForbidden {
		t.Errorf("without a grant cookie: %d", c)
	}
	if c, _ := get(http.MethodPost, "node=node//abc", true); c != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", c)
	}
	if c, _ := get(http.MethodGet, "node=node/x/y/z", true); c != http.StatusBadRequest {
		t.Errorf("malformed node: %d", c)
	}
	if c, _ := get(http.MethodGet, "node=node//other", true); c != http.StatusForbidden {
		t.Errorf("device without a desktop grant: %d", c)
	}
	if c, _ := get(http.MethodGet, "node=node//broken", true); c != http.StatusInternalServerError {
		t.Errorf("failed grant check: %d", c)
	}
	c, body := get(http.MethodGet, "node=node//abc", true)
	if c != http.StatusOK || body["held"] != float64(0) || body["active"] != false {
		t.Errorf("no relay yet: %d %v", c, body)
	}

	// Two relays for the device share one counter until the last closes.
	p := g.holdPressure("node//abc")
	if g.holdPressure("node//abc") != p {
		t.Fatal("a second relay got its own counter")
	}
	p.held.Add(int64(1500 * time.Millisecond))
	before := asked
	if c, body := get(http.MethodGet, "node=abc", true); c != http.StatusOK || body["held"] != float64(1500) || body["active"] != true {
		t.Errorf("held pictures: %d %v", c, body)
	}
	if asked != before {
		t.Error("the desktop grant was looked up again within the cache lifetime")
	}
	g.releasePressure("node//abc", p)
	if _, active := g.heldFor("node//abc"); !active {
		t.Error("counter forgotten while a relay is open")
	}
	g.releasePressure("node//abc", p)
	if _, active := g.heldFor("node//abc"); active {
		t.Error("counter kept after the last relay closed")
	}

	// Expired grant checks are swept, and checked again.
	g.mu.Lock()
	for k := range g.grants {
		g.grants[k] = time.Now().Add(-time.Second)
	}
	g.mu.Unlock()
	g.sweep(context.Background())
	g.mu.Lock()
	left := len(g.grants)
	g.mu.Unlock()
	if left != 0 {
		t.Errorf("%d expired grant checks kept", left)
	}
	g.granted = nil
	if c, _ := get(http.MethodGet, "node=node//abc", true); c != http.StatusForbidden {
		t.Errorf("without a grant check: %d", c)
	}
}
