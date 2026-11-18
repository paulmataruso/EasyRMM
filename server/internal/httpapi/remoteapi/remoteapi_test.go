package remoteapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/remote"
)

func TestWriteLaunch(t *testing.T) {
	const link = "https://mesh.rmm.example.com/.easyrmm/launch?t=abc"
	for _, c := range []struct {
		origin   *httpapi.Origin
		want     string
		internal bool
	}{
		{nil, link, false},
		{&httpapi.Origin{Console: "https://rmm.example.com", Mesh: "https://mesh.rmm.example.com"}, link, false},
		{&httpapi.Origin{Console: "https://203.0.113.10", Mesh: "https://203.0.113.10:4443"}, "https://203.0.113.10:4443/.easyrmm/launch?t=abc", false},
		{&httpapi.Origin{Console: "https://203.0.113.10", Mesh: "https://203.0.113.10:4443", Pin: "sha256//x"}, "https://203.0.113.10:4443/.easyrmm/launch?t=abc", true},
		{&httpapi.Origin{Console: "https://203.0.113.10"}, link, false}, // remote access off for that origin
	} {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/devices/x/remote-sessions", nil)
		if c.origin != nil {
			r = httpapi.WithOrigin(r, *c.origin)
		}
		w := httptest.NewRecorder()
		writeLaunch(w, r, &remote.Launch{URL: link, Kind: "terminal"})
		var got remote.Launch
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if w.Code != http.StatusCreated || w.Header().Get("Cache-Control") != "no-store" || got.URL != c.want || got.Kind != "terminal" || got.InternalCA != c.internal {
			t.Errorf("origin %+v: %d %q %+v", c.origin, w.Code, w.Header().Get("Cache-Control"), got)
		}
	}
}

func TestOnOrigin(t *testing.T) {
	for _, c := range []struct{ link, origin, want string }{
		{"https://mesh.rmm.example.com/.easyrmm/launch?t=abc", "https://203.0.113.10:4443", "https://203.0.113.10:4443/.easyrmm/launch?t=abc"},
		{"https://mesh.rmm.example.com/.easyrmm/launch?t=abc", "https://[2001:db8::10]:4443", "https://[2001:db8::10]:4443/.easyrmm/launch?t=abc"},
		{"https://mesh.rmm.example.com/.easyrmm/launch?t=abc", "https://mesh.rmm.example.com", "https://mesh.rmm.example.com/.easyrmm/launch?t=abc"},
		{"https://mesh.rmm.example.com/x", "::not a url", "https://mesh.rmm.example.com/x"},
		{"https://mesh.rmm.example.com/x", "", "https://mesh.rmm.example.com/x"},
		{"%zz", "https://203.0.113.10:4443", "%zz"},
	} {
		if got := onOrigin(c.link, c.origin); got != c.want {
			t.Errorf("onOrigin(%q, %q) = %q, want %q", c.link, c.origin, got, c.want)
		}
	}
}
