package easypatch

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
)

// engineSaw is what the engine received.
type engineSaw struct {
	method, target, host string
	header               http.Header
	bodySHA              string
}

func recordingEngine(t *testing.T, answer http.HandlerFunc) (*url.URL, func() []engineSaw) {
	t.Helper()
	var mu sync.Mutex
	var got []engineSaw
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		sum := sha256.Sum256(b)
		mu.Lock()
		got = append(got, engineSaw{r.Method, r.RequestURI, r.Host, r.Header.Clone(), hex.EncodeToString(sum[:])})
		mu.Unlock()
		if answer != nil {
			answer(w, r)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	return u, func() []engineSaw {
		mu.Lock()
		defer mu.Unlock()
		return append([]engineSaw(nil), got...)
	}
}

// agentEdge serves the forwarder the way Handler does: client address
// resolved, origin recorded.
func agentEdge(target *url.URL, trusted []netip.Prefix) http.Handler {
	fwd := NewAgentProxy(target, true, slog.New(slog.DiscardHandler))
	return httpapi.Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fwd.ServeHTTP(w, httpapi.WithOrigin(r, httpapi.Origin{Console: "https://rmm.example.com"}))
	}), httpapi.RealIP(trusted), httpapi.RequestContext(slog.New(slog.DiscardHandler)))
}

func TestAgentPaths(t *testing.T) {
	for p, want := range map[string]bool{
		"/api/v1/agents/check-in":                  true,
		"/api/v1/agents/jobs/0f6b/ack":             true,
		"/downloads/agent/EasyPatchAgent-1.9.msi":  true,
		"/downloads/winget/manifest.yaml":          true,
		"/downloads/install/abc.ps1":               false,
		"/downloads/install/macos/abc.sh":          false,
		"/api/v1/agents":                           false,
		"/api/v1/agentsx/check-in":                 false,
		"/api/v1/organizations":                    false,
		"/api/agent/v1/check-in":                   false,
		"/health/ready":                            false,
		"/downloads/agentx/EasyPatchAgent-1.9.msi": false,
	} {
		if got := AgentPath(p); got != want {
			t.Errorf("%s: %v, want %v", p, got, want)
		}
	}
}

// TestAgentHost: on an imported EasyPatch's name, agents reach the engine
// and people are sent to EasyRMM's patching pages.
func TestAgentHost(t *testing.T) {
	agents := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) })
	h := AgentHost(agents, "https://rmm.example.com/")
	for p, want := range map[string]int{
		"/api/v1/agents/check-in":                 http.StatusTeapot,
		"/downloads/agent/EasyPatchAgent-1.9.msi": http.StatusTeapot,
		"/downloads/winget/manifest.yaml":         http.StatusTeapot,
		"/":                                       http.StatusFound,
		"/endpoints/0f6b?tab=updates":             http.StatusFound,
		"/downloads/install/abc.ps1":              http.StatusFound,
		"/api/v1/organizations":                   http.StatusFound,
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://patch.old.test"+p, nil))
		if rec.Code != want {
			t.Errorf("%s: %d, want %d", p, rec.Code, want)
		}
		if want == http.StatusFound && rec.Header().Get("Location") != "https://rmm.example.com/patching" {
			t.Errorf("%s sent to %q", p, rec.Header().Get("Location"))
		}
	}
}

func TestAgentProxy(t *testing.T) {
	target, got := recordingEngine(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "easyrmm_session=stolen; Path=/")
		w.Header().Add("Set-Cookie", "other=1")
		w.Header().Set("Clear-Site-Data", `"cookies", "storage"`)
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Security-Policy", "default-src *")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "<script>alert(1)</script>")
	})
	edge := httptest.NewServer(agentEdge(target, nil))
	t.Cleanup(edge.Close)

	// What the agent signed reaches the engine as it was sent.
	body := []byte(`{"agentVersion":"1.10.0","activeJobIds":[]}` + "\n")
	const path = "/api/v1/agents/check-in?a=%20b&c=d+e&x"
	req, _ := http.NewRequest("POST", edge.URL+path, bytes.NewReader(body))
	req.Host = "rmm.example.com"
	req.Header.Set("X-EasyPatch-Signature", "sig")
	req.Header.Set("X-Forwarded-For", "198.51.100.66")
	req.Header.Set("X-Forwarded-Host", "evil.example")
	req.Header.Set("Forwarded", "for=198.51.100.66")
	req.Header.Set(StatementHeader, "forged")
	req.Header.Set("Cookie", "easyrmm_session=abc; easyrmm_csrf=def")
	resp, err := edge.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	answer, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	calls := got()
	if len(calls) != 1 {
		t.Fatalf("calls: %+v", calls)
	}
	c := calls[0]
	sum := sha256.Sum256(body)
	if c.method != "POST" || c.target != path || c.bodySHA != hex.EncodeToString(sum[:]) || c.host != "rmm.example.com" {
		t.Errorf("request changed on the way: %+v", c)
	}
	if c.header.Get("X-EasyPatch-Signature") != "sig" {
		t.Error("the agent's signature did not arrive")
	}
	if v := c.header.Values("X-Forwarded-For"); len(v) != 1 || v[0] != "127.0.0.1" {
		t.Errorf("X-Forwarded-For %q: the client's own value was kept", v)
	}
	if c.header.Get("X-Forwarded-Proto") != "https" || c.header.Get("X-Forwarded-Host") != "rmm.example.com" {
		t.Errorf("forwarded proto/host: %v", c.header)
	}
	for _, h := range []string{StatementHeader, "Cookie", "Forwarded"} {
		if c.header.Get(h) != "" {
			t.Errorf("%s reached the engine: %q", h, c.header.Get(h))
		}
	}

	// Nothing the engine answers acts on EasyRMM's origin.
	if resp.StatusCode != http.StatusOK || string(answer) != "<script>alert(1)</script>" {
		t.Errorf("answer %d %q", resp.StatusCode, answer)
	}
	if len(resp.Header.Values("Set-Cookie")) != 0 || resp.Header.Get("Clear-Site-Data") != "" {
		t.Errorf("cookies or site data from the engine: %v", resp.Header)
	}
	if resp.Header.Get("Content-Security-Policy") != "default-src 'none'; frame-ancestors 'none'; sandbox" ||
		resp.Header.Get("X-Content-Type-Options") != "nosniff" || resp.Header.Get("Strict-Transport-Security") == "" {
		t.Errorf("answer not sandboxed: %v", resp.Header)
	}
}

// Behind EasyRMM's own TLS proxy, the engine sees the address EasyRMM
// resolved from it, once, and no address a client claims.
func TestAgentProxyOffload(t *testing.T) {
	target, got := recordingEngine(t, nil)
	edge := httptest.NewServer(agentEdge(target, []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}))
	t.Cleanup(edge.Close)
	req, _ := http.NewRequest("POST", edge.URL+"/api/v1/agents/enroll", strings.NewReader("{}"))
	req.Header.Set("X-Forwarded-For", "198.51.100.66, 203.0.113.7")
	resp, err := edge.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if v := got()[0].header.Values("X-Forwarded-For"); len(v) != 1 || v[0] != "203.0.113.7" {
		t.Errorf("X-Forwarded-For %q", v)
	}
}

func TestAgentProxyRefuses(t *testing.T) {
	target, got := recordingEngine(t, nil)
	edge := httptest.NewServer(agentEdge(target, nil))
	t.Cleanup(edge.Close)
	send := func(method, rawPath string, body io.Reader, size int64) int {
		t.Helper()
		// Raw request lines: the client must not clean the path first.
		c, err := net.Dial("tcp", edge.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		req, _ := http.NewRequest(method, "http://rmm.example.com/", body)
		req.URL = &url.URL{Opaque: rawPath}
		req.ContentLength = size
		if err := req.Write(c); err != nil && !strings.Contains(err.Error(), "broken pipe") && !strings.Contains(err.Error(), "reset") {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(c), req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	// Paths that could mean another path to the engine never leave EasyRMM.
	for _, p := range []string{
		"/api/v1/agents/../organizations",
		"/api/v1/agents/%2e%2e/organizations",
		"/api/v1/agents/..%2forganizations",
		"/downloads/agent/..%5c..%5cappsettings.json",
		"/downloads/agent/./x.msi",
		"/api/v1/agents//check-in",
		"/downloads/winget/%00x",
	} {
		if code := send("GET", p, nil, 0); code != http.StatusBadRequest && code != http.StatusNotFound {
			t.Errorf("%s: %d", p, code)
		}
	}
	if n := len(got()); n != 0 {
		t.Fatalf("%d unclean paths reached the engine: %+v", n, got())
	}

	// 20 MB at most, declared or not.
	if code := send("POST", "/api/v1/agents/inventory", bytes.NewReader(make([]byte, AgentBodyLimit+1)), AgentBodyLimit+1); code != http.StatusRequestEntityTooLarge {
		t.Errorf("declared oversize body: %d", code)
	}
	if code := send("POST", "/api/v1/agents/inventory", io.LimitReader(zeroReader{}, AgentBodyLimit+1), -1); code != http.StatusRequestEntityTooLarge {
		t.Errorf("chunked oversize body: %d", code)
	}
	if code := send("POST", "/api/v1/agents/inventory", bytes.NewReader(make([]byte, 16<<20)), 16<<20); code != http.StatusNoContent {
		t.Errorf("16 MiB body: %d", code)
	}
}

func TestAgentProxyEngineDown(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	target, _ := url.Parse(srv.URL)
	srv.Close()
	edge := httptest.NewServer(agentEdge(target, nil))
	t.Cleanup(edge.Close)
	resp, err := edge.Client().Post(edge.URL+"/api/v1/agents/check-in", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway || resp.Header.Get("Retry-After") == "" || !strings.Contains(string(b), "patching_unavailable") {
		t.Errorf("%d %v %s", resp.StatusCode, resp.Header, b)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}
