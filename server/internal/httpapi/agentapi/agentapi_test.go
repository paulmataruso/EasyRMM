package agentapi

import (
	"bufio"
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/agents"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
)

const (
	testPin    = "sha256//47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
	testKeyPin = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
)

func newAPI(t *testing.T, ca []byte) *API {
	t.Helper()
	a, err := New(nil, &agents.Builds{}, []Address{
		{URL: "https://rmm.example.com/"},
		{URL: "https://203.0.113.10", Pin: testPin, KeyPin: testKeyPin},
	}, ca, nil)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func serve(a *API, path string, o *httpapi.Origin) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	if o != nil {
		r = httpapi.WithOrigin(r, *o)
	}
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	return w
}

func TestInstallScriptPerAddress(t *testing.T) {
	a := newAPI(t, testCA)
	dns := serve(a, "/api/agent/v1/install.sh", &httpapi.Origin{Console: "https://rmm.example.com"}).Body.String()
	ip := serve(a, "/api/agent/v1/install.sh", &httpapi.Origin{Console: "https://203.0.113.10", Pin: testPin}).Body.String()
	unknown := serve(a, "/api/agent/v1/install.sh", nil).Body.String()

	if !strings.Contains(dns, "SERVER='https://rmm.example.com'\n") || strings.Contains(dns, "pinnedpubkey") || strings.Contains(dns, "--ca-file") {
		t.Errorf("DNS script:\n%s", dns)
	}
	if !strings.Contains(dns, "wget -q --https-only") {
		t.Error("DNS script lost its wget fallback")
	}
	for _, want := range []string{
		"SERVER='https://203.0.113.10'\n",
		"PIN='" + testPin + "'\n",
		`curl -fsSL --proto '=https' --insecure --pinnedpubkey "$PIN"`,
		`fetch "$SERVER/api/agent/v1/ca.pem" "$TMP/ca.pem"`,
		`install --server "$SERVER" --ca-file "$TMP/ca.pem"`,
		"curl is required to check the server's public key",
	} {
		if !strings.Contains(ip, want) {
			t.Errorf("IP script lacks %q", want)
		}
	}
	if strings.Contains(ip, "wget") {
		t.Error("a pinned script must not fall back to wget, which cannot pin")
	}
	if unknown != dns {
		t.Error("a request without an origin should get the public URL's script")
	}
	// Both are valid shell.
	for name, script := range map[string]string{"dns": dns, "ip": ip} {
		if strings.Contains(script, "exec /usr/local/bin/easyrmm-agent") {
			t.Errorf("%s: exec skips the cleanup trap", name)
		}
		for _, sh := range []string{"sh", "bash", "dash"} {
			path, err := exec.LookPath(sh)
			if err != nil {
				continue
			}
			f := filepath.Join(t.TempDir(), name+".sh")
			if err := os.WriteFile(f, []byte(script), 0o600); err != nil {
				t.Fatal(err)
			}
			if out, err := exec.CommandContext(t.Context(), path, "-n", f).CombinedOutput(); err != nil { //nolint:gosec // test-controlled arguments
				t.Errorf("%s -n %s: %v %s", sh, name, err, out)
			}
		}
	}
}

func TestWindowsInstallScriptPerAddress(t *testing.T) {
	a := newAPI(t, testCA)
	get := func(o *httpapi.Origin) string {
		w := serve(a, "/api/agent/v1/install.ps1", o)
		if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "text/plain; charset=us-ascii" {
			t.Errorf("install.ps1: %d %q", w.Code, w.Header().Get("Content-Type"))
		}
		return w.Body.String()
	}
	dns := get(&httpapi.Origin{Console: "https://rmm.example.com"})
	ip := get(&httpapi.Origin{Console: "https://203.0.113.10"})
	if get(nil) != dns {
		t.Error("a request without an origin should get the public URL's script")
	}
	for name, script := range map[string]string{"dns": dns, "ip": ip} {
		for i, r := range script {
			if r > 0x7e || (r < 0x20 && r != '\r' && r != '\n') {
				t.Fatalf("%s: byte %d is %q; Windows PowerShell reads the script as ANSI", name, i, r)
			}
		}
		if strings.Count(script, "\n") != strings.Count(script, "\r\n") {
			t.Errorf("%s: not CRLF throughout", name)
		}
		if !strings.Contains(script, "$Server = '"+map[string]string{"dns": "https://rmm.example.com", "ip": "https://203.0.113.10"}[name]+"'") ||
			!strings.Contains(script, `$env:EASYRMM_TOKEN = $Token`) || !strings.Contains(script, "Get-FileHash -Algorithm SHA256") {
			t.Errorf("%s script:\n%s", name, script)
		}
	}
	if strings.Contains(dns, "ServerCertificateValidationCallback") || strings.Contains(dns, "--ca-file") {
		t.Errorf("an unpinned script pins:\n%s", dns)
	}
	for _, want := range []string{
		"-eq '" + testKeyPin + "'",
		`$web.DownloadFile("$Server/api/agent/v1/ca.pem", $ca)`,
		`& $exe install --server $Server --ca-file $ca`,
		"[Net.ServicePointManager]::ServerCertificateValidationCallback = $null",
		"PowerShell 7 cannot",
	} {
		if !strings.Contains(ip, want) {
			t.Errorf("pinned script lacks %q", want)
		}
	}
	// PowerShell parses both, where it is installed (GitHub's Linux runners
	// have it).
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Log("pwsh not found; parse check skipped")
		return
	}
	for name, script := range map[string]string{"dns": dns, "ip": ip} {
		f := filepath.Join(t.TempDir(), name+".ps1")
		if err := os.WriteFile(f, []byte(script), 0o600); err != nil {
			t.Fatal(err)
		}
		check := `$e = $null; [void][Management.Automation.Language.Parser]::ParseFile($env:EASYRMM_PS1, [ref]$null, [ref]$e); if ($e) { $e | ForEach-Object { $_.ToString() }; exit 1 }; 'parsed'`
		cmd := exec.CommandContext(t.Context(), pwsh, "-NoProfile", "-NonInteractive", "-Command", check) //nolint:gosec // test-controlled arguments
		cmd.Env = append(os.Environ(), "EASYRMM_PS1="+f)
		if out, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(out), "parsed") {
			t.Errorf("%s: PowerShell parse errors: %v\n%s", name, err, out)
		}
	}
}

// TestWindowsInstallScriptOrder: the script creates the folders, locks them
// down, verifies them, excludes them and only then downloads (ADR-0070),
// and it touches nothing it must not.
func TestWindowsInstallScriptOrder(t *testing.T) {
	a := newAPI(t, testCA)
	for name, o := range map[string]*httpapi.Origin{"dns": {Console: "https://rmm.example.com"}, "ip": {Console: "https://203.0.113.10"}} {
		script := serve(a, "/api/agent/v1/install.ps1", o).Body.String()
		last := -1
		for _, step := range []string{"Step 'create'", "Step 'lock'", "Step 'verify'", "Step 'exclude'", "Step 'download'"} {
			i := strings.Index(script, step)
			if i < 0 || i < last {
				t.Fatalf("%s: %s is missing or out of order", name, step)
			}
			last = i
		}
		// Nothing is downloaded before the download step, and nothing is
		// excluded before the folders are verified.
		dl := strings.Index(script, "Step 'download'")
		if i := strings.Index(script, "$web.DownloadFile"); i < dl {
			t.Errorf("%s: a download comes before the download step", name)
		}
		if i := strings.Index(script, "    Add-Exclusions"); i < strings.Index(script, "Step 'exclude'") || i > dl {
			t.Errorf("%s: the exclusions are not added in their own step", name)
		}
		for _, never := range []string{"DisableRealtimeMonitoring", "DisableIOAVProtection", "DisableScriptScanning", "Amsi", "AMSI", "ExclusionExtension", "Set-MpPreference", "DisableBehaviorMonitoring"} {
			if strings.Contains(script, never) {
				t.Errorf("%s: the script mentions %s", name, never)
			}
		}
		for _, want := range []string{"ExclusionPath", "ExclusionProcess", "AttackSurfaceReductionOnlyExclusions", "ControlledFolderAccessAllowedApplications",
			"EASYRMM_INSTALL_FAIL_AT", "Undo-Install", "defender-exclusions.json", "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"} {
			if !strings.Contains(script, want) {
				t.Errorf("%s: the script lacks %s", name, want)
			}
		}
		if i, j := strings.Index(script, "} finally {"), strings.Index(script, "if (-not $ok) { Undo-Install }"); i < 0 || j < i {
			t.Errorf("%s: the clean-up is not in the finally block", name)
		}
	}
}

// testCA stands in for the authority's certificate: the API only re-encodes it.
var testCA = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("DER bytes")})

func TestCertificateAuthorityRoute(t *testing.T) {
	a := newAPI(t, testCA)
	w := serve(a, "/api/agent/v1/ca.pem", nil)
	if w.Code != http.StatusOK || w.Body.String() != string(testCA) || w.Header().Get("Content-Type") != "application/x-pem-file" {
		t.Errorf("CA: %d %q %q", w.Code, w.Body.String(), w.Header().Get("Content-Type"))
	}
	// The same certificate in DER, as a .crt file Windows installs.
	w = serve(a, "/api/agent/v1/easyrmm-ca.crt", nil)
	if w.Code != http.StatusOK || w.Body.String() != "DER bytes" || w.Header().Get("Content-Type") != "application/x-x509-ca-cert" ||
		w.Header().Get("Content-Disposition") != `attachment; filename="easyrmm-ca.crt"` {
		t.Errorf("CA certificate: %d %q %v", w.Code, w.Body.String(), w.Header())
	}

	a, err := New(nil, &agents.Builds{}, []Address{{URL: "https://rmm.example.com"}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/agent/v1/ca.pem", "/api/agent/v1/easyrmm-ca.crt"} {
		if w := serve(a, path, nil); w.Code != http.StatusNotFound {
			t.Errorf("%s without an authority: %d", path, w.Code)
		}
	}
	// Anything but a PEM certificate is a configuration error.
	if _, err := New(nil, &agents.Builds{}, []Address{{URL: "https://rmm.example.com"}}, []byte("not PEM"), nil); err == nil {
		t.Error("a certificate authority that is not PEM accepted")
	}
}

func TestNewRejectsUnsafeAddresses(t *testing.T) {
	for name, addrs := range map[string][]Address{
		"none":             nil,
		"quote":            {{URL: "https://rmm.example.com'; rm -rf /"}},
		"dollar in pin":    {{URL: "https://203.0.113.10", Pin: "$(id)"}},
		"backtick":         {{URL: "https://203.0.113.10", KeyPin: "`whoami`"}},
		"non-ASCII":        {{URL: "https://rmm.exämple.com"}},
		"line break":       {{URL: "https://rmm.example.com\nWrite-Host"}},
		"pin without a CA": {{URL: "https://203.0.113.10", Pin: testPin}},
		"key pin, no CA":   {{URL: "https://203.0.113.10", KeyPin: testKeyPin}},
	} {
		if _, err := New(nil, &agents.Builds{}, addrs, nil, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestReadBodyDeadline checks that a request body that stalls is given up
// on, and that the deadline is cleared once the body has arrived, so a
// long poll waiting afterwards is not cut off.
func TestReadBodyDeadline(t *testing.T) {
	old := bodyTimeout
	bodyTimeout = 300 * time.Millisecond
	t.Cleanup(func() { bodyTimeout = old })

	type result struct {
		body    string
		err     error
		ctxErr  error
		elapsed time.Duration
	}
	results := make(chan result, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		b, err := readBody(w, r, 1<<20)
		if err == nil {
			// Wait past the deadline, as a long poll does.
			time.Sleep(2 * bodyTimeout)
		}
		results <- result{string(b), err, r.Context().Err(), time.Since(start)}
		if err == nil {
			_, _ = io.WriteString(w, "answered")
		}
	}))
	t.Cleanup(srv.Close)

	// A body that arrives in time; the wait after it is not cut off.
	resp, err := http.Post(srv.URL, "application/json", strings.NewReader(`{"ok":true}`))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if r := <-results; r.err != nil || r.body != `{"ok":true}` || r.ctxErr != nil || string(got) != "answered" {
		t.Fatalf("body in time: %+v, answer %q", r, got)
	}

	// A body that starts and stalls.
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })
	go func() { _, _ = pw.Write([]byte(`{"facts":`)) }()
	go func() {
		req, _ := http.NewRequest(http.MethodPost, srv.URL, pr)
		if resp, err := http.DefaultClient.Do(req); err == nil {
			_ = resp.Body.Close()
		}
	}()
	select {
	case r := <-results:
		if !errors.Is(r.err, errBodyTimeout) || r.elapsed > 5*time.Second {
			t.Fatalf("stalled body: %+v", r)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a stalled body was waited for")
	}
}

func TestPollsPerDevice(t *testing.T) {
	a := newAPI(t, testCA)
	dev, other := uuid.New(), uuid.New()
	var wg sync.WaitGroup
	entered := make(chan bool, 2*maxPolls)
	for range 2 * maxPolls {
		wg.Go(func() { entered <- a.enterPoll(dev) })
	}
	wg.Wait()
	close(entered)
	n := 0
	for ok := range entered {
		if ok {
			n++
		}
	}
	if n != maxPolls || !a.enterPoll(other) {
		t.Fatalf("%d polls open at once; another device refused", n)
	}
	a.leavePoll(dev)
	if !a.enterPoll(dev) || a.enterPoll(dev) {
		t.Fatal("a closed poll did not make room for exactly one")
	}
	for range maxPolls {
		a.leavePoll(dev)
	}
	a.leavePoll(other)
	if len(a.polls) != 0 {
		t.Errorf("devices with no polls are remembered: %v", a.polls)
	}
}

// TestRefuseUnread checks that a request refused before its body is read
// is answered while the body is still arriving, and that the server does
// not go on waiting for the rest of it: over HTTP/1 it closes the
// connection even if the client never does, over HTTP/2 only the stream
// ends and the connection serves on.
func TestRefuseUnread(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ok" {
			_, _ = io.WriteString(w, "ok")
			return
		}
		_ = refuseUnread(w, r, false, nil)
		w.WriteHeader(http.StatusUnauthorized)
	})

	t.Run("HTTP/1.1", func(t *testing.T) {
		srv := httptest.NewServer(handler)
		t.Cleanup(srv.Close)
		// A client that sends part of a chunked body, reads the answer and
		// then neither sends more nor hangs up.
		conn, err := net.Dial("tcp", srv.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		_, _ = io.WriteString(conn, "POST /refuse HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n9\r\n{\"facts\":\r\n")
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("not answered while the body arrives: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized || !resp.Close {
			t.Fatalf("answer %d %v", resp.StatusCode, resp.Header)
		}
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
			t.Fatalf("the server kept the connection, waiting for the body: %v", err)
		}
	})

	t.Run("HTTP/2", func(t *testing.T) {
		closed := make(chan struct{}, 4)
		srv := httptest.NewUnstartedServer(handler)
		srv.EnableHTTP2 = true
		srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
			if s == http.StateClosed {
				closed <- struct{}{}
			}
		}
		srv.StartTLS()
		t.Cleanup(srv.Close)
		client := srv.Client()
		pr, pw := io.Pipe()
		t.Cleanup(func() { _ = pw.Close() })
		go func() { _, _ = pw.Write([]byte(`{"facts":`)) }()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/refuse", pr)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("not answered while the body arrives: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized || resp.ProtoMajor != 2 {
			t.Fatalf("answer %d over %s", resp.StatusCode, resp.Proto)
		}
		ok, err := client.Get(srv.URL + "/ok")
		if err != nil {
			t.Fatal(err)
		}
		_ = ok.Body.Close()
		select {
		case <-closed:
			t.Fatal("the HTTP/2 connection was closed")
		default:
		}
	})
}

// wrapped stands for the server's middleware around the response writer:
// net/http's MaxBytesReader cannot mark a wrapped writer's connection for
// closing, so it is kept after a body that is too large.
type wrapped struct{ http.ResponseWriter }

func (w wrapped) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// TestRefusalsKeepConnectionsUsable checks that refusing a request does
// not spoil the keep-alive connection it came on: a request without a
// body, or whose body was read to its end, leaves the connection to the
// next request with a live context.
func TestRefusalsKeepConnectionsUsable(t *testing.T) {
	var canceled atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		w := wrapped{rw}
		switch r.URL.Path {
		case "/ok":
			if r.Context().Err() != nil {
				canceled.Add(1)
			}
		case "/refuse":
			_ = refuseUnread(w, r, false, nil)
			w.WriteHeader(http.StatusUnauthorized)
		case "/read":
			if _, err := readBody(w, r, 64); err != nil {
				var e *httpapi.Error
				if errors.As(err, &e) {
					w.WriteHeader(e.Status)
				}
			}
		}
	}))
	t.Cleanup(srv.Close)
	c := srv.Client()
	send := func(method, path string, body []byte, want int) {
		t.Helper()
		var rd io.Reader
		if body != nil {
			rd = bytes.NewReader(body)
		}
		req, _ := http.NewRequest(method, srv.URL+path, rd)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("%s %s: %d", method, path, resp.StatusCode)
		}
	}
	for range 50 {
		send(http.MethodGet, "/refuse", nil, http.StatusUnauthorized)
		send(http.MethodGet, "/ok", nil, http.StatusOK)
		send(http.MethodPost, "/read", bytes.Repeat([]byte("x"), 65), http.StatusRequestEntityTooLarge)
		send(http.MethodGet, "/ok", nil, http.StatusOK)
		send(http.MethodPost, "/refuse", bytes.Repeat([]byte("x"), 133), http.StatusUnauthorized)
		send(http.MethodGet, "/ok", nil, http.StatusOK)
	}
	if n := canceled.Load(); n != 0 {
		t.Errorf("%d requests arrived on a connection whose context was canceled", n)
	}
}

// TestWriteInstallScriptForCI writes the script a server hands out, for the
// CI job that runs it on a real Windows (ADR-0070, step 0). It does nothing
// unless EASYRMM_WRITE_INSTALL_PS1 names the file.
func TestWriteInstallScriptForCI(t *testing.T) {
	out := os.Getenv("EASYRMM_WRITE_INSTALL_PS1")
	if out == "" {
		t.Skip("only CI's Windows job asks for the script")
	}
	script := serve(newAPI(t, testCA), "/api/agent/v1/install.ps1", &httpapi.Origin{Console: "http://127.0.0.1:18080"}).Body.String()
	if err := os.WriteFile(out, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
}
