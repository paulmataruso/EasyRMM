package agentapi

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

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
