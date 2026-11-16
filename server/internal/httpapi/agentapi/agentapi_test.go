package agentapi

import (
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

const testPin = "sha256//47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="

func newAPI(t *testing.T, ca []byte) *API {
	t.Helper()
	a, err := New(nil, &agents.Builds{}, []Address{
		{URL: "https://rmm.example.com/"},
		{URL: "https://203.0.113.10", Pin: testPin},
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
	a := newAPI(t, []byte("-----BEGIN CERTIFICATE-----\n"))
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

func TestCertificateAuthorityRoute(t *testing.T) {
	w := serve(newAPI(t, []byte("PEM")), "/api/agent/v1/ca.pem", nil)
	if w.Code != http.StatusOK || w.Body.String() != "PEM" || w.Header().Get("Content-Type") != "application/x-pem-file" {
		t.Errorf("CA: %d %q %q", w.Code, w.Body.String(), w.Header().Get("Content-Type"))
	}
	a, err := New(nil, &agents.Builds{}, []Address{{URL: "https://rmm.example.com"}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if w := serve(a, "/api/agent/v1/ca.pem", nil); w.Code != http.StatusNotFound {
		t.Errorf("CA without one: %d", w.Code)
	}
}

func TestNewRejectsUnsafeAddresses(t *testing.T) {
	for name, addrs := range map[string][]Address{
		"none":             nil,
		"quote":            {{URL: "https://rmm.example.com'; rm -rf /"}},
		"dollar in pin":    {{URL: "https://203.0.113.10", Pin: "$(id)"}},
		"pin without a CA": {{URL: "https://203.0.113.10", Pin: testPin}},
	} {
		if _, err := New(nil, &agents.Builds{}, addrs, nil, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
