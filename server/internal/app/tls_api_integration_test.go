//go:build integration

package app_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/paulmataruso/easyrmm/server/internal/config"
)

type tlsOverview struct {
	Mode    string `json:"mode"`
	Managed bool   `json:"managed"`
	Status  *struct {
		Directory string `json:"directory"`
		Email     string `json:"email"`
		Account   bool   `json:"account"`
		Names     []struct {
			Name  string `json:"name"`
			Role  string `json:"role"`
			State string `json:"state"`
		} `json:"names"`
		Warnings []string `json:"warnings"`
	} `json:"status"`
}

// TestCertificatesAPI is the Certificates page's data: where the certificates
// come from, each name's state in acme mode, who may read it, and what Retry
// now and the checks answer for a name that is not the server's. No key is in
// any answer.
func TestCertificatesAPI(t *testing.T) {
	h := newHarnessWith(t, false, func(c *config.Config) {
		c.TLSMode = config.TLSAcme
		c.ACMEDirectory = "https://127.0.0.1:1/directory" // never reached: the account cannot be made
		c.ListenHTTPS, c.ListenHTTP = ":8443", ":8080"
		c.Notes = []string{"EASYRMM_MESH_CERT_URL is ignored unless EASYRMM_TLS_MODE=offload"}
	})
	if err := h.deps.TLS.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.deps.TLS.Close)
	admin, _ := setUp(t, h)
	const base = "/api/v1/settings/certificates"

	var v tlsOverview
	admin.expect(http.StatusOK, "GET", base, nil, &v)
	if v.Mode != "acme" || !v.Managed || v.Status == nil || len(v.Status.Names) != 2 || v.Status.Account || v.Status.Email != "" {
		t.Fatalf("overview: %+v", v)
	}
	if v.Status.Names[0].Name != "mesh.rmm.test" || v.Status.Names[0].Role != "remote access" || v.Status.Names[1].Name != "rmm.test" || v.Status.Names[1].State != "pending" {
		t.Fatalf("names: %+v", v.Status.Names)
	}
	if len(v.Status.Warnings) != 1 || !strings.Contains(v.Status.Warnings[0], "EASYRMM_MESH_CERT_URL") {
		t.Fatalf("warnings: %v", v.Status.Warnings)
	}

	// Nothing secret in what the page reads.
	body := admin.do("GET", base, nil).body
	for _, bad := range []string{"PRIVATE KEY", "privateKey", "accountKey"} {
		if strings.Contains(string(body), bad) {
			t.Fatalf("the answer mentions %s", bad)
		}
	}

	// Only whoever manages the platform reaches it.
	acme := orgID(t, admin, "Acme")
	invite(t, h, admin, "olive@acme.example", []map[string]any{{"role": "org_admin", "organizationId": acme}})
	org := h.client()
	org.signIn("olive@acme.example", "a long and unusual passphrase", "")
	for _, route := range [][2]string{{"GET", base}, {"POST", base + "/rmm.test/retry"}, {"POST", base + "/rmm.test/order-anyway"}, {"POST", base + "/rmm.test/check"}} {
		if r := org.do(route[0], route[1], nil); r.status != http.StatusForbidden {
			t.Fatalf("%s %s as an organization's administrator: %d", route[0], route[1], r.status)
		}
	}

	// A name that is not the server's.
	for _, route := range []string{"/other.test/retry", "/other.test/order-anyway", "/other.test/check"} {
		wantStatus(t, admin.do("POST", base+route, nil), http.StatusNotFound, "not_found")
	}
	// The certificate authority cannot be reached: the account is not made, and the page says so.
	wantStatus(t, admin.do("POST", base+"/rmm.test/retry", nil), http.StatusConflict, "no_account")
	if n := tlsAudit(t, h, "tls.retry"); n != 0 {
		t.Fatalf("a refused retry was audited %d times", n)
	}
}

func tlsAudit(t *testing.T, h *harness, action string) int {
	t.Helper()
	var n int
	if err := h.db.DB.Pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_log WHERE action = $1`, action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Where the server does not obtain its certificates, the page says so and the
// routes that act answer not found.
func TestCertificatesAPIWithoutACME(t *testing.T) {
	h := newHarness(t, false)
	admin, _ := setUp(t, h)
	var v tlsOverview
	admin.expect(http.StatusOK, "GET", "/api/v1/settings/certificates", nil, &v)
	if v.Mode != "offload" || v.Managed || v.Status != nil {
		t.Fatalf("overview: %+v", v)
	}
	wantStatus(t, admin.do("POST", "/api/v1/settings/certificates/rmm.test/retry", nil), http.StatusNotFound, "not_found")
}
