//go:build bundle

package easypatch

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestBundleGateway runs in the bundle test (scripts/e2e/bundle.sh; one-
// product plan, B8) against the patching engine of a running deployment: on
// loopback it accepts EasyRMM's statements and nothing else, and EasyRMM's
// edge does not reach its API whatever a request carries.
//
//	EASYRMM_BUNDLE_ENGINE_URL  the engine on loopback (http://127.0.0.1:18180)
//	EASYRMM_BUNDLE_ENGINE_KEY  EASYRMM_PATCHING_KEY from the deployment's .env
//	EASYRMM_BUNDLE_URL         EasyRMM's public address (https://127.0.0.1)
//	EASYRMM_BUNDLE_SPKI        base64 SHA-256 of its certificate's public key
func TestBundleGateway(t *testing.T) {
	engineURL := os.Getenv("EASYRMM_BUNDLE_ENGINE_URL")
	key, err := base64.StdEncoding.DecodeString(os.Getenv("EASYRMM_BUNDLE_ENGINE_KEY"))
	publicURL := os.Getenv("EASYRMM_BUNDLE_URL")
	spki := os.Getenv("EASYRMM_BUNDLE_SPKI")
	if engineURL == "" || err != nil || len(key) < MinStatementKey || publicURL == "" || spki == "" {
		t.Fatal("set EASYRMM_BUNDLE_ENGINE_URL, EASYRMM_BUNDLE_ENGINE_KEY, EASYRMM_BUNDLE_URL and EASYRMM_BUNDLE_SPKI (scripts/e2e/bundle.sh does)")
	}
	signer, err := NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 30 * time.Second}

	// call sends method target to base with statement (none when empty)
	// and returns the status and body.
	call := func(base, method, target, statement string, c *http.Client) (int, string) {
		t.Helper()
		req, err := http.NewRequest(method, base+target, strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if statement != "" {
			req.Header.Set(StatementHeader, statement)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		return resp.StatusCode, string(body)
	}
	sign := func(s *Signer, st Statement, method, target string) string {
		t.Helper()
		v, err := s.Sign(st, method, target)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	service := Statement{Subject: ServiceSubject, Name: "EasyRMM bundle test", Role: RoleAdmin, AllOrganizations: true}
	const orgs = "/api/v1/organizations"

	// The statement that works, so each refusal below is about what it
	// changes, and the organizations to name.
	status, body := call(engineURL, http.MethodGet, orgs, sign(signer, service, http.MethodGet, orgs), client)
	if status != http.StatusOK {
		t.Fatalf("EasyRMM's own statement: %d %s", status, body)
	}
	var list []Organization
	if err := json.Unmarshal([]byte(body), &list); err != nil || len(list) == 0 {
		t.Fatalf("organizations: %v %s", err, body)
	}
	org := list[0].ID

	refusals := []struct {
		name, method, target, statement string
		want                            int
	}{
		{"no statement", http.MethodGet, orgs, "", http.StatusUnauthorized},
		{"not a statement", http.MethodGet, orgs, "forged", http.StatusUnauthorized},
		{"signed with another key", http.MethodGet, orgs, func() string {
			other, _ := NewSigner([]byte(strings.Repeat("k", MinStatementKey)))
			return sign(other, service, http.MethodGet, orgs)
		}(), http.StatusUnauthorized},
		{"a valid signature over changed claims", http.MethodGet, orgs, func() string {
			parts := strings.Split(sign(signer, service, http.MethodGet, orgs), ".")
			claims, _ := base64.RawURLEncoding.DecodeString(parts[1])
			changed := strings.Replace(string(claims), `"role":"Admin"`, `"role":"SuperAdmin"`, 1)
			return parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(changed)) + "." + parts[2]
		}(), http.StatusUnauthorized},
		{"expired", http.MethodGet, orgs, func() string {
			old := *signer
			old.now = func() time.Time { return time.Now().Add(-2 * StatementLifetime) }
			return sign(&old, service, http.MethodGet, orgs)
		}(), http.StatusUnauthorized},
		{"made for another path", http.MethodGet, orgs + "/" + org.String(), sign(signer, service, http.MethodGet, orgs), http.StatusUnauthorized},
		{"made for another method", http.MethodPost, orgs, sign(signer, service, http.MethodGet, orgs), http.StatusUnauthorized},
		{"made for another query", http.MethodGet, orgs + "?includeArchived=true", sign(signer, service, http.MethodGet, orgs), http.StatusUnauthorized},
		// Out of scope: the role or the organizations the statement names.
		{"read-only acting", http.MethodPost, "/api/v1/enrollment-tokens",
			sign(signer, Statement{Subject: uuid.NewString(), Name: "bundle-readonly@example.test", Role: RoleReadOnly, Organizations: []uuid.UUID{org}},
				http.MethodPost, "/api/v1/enrollment-tokens"), http.StatusForbidden},
		{"another organization's", http.MethodGet, orgs + "/" + org.String(),
			sign(signer, Statement{Subject: uuid.NewString(), Name: "bundle-other@example.test", Role: RoleAdmin, Organizations: []uuid.UUID{uuid.New()}},
				http.MethodGet, orgs+"/"+org.String()), http.StatusNotFound},
	}
	for _, r := range refusals {
		if status, body := call(engineURL, r.method, r.target, r.statement, client); status != r.want {
			t.Errorf("%s: %d, want %d (%s)", r.name, status, r.want, body)
		}
	}

	// EasyRMM's edge, with its own certificate (by key): a valid statement
	// for the engine's API reaches EasyRMM, which has no session for it (or
	// no such route), never the engine.
	edge := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // checked below, by the certificate's public key
		MinVersion:         tls.VersionTLS12,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no certificate")
			}
			return pinned(cs.PeerCertificates[0], spki)
		},
	}}}
	for _, target := range []string{orgs, "/api/v1/endpoints", "/api/v1/audit-logs"} {
		status, body := call(publicURL, http.MethodGet, target, sign(signer, service, http.MethodGet, target), edge)
		if (status != http.StatusUnauthorized && status != http.StatusNotFound) || strings.Contains(body, `"items"`) ||
			strings.HasPrefix(strings.TrimSpace(body), "[") {
			t.Errorf("through the edge, %s: %d %.200s", target, status, body)
		}
	}
}

// pinned checks that cert's public key is spki (base64 SHA-256 of its DER).
func pinned(cert *x509.Certificate, spki string) error {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	if base64.StdEncoding.EncodeToString(sum[:]) != spki {
		return errors.New("the certificate's public key is not the pinned one")
	}
	return nil
}
