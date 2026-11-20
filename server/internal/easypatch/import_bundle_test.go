//go:build bundle

package easypatch

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // TOTP (RFC 6238) is HMAC-SHA-1, as EasyPatch's authenticator codes are
	"crypto/tls"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// The import test (scripts/e2e/import.sh; ADR-0045): a standalone EasyPatch
// 1.10, built from its release tag, is given data through its own console API
// and one real Linux agent, backed up as its backup.sh does, and imported
// into an EasyRMM deployment. TestImportSeedEasyPatch gives the old server
// its data; TestImportedEngine checks the engine after the import.

// oldConsole is a signed-in session with the standalone EasyPatch's console
// API, as its browser console has one: cookies and the anti-forgery header.
type oldConsole struct {
	t    *testing.T
	base *url.URL
	http *http.Client
}

func (c *oldConsole) send(method, path string, body, out any, want int) {
	c.t.Helper()
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			c.t.Fatal(err)
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base.String()+path, r)
	if err != nil {
		c.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for _, k := range c.http.Jar.Cookies(c.base) {
		if k.Name == "XSRF-TOKEN" {
			req.Header.Set("X-XSRF-TOKEN", k.Value)
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != want {
		c.t.Fatalf("%s %s: %d, want %d: %s", method, path, resp.StatusCode, want, data)
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			c.t.Fatalf("%s %s: %v: %s", method, path, err, data)
		}
	}
}

// totp is an authenticator code for secret (base32) at now.
func totp(t *testing.T, secret string, now time.Time) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimRight(secret, "=")))
	if err != nil {
		t.Fatalf("MFA secret: %v", err)
	}
	var step [8]byte
	binary.BigEndian.PutUint64(step[:], uint64(now.Unix()/30)) //nolint:gosec // a positive Unix time
	m := hmac.New(sha1.New, key)
	m.Write(step[:])
	sum := m.Sum(nil)
	o := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[o:o+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", code%1_000_000)
}

func importEnv(t *testing.T, names ...string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, n := range names {
		out[n] = os.Getenv(n)
		if out[n] == "" {
			t.Fatalf("set %s (scripts/e2e/import.sh does)", strings.Join(names, ", "))
		}
	}
	return out
}

// TestImportSeedEasyPatch signs in to the standalone EasyPatch as its first
// administrator (enrolling an authenticator, as EasyPatch asks), and makes
// what the import has to bring across: organizations whose names differ
// only in case, one archived, sites, a webhook whose address only the old
// server's keys decrypt, and an enrollment token for the Linux agent.
//
//	EASYRMM_IMPORT_OLD_URL         the old server (https://patch.import.test), reached on 127.0.0.1:443
//	EASYRMM_IMPORT_CA              the run's CA certificate, which its certificate chains to
//	EASYRMM_IMPORT_ADMIN_EMAIL     its administrator, made with its CLI
//	EASYRMM_IMPORT_ADMIN_PASSWORD  (from the file the script made)
//	EASYRMM_IMPORT_OUT             a folder for the token and the webhook's id
func TestImportSeedEasyPatch(t *testing.T) {
	env := importEnv(t, "EASYRMM_IMPORT_OLD_URL", "EASYRMM_IMPORT_CA", "EASYRMM_IMPORT_ADMIN_EMAIL", "EASYRMM_IMPORT_ADMIN_PASSWORD", "EASYRMM_IMPORT_OUT")
	base, err := url.Parse(env["EASYRMM_IMPORT_OLD_URL"])
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(env["EASYRMM_IMPORT_CA"])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("EASYRMM_IMPORT_CA holds no certificate")
	}
	jar, _ := cookiejar.New(nil)
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	c := &oldConsole{t: t, base: base, http: &http.Client{Timeout: 60 * time.Second, Jar: jar, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		// The old server's name is the run's; it answers on loopback.
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, "127.0.0.1:443")
		},
	}}}

	var login struct {
		MfaRequired      bool `json:"mfaRequired"`
		MfaSetupRequired bool `json:"mfaSetupRequired"`
	}
	c.send(http.MethodPost, "/api/v1/auth/login", map[string]string{"email": env["EASYRMM_IMPORT_ADMIN_EMAIL"],
		"password": env["EASYRMM_IMPORT_ADMIN_PASSWORD"]}, &login, http.StatusOK)
	if !login.MfaSetupRequired {
		t.Fatalf("a new administrator is asked to set up MFA: %+v", login)
	}
	var setup struct {
		Secret string `json:"secret"`
	}
	c.send(http.MethodPost, "/api/v1/auth/mfa/setup", nil, &setup, http.StatusOK)
	c.send(http.MethodPost, "/api/v1/auth/mfa/enable", map[string]string{"code": totp(t, setup.Secret, time.Now())}, nil, http.StatusOK)

	type record struct {
		ID uuid.UUID `json:"id"`
	}
	org := func(name, tz string) uuid.UUID {
		var r record
		c.send(http.MethodPost, "/api/v1/organizations", map[string]any{"name": name, "timeZone": tz}, &r, http.StatusCreated)
		return r.ID
	}
	site := func(org uuid.UUID, name, address string) uuid.UUID {
		var r record
		c.send(http.MethodPost, "/api/v1/organizations/"+org.String()+"/sites", map[string]any{"name": name, "address": address}, &r, http.StatusCreated)
		return r.ID
	}
	contoso := org("Contoso", "Europe/Oslo")
	hq := site(contoso, "HQ", "")
	site(contoso, "Branch", "1 Harbor Road")
	site(org("Fabrikam", "America/New_York"), "Main", "")
	org("fabrikam", "UTC")
	c.send(http.MethodPost, "/api/v1/organizations/"+org("Retired", "UTC").String()+"/archive", nil, nil, http.StatusOK)

	var channel struct {
		Channel struct {
			ID uuid.UUID `json:"id"`
		} `json:"channel"`
	}
	c.send(http.MethodPost, "/api/v1/notifications/channels", map[string]any{"name": "Ops webhook", "type": "Webhook", "enabled": true,
		"webhookFormat": "Generic", "webhookUrl": "https://hooks.import.test/patching"}, &channel, http.StatusOK)

	var tokens []struct {
		PlaintextToken string `json:"plaintextToken"`
	}
	c.send(http.MethodPost, "/api/v1/enrollment-tokens", map[string]any{"organizationId": contoso, "siteId": hq, "description": "import test",
		"expiresInHours": 24, "maxUses": 1, "count": 1}, &tokens, http.StatusOK)
	if len(tokens) != 1 || tokens[0].PlaintextToken == "" {
		t.Fatalf("enrollment token: %+v", tokens)
	}
	out := env["EASYRMM_IMPORT_OUT"]
	if err := os.WriteFile(filepath.Join(out, "token"), []byte(tokens[0].PlaintextToken), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "channel"), []byte(channel.Channel.ID.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestImportedEngine checks the patching engine after the import, through
// its API on loopback with EasyRMM's statements: the old server's agent
// checks in through EasyRMM's edge on the old name and runs a scan; the
// old server's notification secrets decrypt with its keys; and the
// reconciler gave the engine EasyRMM's names.
//
//	EASYRMM_IMPORT_ENGINE_URL  the engine on loopback (http://127.0.0.1:18180)
//	EASYRMM_IMPORT_ENGINE_KEY  EASYRMM_PATCHING_KEY from the deployment's .env
//	EASYRMM_IMPORT_ENDPOINT    the agent's endpoint, as the old server had it
//	EASYRMM_IMPORT_CHANNEL     the webhook TestImportSeedEasyPatch made
//	EASYRMM_IMPORT_SINCE       when the old server stopped (RFC 3339)
func TestImportedEngine(t *testing.T) {
	env := importEnv(t, "EASYRMM_IMPORT_ENGINE_URL", "EASYRMM_IMPORT_ENGINE_KEY", "EASYRMM_IMPORT_ENDPOINT", "EASYRMM_IMPORT_CHANNEL",
		"EASYRMM_IMPORT_SINCE")
	key, err := base64.StdEncoding.DecodeString(env["EASYRMM_IMPORT_ENGINE_KEY"])
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewEngineClient(env["EASYRMM_IMPORT_ENGINE_URL"], signer, "import-test")
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err1 := uuid.Parse(env["EASYRMM_IMPORT_ENDPOINT"])
	channel, err2 := uuid.Parse(env["EASYRMM_IMPORT_CHANNEL"])
	since, err3 := time.Parse(time.RFC3339, env["EASYRMM_IMPORT_SINCE"])
	if err1 != nil || err2 != nil || err3 != nil {
		t.Fatal(err1, err2, err3)
	}
	ctx := context.Background()
	wait := func(what string, limit time.Duration, done func() (bool, string)) {
		t.Helper()
		var last string
		for end := time.Now().Add(limit); time.Now().Before(end); time.Sleep(5 * time.Second) {
			var ok bool
			if ok, last = done(); ok {
				return
			}
		}
		t.Fatalf("%s: not within %s (%s)", what, limit, last)
	}

	// The agent, enrolled with the old server, checks in again: with
	// EasyRMM's edge on the old name.
	wait("the agent checks in through EasyRMM", 10*time.Minute, func() (bool, string) {
		e, err := client.Endpoint(ctx, endpoint)
		if err != nil {
			return false, err.Error()
		}
		return e.Summary.LastCheckInAt != nil && e.Summary.LastCheckInAt.After(since), fmt.Sprintf("%+v", e.Summary)
	})
	scan, err := client.BulkScan(ctx, []uuid.UUID{endpoint}, "")
	if err != nil || scan.Succeeded != 1 || scan.Results[0].JobID == nil {
		t.Fatalf("scan: %v %+v", err, scan)
	}
	wait("the agent runs a scan", 10*time.Minute, func() (bool, string) {
		j, err := client.Job(ctx, *scan.Results[0].JobID)
		if err != nil {
			return false, err.Error()
		}
		if s := j.Summary.Status; s == "Failed" || s == "Expired" || s == statusCanceled {
			t.Fatalf("scan: %+v", j)
		}
		return j.Summary.Status == "Completed", j.Summary.Status
	})

	// The webhook's address was encrypted with the old server's keys. The
	// engine decrypts it before anything else, so a delivery that fails
	// for any other reason (hooks.import.test does not resolve) shows the
	// keys came across.
	// Channels are server-wide: a super administrator's, as for EasyRMM's
	// own Settings → Patching → Notifications.
	super := WithStatement(ctx, Statement{Subject: ServiceSubject, Name: "import-test", Role: RoleSuperAdmin, AllOrganizations: true})
	if _, err := client.TestChannel(super, channel); err != nil {
		t.Fatalf("test delivery: %v", err)
	}
	wait("the test delivery is tried", 5*time.Minute, func() (bool, string) {
		p, err := client.Deliveries(super, channel, "", 1, 20)
		if err != nil {
			return false, err.Error()
		}
		for _, d := range p.Items {
			if strings.Contains(d.LastError, "cannot be decrypted") {
				t.Fatalf("the old server's keys did not come across: %s", d.LastError)
			}
			if d.Kind == "Test" && d.LastError != "" {
				t.Logf("test delivery: %s (%s)", d.Status, d.LastError)
				return true, ""
			}
		}
		return false, fmt.Sprintf("%+v", p.Items)
	})

	// The reconciler gave the engine EasyRMM's names: the second
	// "fabrikam" is EasyRMM's "fabrikam (2)".
	wait("the engine takes EasyRMM's names", 8*time.Minute, func() (bool, string) {
		list, err := client.AllOrganizations(ctx)
		if err != nil {
			return false, err.Error()
		}
		var names []string
		for _, o := range list {
			names = append(names, o.Name)
		}
		for _, want := range []string{"Contoso", "Fabrikam", "fabrikam (2)"} {
			if !strings.Contains(","+strings.Join(names, ",")+",", ","+want+",") {
				return false, strings.Join(names, ", ")
			}
		}
		return true, ""
	})
}
