//go:build integration

package app_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/paulmataruso/easyrmm/server/internal/app"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/config"
	"github.com/paulmataruso/easyrmm/server/internal/easypatch/eptest"
	"github.com/paulmataruso/easyrmm/server/internal/mailserver"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
	"github.com/paulmataruso/easyrmm/server/internal/testmail"
)

const publicOrigin = "https://rmm.test"

type harness struct {
	t       *testing.T
	srv     *httptest.Server
	dataDir string
	// mp is the real SMTP server (Mailpit) the console's mail server sends
	// to, when the harness has one.
	mp   *testmail.Mailpit
	db   *testdb.Instance
	cfg  *config.Config
	deps *app.Deps
	// logs is everything the server logged, at every level.
	logs *lockedBuffer
}

// lockedBuffer is a buffer the server's goroutines can log into.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func newHarness(t *testing.T, withMail bool) *harness {
	t.Helper()
	return newHarnessWith(t, withMail, nil)
}

// newHarnessWith lets a test adjust the configuration before the server is
// built.
func newHarnessWith(t *testing.T, withMail bool, adjust func(*config.Config)) *harness {
	t.Helper()
	inst := testdb.New(t)
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	pub, _ := url.Parse(publicOrigin)
	mesh, _ := url.Parse("https://mesh.rmm.test")
	cfg := &config.Config{
		PublicURL: pub, MeshPublicURL: mesh, TLSMode: config.TLSOffload,
		SecretKeys: []secrets.Key{{ID: "k1", Raw: raw}}, DataDir: t.TempDir(),
		RequireMFA: true, SessionIdle: 2 * time.Hour, SessionMaxAge: 12 * time.Hour,
		PasswordResetTTL: 30 * time.Minute, ArgonMaxParallel: 4, AuditRetention: 365 * 24 * time.Hour,
	}
	// Every deployment runs the patching engine with EasyRMM.
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	cfg.Patching = config.Patching{URL: eptest.NewEngine(t, key).URL(), Key: key}
	if adjust != nil {
		adjust(cfg)
	}
	h := &harness{t: t, dataDir: cfg.DataDir, db: inst, cfg: cfg, logs: &lockedBuffer{}}
	log := slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	deps, err := app.Build(context.Background(), cfg, inst.DB, log)
	if err != nil {
		t.Fatal(err)
	}
	h.deps = deps
	if withMail {
		h.mp = testmail.New(t)
		h.useMailpit(h.mp)
	}
	handler, err := app.Handler(cfg, deps, log)
	if err != nil {
		t.Fatal(err)
	}
	h.srv = httptest.NewTLSServer(handler)
	t.Cleanup(h.srv.Close)
	return h
}

// useMailpit sets Mailpit's plain server as the console's mail server.
func (h *harness) useMailpit(mp *testmail.Mailpit) {
	h.t.Helper()
	if _, err := h.deps.Mail.Update(context.Background(), audit.SystemActor("test"), mailserver.Input{Host: mp.Host, Port: mp.Port,
		Security: "none", SignIn: mailserver.SignInPassword, Username: mp.Username, Password: mp.Password, FromAddress: mp.From}); err != nil {
		h.t.Fatal(err)
	}
}

// client is a browser: it keeps cookies, sends the application's Host and
// Origin, and echoes the CSRF token like the web interface does.
type client struct {
	h      *harness
	http   *http.Client
	csrf   string
	origin string
}

func (h *harness) client() *client {
	jar, _ := cookiejar.New(nil)
	// srv.Client() is shared; each browser needs its own cookie jar.
	c := &http.Client{Transport: h.srv.Client().Transport, Jar: jar}
	return &client{h: h, http: c, origin: publicOrigin}
}

type response struct {
	status int
	body   []byte
	header http.Header
}

func (r response) decode(t *testing.T, v any) {
	t.Helper()
	if err := json.Unmarshal(r.body, v); err != nil {
		t.Fatalf("decoding %s: %v", r.body, err)
	}
}

func (r response) errorCode(t *testing.T) string {
	t.Helper()
	var e struct {
		Error struct {
			Code   string            `json:"code"`
			Fields map[string]string `json:"fields"`
		} `json:"error"`
	}
	r.decode(t, &e)
	return e.Error.Code
}

func (c *client) do(method, path string, body any, mutate ...func(*http.Request)) response {
	c.h.t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			c.h.t.Fatal(err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.h.srv.URL+path, rdr)
	if err != nil {
		c.h.t.Fatal(err)
	}
	req.Host = "rmm.test"
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.origin != "" {
		req.Header.Set("Origin", c.origin)
	}
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	for _, m := range mutate {
		m(req)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return response{status: resp.StatusCode, body: b, header: resp.Header}
}

func (c *client) expect(status int, method, path string, body any, out any) response {
	c.h.t.Helper()
	r := c.do(method, path, body)
	if r.status != status {
		c.h.t.Fatalf("%s %s: status %d, want %d: %s", method, path, r.status, status, r.body)
	}
	if out != nil {
		r.decode(c.h.t, out)
	}
	return r
}

type sessionView struct {
	State       string   `json:"state"`
	CSRFToken   string   `json:"csrfToken"`
	Permissions []string `json:"permissions"`
	User        struct {
		ID         string `json:"id"`
		Email      string `json:"email"`
		MFAEnabled bool   `json:"mfaEnabled"`
	} `json:"user"`
}

func code(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	c, err := totp.GenerateCodeCustom(secret, at, totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// signIn logs in and enrolls TOTP when required, returning the secret.
func (c *client) signIn(email, password, secret string) string {
	t := c.h.t
	t.Helper()
	var s sessionView
	c.expect(http.StatusOK, "POST", "/api/v1/auth/login", map[string]string{"email": email, "password": password}, &s)
	c.csrf = s.CSRFToken
	switch s.State {
	case "mfa_enrollment":
		var enr struct {
			Secret    string `json:"secret"`
			QRCodeSVG string `json:"qrCodeSvg"`
		}
		c.expect(http.StatusOK, "POST", "/api/v1/auth/mfa/totp/begin", map[string]string{}, &enr)
		if !strings.HasPrefix(enr.QRCodeSVG, "data:image/svg+xml;base64,") {
			t.Fatalf("qr code is not an svg data url: %.40s", enr.QRCodeSVG)
		}
		var done struct {
			RecoveryCodes []string    `json:"recoveryCodes"`
			Session       sessionView `json:"session"`
		}
		c.expect(http.StatusOK, "POST", "/api/v1/auth/mfa/totp/confirm", map[string]string{"code": code(t, enr.Secret, time.Now())}, &done)
		if len(done.RecoveryCodes) != 10 || done.Session.State != "active" {
			t.Fatalf("enrollment result: %+v", done)
		}
		c.csrf = done.Session.CSRFToken
		return enr.Secret
	case "mfa_required":
		// The enrollment code's time step cannot be replayed; use the next.
		var v sessionView
		c.expect(http.StatusOK, "POST", "/api/v1/auth/mfa/verify", map[string]string{"code": code(t, secret, time.Now().Add(30*time.Second))}, &v)
		if v.State != "active" {
			t.Fatalf("state after mfa = %q", v.State)
		}
		c.csrf = v.CSRFToken
		return secret
	}
	t.Fatalf("unexpected state %q", s.State)
	return ""
}

type idObj struct {
	ID string `json:"id"`
}

func TestHTTPEndToEnd(t *testing.T) {
	h := newHarness(t, false)
	admin := h.client()

	// --- First-run setup -------------------------------------------------
	var st struct {
		Required bool `json:"required"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/setup", nil, &st)
	if !st.Required {
		t.Fatal("setup should be required on an empty database")
	}
	tokenBytes, err := os.ReadFile(filepath.Join(h.dataDir, "setup-token"))
	if err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(filepath.Join(h.dataDir, "setup-token")); info.Mode().Perm() != 0o600 {
		t.Fatalf("setup token mode %v", info.Mode().Perm())
	}
	token := strings.TrimSpace(string(tokenBytes))
	setup := map[string]string{"token": "wrong", "email": "Admin@MSP.example", "displayName": "Ada Admin",
		"password": "correct horse battery staple", "organizationName": "Acme Corp"}
	if r := admin.do("POST", "/api/v1/setup", setup); r.status != http.StatusUnprocessableEntity || r.errorCode(t) != "validation_failed" {
		t.Fatalf("wrong token: %d %s", r.status, r.body)
	}
	setup["token"] = token
	setup["password"] = "password1234"
	if r := admin.do("POST", "/api/v1/setup", setup); r.status != http.StatusUnprocessableEntity || !strings.Contains(string(r.body), `"password"`) {
		t.Fatalf("weak password: %d %s", r.status, r.body)
	}
	setup["password"] = "correct horse battery staple"
	admin.expect(http.StatusNoContent, "POST", "/api/v1/setup", setup, nil)
	if _, err := os.Stat(filepath.Join(h.dataDir, "setup-token")); !os.IsNotExist(err) {
		t.Fatal("setup token file should be removed after setup")
	}
	if r := admin.do("POST", "/api/v1/setup", setup); r.status != http.StatusConflict {
		t.Fatalf("second setup: %d %s", r.status, r.body)
	}

	// --- Sign-in, MFA gating, CSRF ----------------------------------------
	if r := admin.do("POST", "/api/v1/auth/login", map[string]string{"email": "admin@msp.example", "password": "nope nope nope"}); r.status != http.StatusUnauthorized {
		t.Fatalf("bad password: %d", r.status)
	}
	var s sessionView
	admin.expect(http.StatusOK, "POST", "/api/v1/auth/login", map[string]string{"email": "admin@msp.example", "password": "correct horse battery staple"}, &s)
	if s.State != "mfa_enrollment" {
		t.Fatalf("state = %q, want mfa_enrollment", s.State)
	}
	admin.csrf = s.CSRFToken
	if r := admin.do("GET", "/api/v1/organizations", nil); r.status != http.StatusForbidden || r.errorCode(t) != "mfa_required" {
		t.Fatalf("org list before MFA: %d %s", r.status, r.body)
	}
	cookie := s.CSRFToken
	adminSecret := ""
	{
		var enr struct {
			Secret string `json:"secret"`
		}
		admin.expect(http.StatusOK, "POST", "/api/v1/auth/mfa/totp/begin", map[string]string{}, &enr)
		adminSecret = enr.Secret
		if r := admin.do("POST", "/api/v1/auth/mfa/totp/confirm", map[string]string{"code": "000000"}); r.status != http.StatusUnauthorized {
			t.Fatalf("wrong enrollment code: %d %s", r.status, r.body)
		}
		var done struct {
			Session sessionView `json:"session"`
		}
		admin.expect(http.StatusOK, "POST", "/api/v1/auth/mfa/totp/confirm", map[string]string{"code": code(t, adminSecret, time.Now())}, &done)
		admin.csrf = done.Session.CSRFToken
		if admin.csrf == cookie {
			t.Fatal("CSRF token should change when the session is rotated")
		}
	}

	// CSRF: missing token, foreign origin, cross-site fetch metadata.
	noToken := *admin
	noToken.csrf = ""
	if r := noToken.do("POST", "/api/v1/organizations", map[string]string{"name": "X"}); r.status != http.StatusForbidden || r.errorCode(t) != "csrf_failed" {
		t.Fatalf("missing csrf token: %d %s", r.status, r.body)
	}
	evil := *admin
	evil.origin = "https://evil.example"
	if r := evil.do("POST", "/api/v1/organizations", map[string]string{"name": "X"}); r.status != http.StatusForbidden {
		t.Fatalf("foreign origin: %d %s", r.status, r.body)
	}
	if r := admin.do("POST", "/api/v1/organizations", map[string]string{"name": "X"}, func(r *http.Request) {
		r.Header.Set("Sec-Fetch-Site", "cross-site")
	}); r.status != http.StatusForbidden {
		t.Fatalf("cross-site fetch: %d %s", r.status, r.body)
	}

	// --- Tenancy as super admin ------------------------------------------
	var orgs struct {
		Items []struct {
			ID        string `json:"id"`
			Name      string `json:"name"`
			CanManage bool   `json:"canManage"`
		} `json:"items"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/organizations", nil, &orgs)
	if len(orgs.Items) != 1 || orgs.Items[0].Name != "Acme Corp" || !orgs.Items[0].CanManage {
		t.Fatalf("orgs after setup: %+v", orgs)
	}
	orgA := orgs.Items[0].ID
	var orgB idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations", map[string]string{"name": "Globex"}, &orgB)
	if r := admin.do("POST", "/api/v1/organizations", map[string]string{"name": "  globex "}); r.status != http.StatusUnprocessableEntity {
		t.Fatalf("duplicate org name: %d %s", r.status, r.body)
	}
	if r := admin.do("POST", "/api/v1/organizations", map[string]any{"name": "Y", "extra": 1}); r.status != http.StatusUnprocessableEntity {
		t.Fatalf("unknown field: %d %s", r.status, r.body)
	}
	var siteA, siteB, siteA2 idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+orgA+"/sites", map[string]string{"name": "HQ", "timezone": "Europe/London"}, &siteA)
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+orgB.ID+"/sites", map[string]string{"name": "Plant"}, &siteB)
	if r := admin.do("POST", "/api/v1/organizations/"+orgA+"/sites", map[string]string{"name": "Bad TZ", "timezone": "Mars/Base"}); r.status != http.StatusUnprocessableEntity {
		t.Fatalf("bad time zone: %d %s", r.status, r.body)
	}
	var groupB idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/sites/"+siteB.ID+"/device-groups", map[string]string{"name": "Servers"}, &groupB)
	if r := admin.do("DELETE", "/api/v1/organizations/"+orgB.ID, nil); r.status != http.StatusConflict {
		t.Fatalf("deleting non-empty org: %d %s", r.status, r.body)
	}

	// --- Invite an organization administrator for Acme --------------------
	var inv struct {
		User    struct{ ID string } `json:"user"`
		Link    string              `json:"link"`
		Emailed bool                `json:"emailed"`
	}
	admin.expect(http.StatusCreated, "POST", "/api/v1/users", map[string]any{
		"email": "olivia@acme.example", "displayName": "Olivia Org",
		"assignments": []map[string]any{{"role": "org_admin", "organizationId": orgA}},
	}, &inv)
	if inv.Emailed || !strings.HasPrefix(inv.Link, publicOrigin+"/welcome#token=") {
		t.Fatalf("invite without mail should return the link: %+v", inv)
	}
	olivia := h.client()
	olivia.expect(http.StatusNoContent, "POST", "/api/v1/auth/password-reset/complete", map[string]string{
		"token": strings.TrimPrefix(inv.Link, publicOrigin+"/welcome#token="), "password": "a long and unusual passphrase",
	}, nil)
	olivia.signIn("olivia@acme.example", "a long and unusual passphrase", "")

	// --- Cross-tenant isolation (IDOR) ------------------------------------
	olivia.expect(http.StatusOK, "GET", "/api/v1/organizations", nil, &orgs)
	if len(orgs.Items) != 1 || orgs.Items[0].ID != orgA {
		t.Fatalf("org admin sees %+v", orgs.Items)
	}
	for _, p := range []string{
		"/api/v1/organizations/" + orgB.ID,
		"/api/v1/organizations/" + orgB.ID + "/sites",
		"/api/v1/sites/" + siteB.ID,
		"/api/v1/sites/" + siteB.ID + "/device-groups",
	} {
		if r := olivia.do("GET", p, nil); r.status != http.StatusNotFound {
			t.Errorf("GET %s across tenants: %d %s", p, r.status, r.body)
		}
	}
	for _, c := range []struct{ method, path string }{
		{"PUT", "/api/v1/organizations/" + orgB.ID},
		{"PUT", "/api/v1/sites/" + siteB.ID},
		{"DELETE", "/api/v1/sites/" + siteB.ID},
		{"POST", "/api/v1/organizations/" + orgB.ID + "/sites"},
		{"POST", "/api/v1/sites/" + siteB.ID + "/device-groups"},
		{"PUT", "/api/v1/device-groups/" + groupB.ID},
		{"DELETE", "/api/v1/device-groups/" + groupB.ID},
	} {
		var body any
		if c.method != "DELETE" {
			body = map[string]string{"name": "pwned"}
		}
		if r := olivia.do(c.method, c.path, body); r.status != http.StatusNotFound {
			t.Errorf("%s %s across tenants: %d %s", c.method, c.path, r.status, r.body)
		}
	}
	var sitesSeen struct {
		Items []idObj `json:"items"`
	}
	olivia.expect(http.StatusOK, "GET", "/api/v1/sites?organizationId="+orgB.ID, nil, &sitesSeen)
	if len(sitesSeen.Items) != 0 {
		t.Fatalf("filtering by a foreign organization leaked %d sites", len(sitesSeen.Items))
	}
	// Within her own organization she can manage.
	olivia.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+orgA+"/sites", map[string]string{"name": "Branch"}, &siteA2)
	olivia.expect(http.StatusOK, "PUT", "/api/v1/organizations/"+orgA, map[string]string{"name": "Acme Corp", "notes": "Edited by its administrator."}, nil)
	// Names are unique on the server, so only a Super Administrator renames:
	// a rename to a taken name would tell her another customer's name.
	if r := olivia.do("PUT", "/api/v1/organizations/"+orgA, map[string]string{"name": "Globex"}); r.status != http.StatusUnprocessableEntity ||
		!strings.Contains(string(r.body), "Only a Super Administrator can rename") {
		t.Fatalf("org admin renaming to a taken name: %d %s", r.status, r.body)
	}
	// Platform-level actions are not hers.
	if r := olivia.do("POST", "/api/v1/organizations", map[string]string{"name": "Mine"}); r.status != http.StatusForbidden {
		t.Fatalf("org admin creating org: %d %s", r.status, r.body)
	}
	if r := olivia.do("DELETE", "/api/v1/organizations/"+orgA, nil); r.status != http.StatusForbidden {
		t.Fatalf("org admin deleting org: %d %s", r.status, r.body)
	}

	// --- Privilege escalation through user management ---------------------
	for name, as := range map[string][]map[string]any{
		"super admin":    {{"role": "super_admin"}},
		"foreign org":    {{"role": "technician", "organizationId": orgB.ID}},
		"foreign site":   {{"role": "technician", "organizationId": orgB.ID, "siteId": siteB.ID}},
		"site wrong org": {{"role": "technician", "organizationId": orgA, "siteId": siteB.ID}},
	} {
		r := olivia.do("POST", "/api/v1/users", map[string]any{"email": "x-" + strings.ReplaceAll(name, " ", "") + "@acme.example", "displayName": "X", "assignments": as})
		if r.status != http.StatusUnprocessableEntity {
			t.Errorf("escalation %q: %d %s", name, r.status, r.body)
		}
	}
	var tech struct {
		User struct{ ID string } `json:"user"`
	}
	olivia.expect(http.StatusCreated, "POST", "/api/v1/users", map[string]any{
		"email": "tom@acme.example", "displayName": "Tom Tech",
		"assignments": []map[string]any{{"role": "technician", "organizationId": orgA, "siteId": siteA.ID}},
	}, &tech)

	var ulist struct {
		Items []struct {
			ID        string `json:"id"`
			Email     string `json:"email"`
			CanManage bool   `json:"canManage"`
		} `json:"items"`
	}
	olivia.expect(http.StatusOK, "GET", "/api/v1/users", nil, &ulist)
	for _, u := range ulist.Items {
		if u.Email == "admin@msp.example" {
			t.Fatal("org admin can see the platform super admin")
		}
	}
	if len(ulist.Items) != 2 {
		t.Fatalf("org admin user list: %+v", ulist.Items)
	}
	// She cannot change her own access, or the super admin's.
	var me sessionView
	olivia.expect(http.StatusOK, "GET", "/api/v1/auth/session", nil, &me)
	if r := olivia.do("POST", "/api/v1/users/"+me.User.ID+"/disable", nil); r.status != http.StatusConflict {
		t.Fatalf("self disable: %d %s", r.status, r.body)
	}
	var adminSess sessionView
	admin.expect(http.StatusOK, "GET", "/api/v1/auth/session", nil, &adminSess)
	if r := olivia.do("POST", "/api/v1/users/"+adminSess.User.ID+"/disable", nil); r.status != http.StatusNotFound {
		t.Fatalf("org admin disabling super admin: %d %s", r.status, r.body)
	}

	// --- Audit visibility ---------------------------------------------------
	var audit struct {
		Items []struct {
			Action         string  `json:"action"`
			OrganizationID *string `json:"organizationId"`
		} `json:"items"`
	}
	olivia.expect(http.StatusOK, "GET", "/api/v1/audit?limit=500", nil, &audit)
	if len(audit.Items) == 0 {
		t.Fatal("org admin should see her organization's audit log")
	}
	for _, e := range audit.Items {
		if e.OrganizationID == nil || *e.OrganizationID != orgA {
			t.Fatalf("org admin sees foreign audit entry %+v", e)
		}
	}
	if r := olivia.do("GET", "/api/v1/audit/verify", nil); r.status != http.StatusForbidden {
		t.Fatalf("org admin verifying chain: %d", r.status)
	}
	var vr struct {
		Checked    int64  `json:"checked"`
		FirstBadID *int64 `json:"firstBadId"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/audit/verify", nil, &vr)
	if vr.Checked == 0 || vr.FirstBadID != nil {
		t.Fatalf("audit chain: %+v", vr)
	}

	// --- Sessions, disable and last super admin -----------------------------
	if r := admin.do("POST", "/api/v1/users/"+adminSess.User.ID+"/disable", nil); r.status != http.StatusConflict {
		t.Fatalf("super admin disabling self: %d %s", r.status, r.body)
	}
	admin.expect(http.StatusOK, "POST", "/api/v1/users/"+me.User.ID+"/disable", nil, nil)
	if r := olivia.do("GET", "/api/v1/organizations", nil); r.status != http.StatusUnauthorized {
		t.Fatalf("disabled user still signed in: %d %s", r.status, r.body)
	}
	if r := olivia.do("POST", "/api/v1/auth/login", map[string]string{"email": "olivia@acme.example", "password": "a long and unusual passphrase"}); r.status != http.StatusUnauthorized {
		t.Fatalf("disabled user signing in: %d %s", r.status, r.body)
	}

	var sl struct {
		Items []struct {
			ID      string `json:"id"`
			Current bool   `json:"current"`
		} `json:"items"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/auth/sessions", nil, &sl)
	if len(sl.Items) != 1 || !sl.Items[0].Current {
		t.Fatalf("sessions: %+v", sl)
	}

	// A second browser signs in with TOTP (next time step: replay of the
	// enrollment step is refused).
	second := h.client()
	second.signIn("admin@msp.example", "correct horse battery staple", adminSecret)
	admin.expect(http.StatusOK, "GET", "/api/v1/auth/sessions", nil, &sl)
	if len(sl.Items) != 2 {
		t.Fatalf("sessions after second sign-in: %d", len(sl.Items))
	}
	for _, x := range sl.Items {
		if !x.Current {
			admin.expect(http.StatusNoContent, "DELETE", "/api/v1/auth/sessions/"+x.ID, nil, nil)
		}
	}
	if r := second.do("GET", "/api/v1/auth/session", nil); r.status != http.StatusUnauthorized {
		t.Fatalf("revoked session still valid: %d", r.status)
	}

	// --- Misc routing ---------------------------------------------------------
	if r := admin.do("GET", "/api/v1/nope", nil); r.status != http.StatusNotFound || r.errorCode(t) != "not_found" {
		t.Fatalf("unknown api path: %d %s", r.status, r.body)
	}
	if r := admin.do("GET", "/api/v1/organizations", nil, func(r *http.Request) { r.Host = "other.example" }); r.status != http.StatusMisdirectedRequest {
		t.Fatalf("unknown host: %d", r.status)
	}
	r := admin.do("GET", "/api/v1/health", nil)
	if r.header.Get("Content-Security-Policy") == "" || r.header.Get("Strict-Transport-Security") == "" || r.header.Get("X-Frame-Options") != "DENY" {
		t.Fatalf("security headers missing: %v", r.header)
	}

	admin.expect(http.StatusNoContent, "POST", "/api/v1/auth/logout", nil, nil)
	if r := admin.do("GET", "/api/v1/auth/session", nil); r.status != http.StatusUnauthorized {
		t.Fatalf("session after logout: %d", r.status)
	}
}

func TestHTTPPasswordResetByEmail(t *testing.T) {
	h := newHarness(t, true)
	c := h.client()
	token, _ := os.ReadFile(filepath.Join(h.dataDir, "setup-token"))
	c.expect(http.StatusNoContent, "POST", "/api/v1/setup", map[string]string{"token": strings.TrimSpace(string(token)),
		"email": "admin@msp.example", "displayName": "Ada", "password": "correct horse battery staple"}, nil)

	var opts struct {
		PasswordResetAvailable bool `json:"passwordResetAvailable"`
	}
	c.expect(http.StatusOK, "GET", "/api/v1/auth/options", nil, &opts)
	if !opts.PasswordResetAvailable {
		t.Fatal("reset should be available with a mailer")
	}
	// Unknown and known addresses get the same answer.
	r1 := c.expect(http.StatusAccepted, "POST", "/api/v1/auth/password-reset/request", map[string]string{"email": "nobody@msp.example"}, nil)
	r2 := c.expect(http.StatusAccepted, "POST", "/api/v1/auth/password-reset/request", map[string]string{"email": "ADMIN@msp.example"}, nil)
	if !bytes.Equal(r1.body, r2.body) {
		t.Fatal("reset responses differ between known and unknown accounts")
	}
	h.deps.Auth.Wait() // the e-mail goes out after the answer
	sent := h.mp.Received("admin@msp.example")
	if len(sent) != 1 || len(h.mp.Received("nobody@msp.example")) != 0 {
		t.Fatalf("sent mail: %+v", sent)
	}
	i := strings.Index(sent[0].Text, "#token=")
	if i < 0 {
		t.Fatalf("no token in mail: %s", sent[0].Text)
	}
	tok := strings.Fields(sent[0].Text[i+len("#token="):])[0]
	if r := c.do("POST", "/api/v1/auth/password-reset/complete", map[string]string{"token": tok, "password": "short"}); r.status != http.StatusUnprocessableEntity {
		t.Fatalf("weak reset password: %d %s", r.status, r.body)
	}
	c.expect(http.StatusNoContent, "POST", "/api/v1/auth/password-reset/complete", map[string]string{"token": tok, "password": "an entirely new passphrase"}, nil)
	if r := c.do("POST", "/api/v1/auth/password-reset/complete", map[string]string{"token": tok, "password": "yet another passphrase"}); r.status != http.StatusBadRequest {
		t.Fatalf("reused reset token: %d %s", r.status, r.body)
	}
	c.expect(http.StatusOK, "POST", "/api/v1/auth/login", map[string]string{"email": "admin@msp.example", "password": "an entirely new passphrase"}, nil)
}
