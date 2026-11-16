package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

const (
	testOrigin   = "https://rmm.example.com"
	testIPOrigin = "https://203.0.113.10"
)

type fakeResolver struct {
	sessions     map[string]*auth.Session
	users        map[uuid.UUID]*auth.User
	assignments  map[uuid.UUID][]rbac.Assignment
	authErr      error
	principalErr error
	principals   int
}

func (f *fakeResolver) Authenticate(_ context.Context, token string) (*auth.Session, *auth.User, error) {
	if f.authErr != nil {
		return nil, nil, f.authErr
	}
	s, ok := f.sessions[token]
	if !ok {
		return nil, nil, auth.ErrInvalidSession
	}
	return s, f.users[s.UserID], nil
}

func (f *fakeResolver) LoadPrincipal(_ context.Context, userID uuid.UUID) (*rbac.Principal, error) {
	f.principals++
	if f.principalErr != nil {
		return nil, f.principalErr
	}
	return rbac.NewPrincipal(userID, f.assignments[userID])
}

type fixture struct {
	res      *fakeResolver
	sessions *Sessions
	orgID    uuid.UUID
	userID   uuid.UUID
}

func newFixture(t *testing.T, secure bool) *fixture {
	t.Helper()
	userID, orgID := uuid.New(), uuid.New()
	res := &fakeResolver{
		sessions: map[string]*auth.Session{
			"active-token":  {ID: uuid.New(), UserID: userID, State: auth.StateActive},
			"pending-token": {ID: uuid.New(), UserID: userID, State: auth.StateMFARequired},
		},
		users:       map[uuid.UUID]*auth.User{userID: {ID: userID, Email: "tech@example.com", Status: "active"}},
		assignments: map[uuid.UUID][]rbac.Assignment{userID: {{Role: rbac.RoleTechnician, OrganizationID: orgID}}},
	}
	s, err := NewSessions(res, []byte("0123456789abcdef0123456789abcdef"), []string{testOrigin, testIPOrigin + "/"}, secure)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{res: res, sessions: s, orgID: orgID, userID: userID}
}

// load runs a request through Sessions.Load and returns what the handler
// saw.
func (f *fixture) load(t *testing.T, token string) (*Identity, *httptest.ResponseRecorder, bool) {
	t.Helper()
	var seen *Identity
	called := false
	h := f.sessions.Load(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		called = true
		seen = IdentityFrom(r.Context())
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if token != "" {
		req.AddCookie(&http.Cookie{Name: f.sessions.CookieName(), Value: token})
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return seen, rec, called
}

func TestCookieNames(t *testing.T) {
	if n := newFixture(t, true).sessions.CookieName(); n != "__Host-easyrmm_session" {
		t.Fatalf("secure cookie name = %q", n)
	}
	if n := newFixture(t, false).sessions.CookieName(); n != "easyrmm_session" {
		t.Fatalf("insecure cookie name = %q", n)
	}
}

func TestSetAndClearCookie(t *testing.T) {
	f := newFixture(t, true)
	rec := httptest.NewRecorder()
	exp := time.Now().Add(time.Hour)
	f.sessions.SetCookie(rec, "tok", exp)
	c := rec.Result().Cookies()[0]
	if c.Name != "__Host-easyrmm_session" || c.Value != "tok" || c.Path != "/" || c.Domain != "" ||
		!c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("set cookie = %+v", c)
	}
	if c.Expires.Unix() != exp.Unix() {
		t.Fatalf("expires = %v, want %v", c.Expires, exp)
	}

	rec = httptest.NewRecorder()
	f.sessions.ClearCookie(rec)
	c = rec.Result().Cookies()[0]
	if c.Value != "" || c.MaxAge >= 0 || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("clear cookie = %+v", c)
	}

	rec = httptest.NewRecorder()
	newFixture(t, false).sessions.SetCookie(rec, "tok", exp)
	if c := rec.Result().Cookies()[0]; c.Secure || !c.HttpOnly {
		t.Fatalf("development cookie = %+v", c)
	}
}

func TestCSRFTokenDerivation(t *testing.T) {
	f := newFixture(t, true)
	a, b := f.sessions.CSRFToken("token-a"), f.sessions.CSRFToken("token-b")
	if a == "" || a == b || a != f.sessions.CSRFToken("token-a") {
		t.Fatalf("csrf tokens a=%q b=%q", a, b)
	}
	// A different master key gives unrelated tokens.
	other, err := NewSessions(f.res, []byte("another key of thirty-two bytes!"), []string{testOrigin}, true)
	if err != nil {
		t.Fatal(err)
	}
	if other.CSRFToken("token-a") == a {
		t.Fatal("CSRF token does not depend on the key")
	}
}

func TestLoadNoCookie(t *testing.T) {
	f := newFixture(t, true)
	id, _, called := f.load(t, "")
	if !called || id != nil {
		t.Fatalf("called=%v identity=%v", called, id)
	}
}

func TestLoadInvalidCookieIsCleared(t *testing.T) {
	f := newFixture(t, true)
	id, rec, called := f.load(t, "stale-token")
	if !called || id != nil {
		t.Fatalf("called=%v identity=%v", called, id)
	}
	cs := rec.Result().Cookies()
	if len(cs) != 1 || cs[0].MaxAge >= 0 {
		t.Fatalf("stale cookie not cleared: %+v", cs)
	}
}

func TestLoadResolverError(t *testing.T) {
	f := newFixture(t, true)
	f.res.authErr = errors.New("database down")
	_, rec, called := f.load(t, "active-token")
	if called || rec.Code != http.StatusInternalServerError {
		t.Fatalf("called=%v status=%d", called, rec.Code)
	}
}

func TestLoadPrincipalError(t *testing.T) {
	f := newFixture(t, true)
	f.res.principalErr = errors.New("database down")
	_, rec, called := f.load(t, "active-token")
	if called || rec.Code != http.StatusInternalServerError {
		t.Fatalf("called=%v status=%d", called, rec.Code)
	}
}

func TestLoadActiveSession(t *testing.T) {
	f := newFixture(t, true)
	id, _, _ := f.load(t, "active-token")
	if id == nil || id.Principal == nil || id.User.Email != "tech@example.com" {
		t.Fatalf("identity = %+v", id)
	}
	if id.Token != "active-token" || id.CSRFToken != f.sessions.CSRFToken("active-token") {
		t.Fatalf("token/csrf = %q/%q", id.Token, id.CSRFToken)
	}
	if len(id.Scope.Orgs) != 1 || id.Scope.Orgs[0] != f.orgID || id.Scope.All {
		t.Fatalf("scope = %+v", id.Scope)
	}
}

func TestLoadPendingSessionHasNoPrincipal(t *testing.T) {
	f := newFixture(t, true)
	id, _, _ := f.load(t, "pending-token")
	if id == nil || id.Principal != nil || f.res.principals != 0 {
		t.Fatalf("identity = %+v, principal loads = %d", id, f.res.principals)
	}
}

func csrfRequest(method string, headers map[string]string, id *Identity) *http.Request {
	req := httptest.NewRequest(method, "/api/v1/x", strings.NewReader("{}"))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if id != nil {
		req = req.WithContext(context.WithValue(req.Context(), identityKey{}, id))
	}
	return req
}

func TestCSRF(t *testing.T) {
	f := newFixture(t, true)
	id := &Identity{CSRFToken: f.sessions.CSRFToken("active-token")}
	cases := []struct {
		name    string
		method  string
		headers map[string]string
		id      *Identity
		pass    bool
	}{
		{"GET is safe", http.MethodGet, nil, id, true},
		{"HEAD is safe", http.MethodHead, nil, nil, true},
		{"OPTIONS is safe", http.MethodOptions, nil, nil, true},
		{"POST without provenance", http.MethodPost, nil, nil, false},
		{"anonymous same-origin fetch", http.MethodPost, map[string]string{"Sec-Fetch-Site": "same-origin"}, nil, true},
		{"anonymous cross-site fetch", http.MethodPost, map[string]string{"Sec-Fetch-Site": "cross-site"}, nil, false},
		{"same-site is not same-origin", http.MethodPost, map[string]string{"Sec-Fetch-Site": "same-site"}, nil, false},
		{"fetch metadata outranks origin", http.MethodPost, map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": testOrigin}, nil, false},
		{"anonymous matching origin", http.MethodPost, map[string]string{"Origin": testOrigin}, nil, true},
		{"anonymous IP address origin", http.MethodPost, map[string]string{"Origin": testIPOrigin}, nil, true},
		{"IP address with another port", http.MethodPost, map[string]string{"Origin": testIPOrigin + ":4443"}, nil, false},
		{"empty origin", http.MethodPost, map[string]string{"Origin": ""}, nil, false},
		{"anonymous foreign origin", http.MethodPost, map[string]string{"Origin": "https://evil.example"}, nil, false},
		{"origin null", http.MethodPost, map[string]string{"Origin": "null"}, nil, false},
		{"session without token", http.MethodPost, map[string]string{"Sec-Fetch-Site": "same-origin"}, id, false},
		{"session with wrong token", http.MethodDelete, map[string]string{"Sec-Fetch-Site": "same-origin", "X-CSRF-Token": "forged"}, id, false},
		{"session with token", http.MethodPut, map[string]string{"Sec-Fetch-Site": "same-origin", "X-CSRF-Token": id.CSRFToken}, id, true},
		{"session with token, foreign origin", http.MethodPatch, map[string]string{"Origin": "https://evil.example", "X-CSRF-Token": id.CSRFToken}, id, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			called := false
			h := f.sessions.CSRF(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, csrfRequest(c.method, c.headers, c.id))
			if called != c.pass {
				t.Fatalf("passed=%v, want %v (status %d)", called, c.pass, rec.Code)
			}
			if !c.pass {
				if rec.Code != http.StatusForbidden || decodeError(t, rec).Code != "csrf_failed" {
					t.Fatalf("rejection: %d %s", rec.Code, rec.Body.String())
				}
			}
		})
	}
}

func withIdentity(r *http.Request, id *Identity) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), identityKey{}, id))
}

func TestRequireState(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	pending := &Identity{Session: &auth.Session{State: auth.StateMFARequired}}
	active := &Identity{Session: &auth.Session{State: auth.StateActive}}

	rec := httptest.NewRecorder()
	RequireActive(ok).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusUnauthorized || decodeError(t, rec).Code != "unauthenticated" {
		t.Fatalf("anonymous: %d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	RequireActive(ok).ServeHTTP(rec, withIdentity(httptest.NewRequest(http.MethodGet, "/", nil), pending))
	if rec.Code != http.StatusForbidden || decodeError(t, rec).Code != "mfa_required" {
		t.Fatalf("pending: %d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	RequireActive(ok).ServeHTTP(rec, withIdentity(httptest.NewRequest(http.MethodGet, "/", nil), active))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("active: %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	RequireState(auth.StateMFARequired, auth.StateMFAEnrollment)(ok).
		ServeHTTP(rec, withIdentity(httptest.NewRequest(http.MethodGet, "/", nil), pending))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("listed state: %d", rec.Code)
	}
}

func TestCanActorCallerMeta(t *testing.T) {
	f := newFixture(t, true)
	p, err := rbac.NewPrincipal(f.userID, f.res.assignments[f.userID])
	if err != nil {
		t.Fatal(err)
	}
	user := f.res.users[f.userID]
	id := &Identity{User: user, Principal: p, Session: &auth.Session{State: auth.StateActive}}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.0.2.10:999"
	req.Header.Set("User-Agent", "test-agent")

	// Anonymous.
	if Can(req, rbac.PermDeviceView, rbac.Org(f.orgID)) {
		t.Fatal("anonymous request has permissions")
	}
	a := Actor(req)
	if a.Type != audit.ActorUser || a.ID != uuid.Nil || a.Label != "" || a.SourceIP.String() != "192.0.2.10" || a.UserAgent != "test-agent" {
		t.Fatalf("anonymous actor = %+v", a)
	}
	c := Caller(req)
	if c.Can(rbac.PermDeviceView, rbac.Org(f.orgID)) || c.IsSystem() {
		t.Fatal("anonymous caller has permissions")
	}
	m := Meta(req)
	if m.IP.String() != "192.0.2.10" || m.UserAgent != "test-agent" {
		t.Fatalf("meta = %+v", m)
	}

	// Signed in.
	req = withIdentity(req, id)
	if !Can(req, rbac.PermDeviceView, rbac.Org(f.orgID)) {
		t.Fatal("technician cannot view devices in their organization")
	}
	if Can(req, rbac.PermDeviceView, rbac.Org(uuid.New())) {
		t.Fatal("technician can view devices in another organization")
	}
	a = Actor(req)
	if a.ID != f.userID || a.Label != "tech@example.com" {
		t.Fatalf("actor = %+v", a)
	}
	c = Caller(req)
	if !c.Can(rbac.PermScriptRun, rbac.Org(f.orgID)) || c.Can(rbac.PermUserManage, rbac.Org(f.orgID)) {
		t.Fatal("caller permissions do not match the principal")
	}
	if c.Actor.ID != f.userID {
		t.Fatalf("caller actor = %+v", c.Actor)
	}
}
