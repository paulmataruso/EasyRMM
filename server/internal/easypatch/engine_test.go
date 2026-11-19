package easypatch

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/easypatch/eptest"
)

func engineClient(t *testing.T, url string, key []byte) *Client {
	t.Helper()
	s, err := NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewEngineClient(url, s, "test")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The console sees what an EasyPatch answer means for it.
func TestEngineErrorsForTheConsole(t *testing.T) {
	for name, tc := range map[string]struct {
		err  *Error
		kind apperr.Kind
		code string
	}{
		"field errors":           {&Error{Status: 400, Code: "validation_failed", Detail: "name: x", Fields: map[string]string{"name": "x"}}, apperr.KindInvalid, ""},
		"engine unreachable":     {&Error{Detail: "Cannot reach the patching engine: connection refused"}, apperr.KindUnavailable, "patching_unavailable"},
		"engine failing":         {&Error{Status: 503, Detail: "The database is not available."}, apperr.KindUnavailable, "patching_unavailable"},
		"engine refuses the key": {&Error{Status: 401, Detail: "not valid"}, apperr.KindUnavailable, "patching_unavailable"},
		"engine refuses a role":  {&Error{Status: 403, Detail: "no"}, apperr.KindUnavailable, "patching_unavailable"},
		"engine: not found":      {&Error{Status: 404, Detail: "not found"}, apperr.KindNotFound, ""},
		"engine: duplicate job":  {&Error{Status: 409, Code: "duplicate_job", Detail: "queued"}, apperr.KindConflict, "duplicate_job"},
		"engine: refused":        {&Error{Status: 400, Detail: "bad"}, apperr.KindConflict, "easypatch_refused"},
	} {
		t.Run(name, func(t *testing.T) {
			ae, ok := apperr.As(epError(tc.err))
			if !ok || ae.Kind != tc.kind || (tc.code != "" && ae.Code != tc.code) {
				t.Fatalf("%#v", epError(tc.err))
			}
			if tc.kind == apperr.KindInvalid && ae.Fields["name"] != "x" {
				t.Errorf("fields %v", ae.Fields)
			}
		})
	}
	if got := (&Error{Status: 401, Detail: "x"}).Error(); !strings.HasPrefix(got, "The patching engine answered 401") {
		t.Errorf("message %q", got)
	}
}

func TestProblemFields(t *testing.T) {
	e := problem(400, []byte(`{"code":"validation_failed","detail":"name: Name must be 1-100 characters.",
		"errors":{"name":["Name must be 1-100 characters.","second"],"emailRecipients":["Enter 1 to 20 email addresses."],"empty":[]}}`))
	if e.Code != "validation_failed" || len(e.Fields) != 2 || e.Fields["name"] != "Name must be 1-100 characters." || e.Fields["emailRecipients"] == "" {
		t.Fatalf("%+v", e)
	}
	if e := problem(409, []byte(`{"code":"duplicate_job","detail":"queued"}`)); e.Fields != nil {
		t.Errorf("fields without errors: %+v", e.Fields)
	}
}

// What Settings shows of the engine, from looking at it.
func TestEngineProbe(t *testing.T) {
	key := bytes.Repeat([]byte{3}, 32)
	srv := eptest.NewEngine(t, key)
	e := &engine{client: engineClient(t, srv.URL(), key)}
	ctx := context.Background()
	now := time.Now()

	if r := e.row(ctx, now, false); r.lastError != "" || r.version != "1.9.0" || r.capabilities == nil || r.url != srv.URL() {
		t.Fatalf("healthy: %+v", r)
	}
	// Read again only when due, or when asked.
	srv.Set(func() { srv.Version = "1.9.1" })
	if r := e.row(ctx, now.Add(time.Minute), false); r.version != "1.9.0" {
		t.Errorf("read again before it was due: %+v", r)
	}
	if r := e.row(ctx, now.Add(engineCheckEvery), false); r.version != "1.9.1" {
		t.Errorf("not read again when due: %+v", r)
	}
	// Each failure keeps what it last saw of a healthy engine.
	for _, tc := range []struct {
		name           string
		version        string
		readOnly, down bool
		want           string
	}{
		{"no version", "", false, false, "does not answer like EasyPatch"},
		{"not an admin", "1.9.1", true, false, "does not let EasyRMM act as an administrator"},
		{"down", "1.9.1", false, true, "503"},
	} {
		srv.Set(func() { srv.Version, srv.ReadOnly, srv.Down = tc.version, tc.readOnly, tc.down })
		if r := e.row(ctx, now, true); !strings.Contains(r.lastError, tc.want) || r.lastErrorAt == nil || r.version != "1.9.1" {
			t.Errorf("%s: %+v", tc.name, r)
		}
	}
	// It recovers.
	srv.Set(func() { srv.Version, srv.ReadOnly, srv.Down = "1.9.1", false, false })
	if r := e.row(ctx, now, true); r.lastError != "" || r.lastErrorAt != nil {
		t.Errorf("recovered: %+v", r)
	}
	e.noted("The patching engine answered 503: busy", now)
	if r := e.row(ctx, now, false); r.lastError == "" {
		t.Errorf("a failed call is not shown: %+v", r)
	}
}

func TestEngineStatements(t *testing.T) {
	s := &Service{}
	user := access.Caller{Actor: audit.Actor{Type: audit.ActorUser, ID: uuid.New(), Label: "tess@example.com"}}
	org := uuid.New()
	st := statementFor(s.as(context.Background(), user, RoleAdmin, org, org, uuid.Nil), "")
	if st.Subject != user.Actor.ID.String() || st.Name != "tess@example.com" || st.Role != RoleAdmin || st.AllOrganizations ||
		len(st.Organizations) != 1 || st.Organizations[0] != org {
		t.Fatalf("a person's statement: %+v", st)
	}
	// Work no person asked for in person is EasyRMM's.
	system := access.Caller{Actor: audit.SystemActor("")}
	if st := statementFor(s.as(context.Background(), system, RoleReadOnly), ""); st.Subject != ServiceSubject || st.Name != "EasyRMM" ||
		st.Organizations == nil || len(st.Organizations) != 0 {
		t.Fatalf("EasyRMM's statement: %+v", st)
	}
	// Without one: EasyRMM, Admin everywhere, named after whom it is for.
	if st := statementFor(context.Background(), "ada@example.com"); st.Subject != ServiceSubject || st.Name != "ada@example.com" ||
		st.Role != RoleAdmin || !st.AllOrganizations {
		t.Fatalf("default statement: %+v", st)
	}

	// Names are cleaned rather than refused; subjects are bounded.
	g, _ := NewSigner(bytes.Repeat([]byte{4}, 32))
	tok, err := g.Sign(Statement{Subject: "u", Name: "Ada\nLovelace\t", Role: RoleReadOnly}, "GET", "/api/v1/endpoints")
	if err != nil || !strings.Contains(decodePayload(t, tok), `"name":"Ada Lovelace"`) {
		t.Fatalf("cleaned name: %v %s", err, decodePayload(t, tok))
	}
	if _, err := g.Sign(Statement{Subject: strings.Repeat("s", 129), Name: "x", Role: RoleReadOnly}, "GET", "/"); err == nil {
		t.Error("a 129-character subject was signed")
	}
	if _, err := g.Sign(Statement{Subject: "u", Name: "\n\t", Role: RoleReadOnly}, "GET", "/"); err == nil {
		t.Error("a name of control characters only was signed")
	}
}

func TestEngineClient(t *testing.T) {
	key := bytes.Repeat([]byte{2}, 32)
	signer, _ := NewSigner(key)
	for _, bad := range []string{"://", "http://", "http://example.com:18180", "https://127.0.0.1:18180", "ftp://127.0.0.1:1"} {
		if _, err := NewEngineClient(bad, signer, "test"); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	if _, err := NewEngineClient("http://127.0.0.1:18180", nil, "test"); err == nil {
		t.Error("no signer was accepted")
	}
	if c := engineClient(t, "http://[::1]:18180/", key); c.base.String() != "http://[::1]:18180" {
		t.Errorf("client %v", c.base)
	}

	// A statement is made for one request: a redirect is not followed.
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	t.Cleanup(redirect.Close)
	_, err := engineClient(t, redirect.URL, key).Organizations(context.Background())
	var e *Error
	if !errors.As(err, &e) || e.Status != http.StatusFound {
		t.Fatalf("redirect: %#v", err)
	}
	// Nothing listening.
	closed := httptest.NewServer(http.NotFoundHandler())
	url := closed.URL
	closed.Close()
	_, err = engineClient(t, url, key).Organizations(context.Background())
	if !errors.As(err, &e) || e.Status != 0 || !strings.Contains(e.Detail, "Cannot reach the patching engine") {
		t.Fatalf("closed: %#v", err)
	}
}

func decodePayload(t *testing.T, tok string) string {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return ""
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
