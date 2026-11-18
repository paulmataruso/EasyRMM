package easypatch

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// golden is testdata/gateway-statement.json: one statement that EasyPatch's
// tests check the engine accepts, so the two sides cannot drift apart.
type golden struct {
	Now           int64       `json:"now"`
	Method        string      `json:"method"`
	Target        string      `json:"target"`
	Subject       string      `json:"subject"`
	Name          string      `json:"name"`
	Role          string      `json:"role"`
	Organizations []uuid.UUID `json:"organizations"`
	Header        string      `json:"header"`
	Payload       string      `json:"payload"`
	Signature     string      `json:"signature"`
}

func readGolden(t *testing.T) golden {
	t.Helper()
	b, err := os.ReadFile("testdata/gateway-statement.json")
	if err != nil {
		t.Fatal(err)
	}
	var g golden
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatal(err)
	}
	return g
}

func TestStatementMatchesWhatEasyPatchAccepts(t *testing.T) {
	g := readGolden(t)
	key := make([]byte, 32) // the test key: bytes 0 to 31
	for i := range key {
		key[i] = byte(i)
	}
	s, err := NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return time.Unix(g.Now, 0) }
	got, err := s.Sign(Statement{Subject: g.Subject, Name: g.Name, Role: g.Role, Organizations: g.Organizations}, g.Method, g.Target)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	want := enc([]byte(g.Header)) + "." + enc([]byte(g.Payload)) + "." + g.Signature
	if got != want {
		t.Fatalf("the signer's statement changed; EasyPatch's tests check the one in testdata:\n got %s\nwant %s", got, want)
	}
}

func TestStatementClaims(t *testing.T) {
	key := []byte(strings.Repeat("k", 32))
	s, _ := NewSigner(key)
	now := time.Unix(1795521600, 0)
	s.now = func() time.Time { return now }
	decode := func(tok string) map[string]any {
		t.Helper()
		parts := strings.Split(tok, ".")
		if len(parts) != 3 {
			t.Fatalf("%d parts", len(parts))
		}
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(parts[0] + "." + parts[1]))
		if enc := base64.RawURLEncoding.EncodeToString(mac.Sum(nil)); enc != parts[2] {
			t.Fatal("not signed with the key")
		}
		b, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}

	// EasyRMM's own work names every organization.
	sign := func(st Statement, method, target string) string {
		t.Helper()
		tok, err := s.Sign(st, method, target)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	all := decode(sign(Statement{Subject: ServiceSubject, Name: "EasyRMM", Role: RoleSuperAdmin, AllOrganizations: true}, "PUT", "/api/v1/settings"))
	if all["orgs"] != "*" || all["sub"] != "service" || all["exp"].(float64)-all["iat"].(float64) != StatementLifetime.Seconds() {
		t.Errorf("service statement: %v", all)
	}
	// A person's call names only the organizations it concerns, and an empty
	// list stays a list (none), never "every one".
	none := decode(sign(Statement{Subject: "u1", Name: "jane@example.com", Role: RoleReadOnly}, "GET", "/api/v1/endpoints"))
	if orgs, ok := none["orgs"].([]any); !ok || len(orgs) != 0 {
		t.Errorf("no organizations became %v", none["orgs"])
	}

	for name, c := range map[string]struct {
		s              Statement
		method, target string
	}{
		"no subject":      {Statement{Name: "x", Role: RoleAdmin}, "GET", "/"},
		"no name":         {Statement{Subject: "x", Role: RoleAdmin}, "GET", "/"},
		"unknown role":    {Statement{Subject: "x", Name: "x", Role: "Owner"}, "GET", "/"},
		"no method":       {Statement{Subject: "x", Name: "x", Role: RoleAdmin}, "", "/"},
		"relative target": {Statement{Subject: "x", Name: "x", Role: RoleAdmin}, "GET", "api/v1"},
	} {
		if _, err := s.Sign(c.s, c.method, c.target); err == nil {
			t.Errorf("%s: signed", name)
		}
	}
	if _, err := NewSigner(make([]byte, 31)); err == nil {
		t.Error("a 31-byte key was accepted")
	}
}
