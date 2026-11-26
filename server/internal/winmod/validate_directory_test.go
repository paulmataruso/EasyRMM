package winmod

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"unicode"

	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

func directoryAction() Action {
	a := sample()
	a.Params = []Param{
		{Name: "id", Type: SID, RefuseWellKnown: true},
		{Name: "ou", Type: DN},
		{Name: "sam", Type: Name, Pattern: regexp.MustCompile(`^[a-z]{1,5}$`)},
		{Name: "title", Type: Text, Max: 20, AllowEmpty: true},
		{Name: "password", Type: Text, Min: 8, Max: 64, Secret: true, Generate: true, Needs: rbac.PermADResetPassword},
	}
	return a
}

func TestDirectoryParameterTypes(t *testing.T) {
	a := directoryAction()
	ok := func(doc string) *Checked {
		t.Helper()
		c, err := a.Validate(json.RawMessage(doc))
		if err != nil {
			t.Fatalf("%s: %v", doc, err)
		}
		return c
	}
	bad := func(doc string) {
		t.Helper()
		if _, err := a.Validate(json.RawMessage(doc)); err == nil {
			t.Errorf("%s was accepted", doc)
		}
	}
	ok(`{"id":"S-1-5-21-1-2-3-1104","ou":"OU=Staff,DC=corp,DC=test","sam":"abc"}`)
	bad(`{"id":"S-1-5-21-1-2-3-999"}`)
	bad(`{"id":"S-1-5-32-544"}`)
	bad(`{"id":"S-1-5-21-1-2-3-04"}`)
	bad(`{"id":5}`)
	bad(`{"ou":"OU=Staff;DC=corp"}`)
	bad(`{"ou":5}`)
	bad(`{"sam":"ABC"}`)
	bad(`{"sam":"abcdef"}`)
	// An empty text is allowed only where it clears.
	if c := ok(`{"title":""}`); !strings.Contains(string(c.Params), `"title":""`) {
		t.Errorf("params %s", c.Params)
	}
	bad(`{"sam":""}`)
	bad(`{"title":"x\ny"}`)
}

func TestGeneratedSecretsAreSealedNotStored(t *testing.T) {
	a := directoryAction()
	c, err := a.Validate(json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	pw := c.Generated["password"]
	if len(pw) != 20 || c.Secrets["password"] != pw || c.Audit["password"] != "(secret)" || strings.Contains(string(c.Params), pw) {
		t.Fatalf("generated %q, secrets %v, audit %v, params %s", pw, c.Secrets, c.Audit, c.Params)
	}
	// A password the request carries is used as it is and nothing is generated.
	c, err = a.Validate(json.RawMessage(`{"password":"Typed-Password-1"}`))
	if err != nil || len(c.Generated) != 0 || c.Secrets["password"] != "Typed-Password-1" {
		t.Errorf("typed: %v %v", c, err)
	}
	// A secret that cannot be generated, or an optional one that is required, is a catalog error.
	for _, p := range []Param{
		{Name: "x", Type: Text, Generate: true},
		{Name: "x", Type: Text, Secret: true, Generate: true, Required: true},
		{Name: "x", Type: Text, RefuseWellKnown: true},
		{Name: "x", Type: Int, Pattern: regexp.MustCompile("a")},
	} {
		b := sample()
		b.Params = []Param{p}
		if _, err := NewCatalog(b); err == nil {
			t.Errorf("%+v was accepted by the catalog", p)
		}
	}
}

func TestGeneratedPasswordsVaryAndHaveEveryClass(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		pw, err := GeneratePassword()
		if err != nil {
			t.Fatal(err)
		}
		if seen[pw] || len(pw) != passwordLength {
			t.Fatalf("%q repeats or has the wrong length", pw)
		}
		seen[pw] = true
		var up, lo, di, sy bool
		for _, r := range pw {
			up, lo, di, sy = up || unicode.IsUpper(r), lo || unicode.IsLower(r), di || unicode.IsDigit(r), sy || strings.ContainsRune(pwSymbol, r)
			if strings.ContainsRune("0O1lIo|", r) {
				t.Fatalf("look-alike %q in %q", r, pw)
			}
		}
		if !up || !lo || !di || !sy {
			t.Fatalf("%q lacks a class", pw)
		}
	}
}
