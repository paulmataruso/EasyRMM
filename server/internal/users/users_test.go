package users_test

import (
	"strings"
	"testing"

	"github.com/paulmataruso/easyrmm/server/internal/users"
)

func TestNormalizeEmail(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"Ada@Example.COM", "ada@example.com", true},
		{"  bob@example.org\t", "bob@example.org", true},
		{"first.last+tag@sub.example.co.uk", "first.last+tag@sub.example.co.uk", true},
		{"no-at-sign.example.com", "no-at-sign.example.com", false},
		{"@example.com", "@example.com", false},
		{"user@", "user@", false},
		{"user@localhost", "user@localhost", false},
		{"a b@example.com", "a b@example.com", false},
		{"Ada <ada@example.com>", "ada <ada@example.com>", false},
		{"x@y.z,other@example.com", "x@y.z,other@example.com", false},
		{"\"quoted\"@example.com", "\"quoted\"@example.com", false},
		{"ab", "ab", false},
		{"a@b.c" + strings.Repeat("c", 250), "a@b.c" + strings.Repeat("c", 250), false},
	}
	for _, c := range cases {
		got, ok := users.NormalizeEmail(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("NormalizeEmail(%q) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}
