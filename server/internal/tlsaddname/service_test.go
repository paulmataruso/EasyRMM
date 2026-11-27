package tlsaddname

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestNormName(t *testing.T) {
	for in, want := range map[string]string{"RMM.Example.com.": "rmm.example.com", " a.b ": "a.b"} {
		if got, err := normName(in); err != nil || got != want {
			t.Errorf("normName(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "localhost", "203.0.113.5", "a b.example.com", "-a.example.com", "a..example.com", "a/b.example.com", "a:443.example.com"} {
		if _, err := normName(in); !errors.Is(err, ErrBadName) {
			t.Errorf("normName(%q) = %v; want ErrBadName", in, err)
		}
	}
}

func TestSameSite(t *testing.T) {
	cases := []struct {
		console, mesh string
		want          bool
	}{
		{"rmm.example.com", "mesh.rmm.example.com", true},
		{"rmm.example.com", "mesh.example.com", true},
		{"rmm.example.com", "mesh.other.org", false},
		{"rmm.example.com", "evilexample.com", false},
		{"example.com", "mesh.example.com", false}, // no parent domain to share
	}
	for _, c := range cases {
		if got := sameSite(c.console, c.mesh); got != c.want {
			t.Errorf("sameSite(%q, %q) = %v; want %v", c.console, c.mesh, got, c.want)
		}
	}
}

func TestNamesFillsTheRemoteAccessName(t *testing.T) {
	c, m, err := (&Service{}).names("RMM.example.com", "")
	if err != nil || c != "rmm.example.com" || m != "mesh.rmm.example.com" {
		t.Fatalf("got %q %q %v", c, m, err)
	}
	if _, _, err := (&Service{}).names("rmm.example.com", "rmm.example.com"); !errors.Is(err, ErrBadName) {
		t.Fatalf("the same name twice: %v", err)
	}
	if _, _, err := (&Service{}).names("rmm.example.com", "mesh.other.org"); !errors.Is(err, ErrNotSameSite) {
		t.Fatalf("another site: %v", err)
	}
}

type fakeResolver map[string][]string

func (f fakeResolver) LookupIPAddr(_ context.Context, h string) ([]net.IPAddr, error) {
	ips, ok := f[h]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: h, IsNotFound: true}
	}
	var out []net.IPAddr
	for _, s := range ips {
		out = append(out, net.IPAddr{IP: net.ParseIP(s)})
	}
	return out, nil
}

func TestPreflight(t *testing.T) {
	s := New(Deps{
		Resolver:  fakeResolver{"rmm.example.com": {"203.0.113.10"}, "mesh.rmm.example.com": {"198.51.100.9"}},
		ServerIPs: func(context.Context) []net.IP { return []net.IP{net.ParseIP("203.0.113.10")} },
	})
	got, err := s.Preflight(context.Background(), "rmm.example.com", "mesh.rmm.example.com")
	if err != nil || len(got) != 2 {
		t.Fatalf("%v %v", got, err)
	}
	if !got[0].Points || got[0].Error != "" {
		t.Errorf("console name: %+v", got[0])
	}
	if got[1].Points || got[1].Error == "" {
		t.Errorf("remote-access name resolves elsewhere and must say so: %+v", got[1])
	}
	got, _ = s.Preflight(context.Background(), "rmm.example.com", "gone.example.com")
	if got[1].Points || len(got[1].Addresses) != 0 || got[1].Error == "" {
		t.Errorf("unresolvable name: %+v", got[1])
	}
}

func TestReachableWithinGrace(t *testing.T) {
	now := time.Now()
	ago := func(d time.Duration) *time.Time { t := now.Add(-d); return &t }
	for name, c := range map[string]struct {
		p    Pair
		want bool
	}{
		"never":           {Pair{}, false},
		"fetch fresh":     {Pair{LastFetchOKAt: ago(time.Hour)}, true},
		"browser only":    {Pair{LastBrowserOKAt: ago(3 * 24 * time.Hour)}, true},
		"both past grace": {Pair{LastFetchOKAt: ago(8 * 24 * time.Hour), LastBrowserOKAt: ago(9 * 24 * time.Hour)}, false},
		"browser rescues": {Pair{LastFetchOKAt: ago(8 * 24 * time.Hour), LastBrowserOKAt: ago(time.Hour)}, true},
	} {
		if got := reachable(&c.p, now); got != c.want {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
}
