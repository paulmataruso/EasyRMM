package addrpolicy

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
)

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func testEnv() *Env {
	return &Env{
		Addrs:  []netip.Addr{addr("203.0.113.5"), addr("198.18.9.9")},
		Nets:   []netip.Prefix{netip.MustParsePrefix("8.8.8.0/24"), netip.MustParsePrefix("2a00:1450::/32")},
		Routed: []netip.Prefix{netip.MustParsePrefix("9.9.9.0/24")},
		NAT64:  []netip.Prefix{netip.MustParsePrefix("2001:db8:64::/96")},
		Names:  []string{"rmm.example.com"},
	}
}

func TestRefuseOrganization(t *testing.T) {
	env := testEnv()
	approved := []netip.Prefix{netip.MustParsePrefix("10.1.2.3/32"), netip.MustParsePrefix("8.8.8.8/32")}
	for _, c := range []struct {
		a      string
		refuse bool
	}{
		// Public addresses go.
		{"93.184.216.34", false},
		{"2606:2800:220:1::1", false},
		// Always refused, IPv4 and IPv6.
		{"127.0.0.1", true}, {"::1", true}, {"0.0.0.0", true}, {"::", true}, {"169.254.169.254", true},
		{"fe80::1", true}, {"224.0.0.1", true}, {"ff02::1", true}, {"255.255.255.255", true}, {"240.0.0.1", true},
		{"192.0.0.9", true}, {"192.0.2.1", true}, {"198.51.100.1", true}, {"203.0.113.9", true}, {"2001:db8::1", true},
		{"198.18.0.1", true}, {"100::1", true}, {"fec0::1", true}, {"64:ff9b:1::1", true}, {"2001::1", true},
		{"fd00:ec2::254", true}, {"100.100.100.200", true},
		// The server itself, even though it is a documentation address.
		{"198.18.9.9", true},
		// Embedded IPv4, mapped and the rest.
		{"::ffff:127.0.0.1", true}, {"::ffff:169.254.169.254", true}, {"64:ff9b::7f00:1", true}, {"64:ff9b::a9fe:a9fe", true},
		{"2002:7f00:1::", true}, {"::7f00:1", true}, {"::a9fe:a9fe", true},
		{"2001:db8:64::7f00:1", true}, // the network's own NAT64 prefix
		{"64:ff9b::5db8:d822", false}, // NAT64 of a public address
		// Private: refused until approved, then allowed only inside the approval.
		{"10.1.2.3", false}, {"10.1.2.4", true}, {"192.168.0.1", true}, {"172.16.0.1", true}, {"100.64.0.1", true}, {"fd12::1", true},
		{"::ffff:10.1.2.3", false}, {"::ffff:10.1.2.4", true}, {"64:ff9b::a01:204", true}, {"2002:0a01:0204::", true},
		// The server's own networks and routed destinations need approval too.
		{"8.8.8.8", false}, {"8.8.8.9", true}, {"9.9.9.9", true}, {"2a00:1450::1", true},
	} {
		got := Refuse(env, Organization, addr(c.a), approved) != ""
		if got != c.refuse {
			t.Errorf("%s: refused %v, want %v", c.a, got, c.refuse)
		}
	}
}

func TestApprovalNeverOverridesTheAlwaysRefused(t *testing.T) {
	env := testEnv()
	everything := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
	for _, a := range []string{"127.0.0.1", "::1", "169.254.169.254", "fd00:ec2::254", "100.100.100.200", "198.18.9.9", "::ffff:127.0.0.1", "64:ff9b::7f00:1"} {
		if Refuse(env, Organization, addr(a), everything) == "" {
			t.Errorf("%s: an approval of everything let it through", a)
		}
	}
	// A private address inside an approved network is fine.
	if why := Refuse(env, Organization, addr("10.9.9.9"), everything); why != "" {
		t.Errorf("approved private address refused: %s", why)
	}
}

func TestNonSlash96NAT64IsRefused(t *testing.T) {
	env := testEnv()
	env.NAT64Other = []netip.Prefix{netip.MustParsePrefix("2001:db8:aa::/64")}
	if Refuse(env, Organization, addr("2001:db8:aa::1"), nil) == "" {
		t.Fatal("an address in a NAT64 prefix of another length was allowed")
	}
}

func TestRefusePlatformKeepsNetguardsRule(t *testing.T) {
	for a, refuse := range map[string]bool{
		"127.0.0.1": false, "10.0.0.5": false, "192.168.1.1": false,
		"169.254.169.254": true, "fe80::1": true, "fd00:ec2::254": true, "::ffff:169.254.169.254": true,
		"64:ff9b::a9fe:a9fe": true, "2002:a9fe:a9fe::": true, "64:ff9b::a00:1": false,
	} {
		if got := Refuse(testEnv(), Platform, addr(a), nil) != ""; got != refuse {
			t.Errorf("%s: refused %v, want %v", a, got, refuse)
		}
	}
}

func TestParseURL(t *testing.T) {
	d, err := ParseURL("https://Hooks.Example.com:8443/path?token=secret")
	if err != nil || d.Host != "hooks.example.com" || d.Port != 8443 {
		t.Fatalf("%+v %v", d, err)
	}
	if d, err = ParseURL("https://hooks.example.com./x"); err != nil || d.Port != 443 || d.Host != "hooks.example.com" {
		t.Fatalf("%+v %v", d, err)
	}
	for _, bad := range []string{"http://example.com", "https://user:pw@example.com/", "ftp://x", "example.com", "https://", "https://example.com/#f", "https://exa mple.com/", "https://example.com:99999/"} {
		if _, err := ParseURL(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestParsePrefixes(t *testing.T) {
	got, err := ParsePrefixes([]string{"10.0.0.7", "10.1.2.3/16", "::ffff:10.9.9.9", "fd00::/8"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.7/32", "10.1.0.0/16", "10.9.9.9/32", "fd00::/8"}
	for i, p := range got {
		if p.String() != want[i] {
			t.Errorf("%d: %s, want %s", i, p, want[i])
		}
	}
	if _, err := ParsePrefixes([]string{"nope"}); err == nil {
		t.Fatal("garbage accepted")
	}
}

// A name that resolves to a refused address is refused after resolution, and a
// second lookup that would give another answer is never made: the connection
// goes to the address that was checked (DNS rebinding).
func TestDialPinsTheCheckedAddress(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	srv.StartTLS()
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	var lookups atomic.Int32
	// The first answer is the checked one (loopback, approved); a rebinding
	// resolver would answer a metadata address the second time.
	p := Policy{Mode: Organization, Approved: nil, Env: Env{Names: nil}}
	p.Resolve = func(context.Context, string) ([]netip.Addr, error) {
		if lookups.Add(1) == 1 {
			return []netip.Addr{addr("93.184.216.34")}, nil
		}
		return []netip.Addr{addr("169.254.169.254")}, nil
	}
	// 93.184.216.34 is public and passes the policy, so the dial goes there (and fails to
	// connect in the sandbox, which is not what is checked): what matters is how often it looked up.
	d := Policy{Mode: Organization, Env: Env{}, Resolve: p.Resolve}
	ctx, cancel := context.WithTimeout(context.Background(), 1)
	defer cancel()
	_, _ = d.DialContext(ctx, "tcp", net.JoinHostPort("rebind.example.com", port))
	if n := lookups.Load(); n != 1 {
		t.Fatalf("the name was looked up %d times, want once", n)
	}

	// A name that resolves to a refused address is refused, with no connection made.
	d.Resolve = func(context.Context, string) ([]netip.Addr, error) { return []netip.Addr{addr("127.0.0.1")}, nil }
	_, err := d.DialContext(context.Background(), "tcp", net.JoinHostPort("evil.example.com", port))
	if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "evil.example.com") {
		t.Fatalf("err %v", err)
	}
	// A mix of a public and a refused address refuses the name.
	d.Resolve = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{addr("93.184.216.34"), addr("10.0.0.1")}, nil
	}
	if _, err = d.DialContext(context.Background(), "tcp", net.JoinHostPort("mixed.example.com", port)); !errors.Is(err, ErrRefused) {
		t.Fatalf("err %v", err)
	}
	// The deployment's own names are refused as a host.
	d.Env.Names = []string{"rmm.example.com"}
	if _, err = d.DialContext(context.Background(), "tcp", "RMM.example.com.:443"); !errors.Is(err, ErrRefused) {
		t.Fatalf("err %v", err)
	}
	// A literal address is checked the same way.
	if _, err = d.DialContext(context.Background(), "tcp", "[::ffff:127.0.0.1]:443"); !errors.Is(err, ErrRefused) {
		t.Fatalf("err %v", err)
	}
}

// Once approved, the connection is made, to the approved address only.
func TestApprovedDestinationConnectsAndRedirectsAreRefused(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
			return
		}
		w.WriteHeader(204)
	}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	ca := pemOf(srv)

	// Loopback is always refused for an organization, approved or not.
	refused := Policy{Mode: Organization, Approved: mustParse(t, "127.0.0.1")}
	c, _, err := NewClient(refused, ca)
	if err != nil {
		t.Fatal(err)
	}
	if err = get(c, "https://127.0.0.1:"+port+"/"); !errors.Is(err, ErrRefused) {
		t.Fatalf("loopback: %v", err)
	}
	if hits.Load() != 0 {
		t.Fatal("the receiver was reached")
	}

	// The platform's own destinations may be on loopback; redirects are not followed.
	plat := Policy{Mode: Platform}
	c, _, err = NewClient(plat, ca)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Get("https://127.0.0.1:" + port + "/redirect")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound || hits.Load() != 1 {
		t.Fatalf("status %d after %d hits: the redirect was followed or not seen", resp.StatusCode, hits.Load())
	}
	// A certificate the destination's authority did not issue is refused: there is no "do not verify".
	c, _, _ = NewClient(plat, nil)
	if err = get(c, "https://127.0.0.1:"+port+"/"); err == nil {
		t.Fatal("an unknown certificate was accepted")
	}
	if _, _, err = NewClient(plat, []byte("not pem")); err == nil {
		t.Fatal("garbage authority accepted")
	}
}

func mustParse(t *testing.T, s ...string) []netip.Prefix {
	t.Helper()
	p, err := ParsePrefixes(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func pemOf(srv *httptest.Server) []byte {
	var out []byte
	for _, c := range srv.TLS.Certificates {
		for _, der := range c.Certificate {
			out = append(out, "-----BEGIN CERTIFICATE-----\n"...)
			out = append(out, b64(der)...)
			out = append(out, "\n-----END CERTIFICATE-----\n"...)
		}
	}
	return out
}

func TestOrganizationClientKeepsNoConnection(t *testing.T) {
	_, tr, err := NewClient(Policy{Mode: Organization}, nil)
	if err != nil || !tr.DisableKeepAlives || tr.Proxy != nil {
		t.Fatalf("%v keepalives disabled %v", err, tr.DisableKeepAlives)
	}
	_, tr, _ = NewClient(Policy{Mode: Platform}, nil)
	if tr.DisableKeepAlives || tr.MaxConnsPerHost != 1 {
		t.Fatal("a platform destination keeps at most one connection")
	}
}

func TestRoutesAndNAT64Parsing(t *testing.T) {
	v4 := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n" +
		"eth0\t00000000\t0100A8C0\t0003\t0\t0\t0\t00000000\n" +
		"eth0\t0000A8C0\t00000000\t0001\t0\t0\t0\t0000FFFF\n" +
		"tun0\t0A00000A\t00000000\t0001\t0\t0\t0\t00FFFFFF\n"
	got := parseRoutes4(v4)
	if len(got) != 2 || got[0].String() != "192.168.0.0/16" || got[1].String() != "10.0.0.0/24" {
		t.Fatalf("%v", got)
	}
	v6 := "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000400 00000001 00000000 00000001 eth0\n" +
		"20010db8000000000000000000000000 20 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 tun0\n" +
		"00000000000000000000000000000001 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000001 00000000 80200001 lo\n"
	if got := parseRoutes6(v6); len(got) != 1 || got[0].String() != "2001:db8::/32" {
		t.Fatalf("%v", got)
	}
	e := &Environment{resolve: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{addr("2001:db8:64::c000:aa"), addr("2001:db8:ff::1")}, nil
	}}
	ok96, other := e.discoverNAT64(context.Background())
	if len(ok96) != 1 || ok96[0].String() != "2001:db8:64::/96" || len(other) != 1 {
		t.Fatalf("%v %v", ok96, other)
	}
}

func TestEnvironmentReadsTheServer(t *testing.T) {
	e := NewEnvironment(func() []string { return []string{"RMM.Example.com.", " "} }, []netip.Addr{addr("203.0.113.77")})
	s := e.Snapshot()
	if len(s.Names) != 1 || s.Names[0] != "rmm.example.com" {
		t.Fatalf("names %v", s.Names)
	}
	found := false
	for _, a := range s.Addrs {
		if a == addr("203.0.113.77") {
			found = true
		}
	}
	if !found || len(s.Nets) == 0 {
		t.Fatalf("addrs %v nets %v", s.Addrs, s.Nets)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e.Run(ctx)
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// get makes a request and closes what came back.
func get(c *http.Client, u string) error {
	resp, err := c.Get(u)
	if err == nil {
		_ = resp.Body.Close()
	}
	return err
}
