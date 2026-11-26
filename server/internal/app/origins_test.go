package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/config"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/meshcentral"
	"github.com/paulmataruso/easyrmm/server/internal/pki"
	"github.com/paulmataruso/easyrmm/server/internal/remote"
)

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

// ipAccessConfig is a DNS deployment with IP access on two addresses.
func ipAccessConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := testConfig(t)
	cfg.TLSMode = config.TLSManual
	cfg.IPAccess = true
	cfg.IPAddresses = []netip.Addr{netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("2001:db8::10")}
	return cfg
}

func TestOriginsAndRouting(t *testing.T) {
	cfg := ipAccessConfig(t)
	ca, err := pki.New()
	if err != nil {
		t.Fatal(err)
	}
	all := origins(cfg, ca, true)
	if len(all) != 3 {
		t.Fatalf("origins = %+v", all)
	}
	if all[0] != (httpapi.Origin{Console: "https://rmm.test", Mesh: "https://mesh.rmm.test"}) {
		t.Errorf("primary = %+v", all[0])
	}
	if all[1] != (httpapi.Origin{Console: "https://203.0.113.10", Mesh: "https://203.0.113.10:4443", Pin: ca.Pin(), KeyPin: ca.KeyPin()}) {
		t.Errorf("IPv4 = %+v", all[1])
	}
	if all[2].Console != "https://[2001:db8::10]" || all[2].Mesh != "https://[2001:db8::10]:4443" {
		t.Errorf("IPv6 = %+v", all[2])
	}
	if got := origins(cfg, ca, false); got[1].Mesh != "" {
		t.Errorf("mesh origin without remote access: %+v", got[1])
	}

	rt := newRouter(all)
	for host, want := range map[string]string{
		"rmm.test":               "console https://rmm.test",
		"RMM.test.:443":          "console https://rmm.test",
		"rmm.test:18443":         "console https://rmm.test", // only the console uses this name
		"mesh.rmm.test":          "mesh https://rmm.test",
		"mesh.rmm.test:8443":     "mesh https://rmm.test",
		"203.0.113.10":           "console https://203.0.113.10",
		"203.0.113.10:443":       "console https://203.0.113.10",
		"203.0.113.10:4443":      "mesh https://203.0.113.10",
		"203.0.113.10:5173":      "", // shared by both: the port must match
		"[2001:db8::10]":         "console https://[2001:db8::10]",
		"[2001:DB8::10]:4443":    "mesh https://[2001:db8::10]",
		"198.51.100.7":           "",
		"evil.test":              "",
		"":                       "",
		"rmm.test.evil.test:443": "",
	} {
		got := ""
		if r, ok := rt.match(host); ok {
			kind := "console"
			if r.mesh {
				kind = "mesh"
			}
			got = kind + " " + r.origin.Console
		}
		if got != want {
			t.Errorf("match(%q) = %q, want %q", host, got, want)
		}
	}

	names, ips := internalAddresses(cfg)
	if len(names) != 0 || len(ips) != 2 || !ips[0].Equal(net.ParseIP("203.0.113.10")) {
		t.Errorf("internal addresses: %v %v", names, ips)
	}
	cfg.TLSMode = config.TLSInternal
	names, ips = internalAddresses(cfg)
	if strings.Join(names, ",") != "rmm.test,mesh.rmm.test" || len(ips) != 2 {
		t.Errorf("internal mode addresses: %v %v", names, ips)
	}
	// The names served besides the origins share the certificate.
	cfg.Patching.AgentHostnames = []string{"patch.old.test"}
	names, _ = internalAddresses(cfg)
	if strings.Join(names, ",") != "rmm.test,mesh.rmm.test,patch.old.test" {
		t.Errorf("internal mode with an imported EasyPatch's name: %v", names)
	}
}

// MeshCentral accepts a session's control connection from every MeshCentral
// origin the server serves, and only from those (allowedOrigin, ADR-0016).
func TestMeshConfigAllowsEveryMeshOrigin(t *testing.T) {
	sec := &remote.Secrets{LoginKey: make([]byte, meshcentral.KeySize), SessionKey: strings.Repeat("s", 64)}
	allowed := func(t *testing.T, cfg *config.Config) string {
		t.Helper()
		cfg.Mesh.InternalURL, cfg.Mesh.CertURL = mustURL("http://127.0.0.1:14430"), "https://127.0.0.1:443"
		out, err := MeshServerConfig(cfg, sec).Render()
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Domains map[string]struct {
				AllowedOrigin []string `json:"allowedOrigin"`
			} `json:"domains"`
		}
		if err := json.Unmarshal(out, &doc); err != nil {
			t.Fatal(err)
		}
		return strings.Join(doc.Domains[""].AllowedOrigin, " ")
	}

	t.Run("DNS install with IP access", func(t *testing.T) {
		if got := allowed(t, ipAccessConfig(t)); got != "mesh.rmm.test 203.0.113.10 [2001:db8::10]" {
			t.Errorf("allowedOrigin = %q", got)
		}
	})
	t.Run("IP-only install", func(t *testing.T) {
		cfg := testConfig(t)
		cfg.PublicURL, cfg.MeshPublicURL = mustURL("https://203.0.113.10"), mustURL("https://203.0.113.10:4443")
		cfg.TLSMode, cfg.IPAccess = config.TLSInternal, true
		// The public address, and the private one behind NAT.
		cfg.IPAddresses = []netip.Addr{netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("192.0.2.10")}
		if got := allowed(t, cfg); got != "203.0.113.10 192.0.2.10" {
			t.Errorf("allowedOrigin = %q", got)
		}
	})
	t.Run("IPv6-only install", func(t *testing.T) {
		cfg := testConfig(t)
		cfg.PublicURL, cfg.MeshPublicURL = mustURL("https://[2001:db8::1]"), mustURL("https://[2001:db8::1]:4443")
		cfg.TLSMode, cfg.IPAccess = config.TLSInternal, true
		cfg.IPAddresses = []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::20")}
		if got := allowed(t, cfg); got != "[2001:db8::1] [2001:db8::20]" {
			t.Errorf("allowedOrigin = %q", got)
		}
	})
	t.Run("IP access off", func(t *testing.T) {
		cfg := ipAccessConfig(t)
		cfg.IPAccess = false
		if got := allowed(t, cfg); got != "mesh.rmm.test" {
			t.Errorf("allowedOrigin = %q", got)
		}
	})
}

func TestHostHandlers(t *testing.T) {
	h := hostHandlers{"patch.old.test": http.NotFoundHandler()}
	for host, want := range map[string]bool{
		"patch.old.test": true, "PATCH.Old.Test.": true, "patch.old.test:443": true, "patch.old.test:8443": true,
		"rmm.test": false, "old.test": false, "": false, "[::1]:443": false,
	} {
		if _, ok := h.match(host); ok != want {
			t.Errorf("match(%q) = %v, want %v", host, ok, want)
		}
	}
}

func TestACMEHosts(t *testing.T) {
	cfg := testConfig(t)
	if got := strings.Join(acmeHosts(cfg), ","); got != "rmm.test,mesh.rmm.test" {
		t.Errorf("acme hosts %s", got)
	}
	cfg.Patching.AgentHostnames = []string{"patch.old.test"}
	if got := strings.Join(acmeHosts(cfg), ","); got != "rmm.test,mesh.rmm.test,patch.old.test" {
		t.Errorf("acme hosts with an imported EasyPatch's name: %s", got)
	}
}

// fakeConn is enough of a net.Conn for choosing a certificate.
type fakeConn struct {
	net.Conn
	local, remote net.Addr
}

func (c fakeConn) LocalAddr() net.Addr  { return c.local }
func (c fakeConn) RemoteAddr() net.Addr { return c.remote }

func tcp(s string) *net.TCPAddr {
	a := netip.MustParseAddrPort(s)
	return net.TCPAddrFromAddrPort(a)
}

func TestCertificateChoice(t *testing.T) {
	cfg := ipAccessConfig(t)
	ca, err := pki.New()
	if err != nil {
		t.Fatal(err)
	}
	names, ips := internalAddresses(cfg)
	if err := ca.SetAddresses(context.Background(), names, ips); err != nil {
		t.Fatal(err)
	}
	internal, _ := ca.Certificate()
	operator := &tls.Certificate{}
	var asked string
	primary := func(h *tls.ClientHelloInfo) (*tls.Certificate, error) { asked = h.ServerName; return operator, nil }
	e := &edge{cfg: cfg, log: discard(), pki: ca}
	get := e.certificates(primary)

	external := fakeConn{local: tcp("203.0.113.10:443"), remote: tcp("198.51.100.20:50000")}
	self := fakeConn{local: tcp("203.0.113.10:443"), remote: tcp("203.0.113.10:50000")}
	loop := fakeConn{local: tcp("127.0.0.1:443"), remote: tcp("127.0.0.1:50000")}
	for _, c := range []struct {
		name  string
		hello *tls.ClientHelloInfo
		want  *tls.Certificate
		sni   string
	}{
		{"DNS name", &tls.ClientHelloInfo{ServerName: "rmm.test", Conn: external}, operator, "rmm.test"},
		{"IP address from outside", &tls.ClientHelloInfo{Conn: external}, internal, ""},
		{"IP as server name", &tls.ClientHelloInfo{ServerName: "203.0.113.10", Conn: external}, internal, ""},
		// MeshCentral has a listener of its own: no rule on the main listeners.
		{"loopback without a server name", &tls.ClientHelloInfo{Conn: loop}, internal, ""},
		{"the host's own address without a server name", &tls.ClientHelloInfo{Conn: self}, internal, ""},
	} {
		asked = ""
		got, err := get(c.hello)
		if err != nil || got != c.want || asked != c.sni {
			t.Errorf("%s: got internal=%v asked %q, err %v", c.name, got == internal, asked, err)
		}
	}
	// MeshCentral's listener serves the MeshCentral name's certificate,
	// whatever server name it is sent and from wherever it connects.
	mesh := e.meshCertificate(primary)
	for _, h := range []*tls.ClientHelloInfo{{Conn: loop}, {ServerName: "unrelated.test", Conn: loop}, {ServerName: "203.0.113.10", Conn: self}} {
		asked = ""
		if got, err := mesh(h); err != nil || got != operator || asked != "mesh.rmm.test" {
			t.Errorf("MeshCentral's listener for %+v: asked %q, err %v", h.ServerName, asked, err)
		}
	}

	// Without IP access an address gets the operator's certificate.
	e.pki = nil
	asked = ""
	if got, _ := e.certificates(primary)(&tls.ClientHelloInfo{Conn: external}); got != operator || asked != "" {
		t.Error("without the internal CA")
	}
	// In internal mode everything is the internal CA's.
	cfg.TLSMode = config.TLSInternal
	e.pki = ca
	if got, _ := e.certificates(ca.GetCertificate)(&tls.ClientHelloInfo{ServerName: "rmm.test", Conn: external}); got != internal {
		t.Error("internal mode served another certificate")
	}
}

// TestEdgeInternalTLS runs an IP-only server: the console on one port and
// MeshCentral on another of the same address, both with a certificate from
// the internal CA that a client trusting the CA accepts.
func TestEdgeInternalTLS(t *testing.T) {
	consoleAddr, meshAddr, httpAddr := reserveAddr(t), reserveAddr(t), reserveAddr(t)
	_, consolePort, _ := net.SplitHostPort(consoleAddr)
	_, meshPort, _ := net.SplitHostPort(meshAddr)
	cfg := testConfig(t)
	cfg.TLSMode = config.TLSInternal
	cfg.PublicURL = mustURL("https://127.0.0.1:" + consolePort)
	cfg.MeshPublicURL = mustURL("https://127.0.0.1:" + meshPort)
	cfg.ListenHTTPS, cfg.ListenHTTP = consoleAddr, httpAddr
	if got := cfg.MeshListeners(); len(got) != 1 || got[0] != "127.0.0.1:"+meshPort {
		t.Fatalf("mesh listeners = %v", got)
	}
	ca, err := pki.New()
	if err != nil {
		t.Fatal(err)
	}
	names, ips := internalAddresses(cfg)
	if err := ca.SetAddresses(context.Background(), names, ips); err != nil {
		t.Fatal(err)
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("host=" + r.Host)) })
	stop := runEdge(t, &edge{cfg: cfg, handler: h, hold: notHeld(t), log: discard(), pki: ca})
	defer stop()

	block, _ := pem.Decode(ca.CAPEM())
	caCert, _ := x509.ParseCertificate(block.Bytes)
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	c := noRedirect()
	c.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	for _, u := range []string{cfg.PublicURL.String() + "/", cfg.MeshPublicURL.String() + "/"} {
		resp, body := get(t, c, u, "")
		if resp.StatusCode != http.StatusOK || body != "host="+mustURL(u).Host {
			t.Errorf("%s: %d %q", u, resp.StatusCode, body)
		}
	}
	// Plain HTTP on the address redirects to the console.
	resp, _ := get(t, noRedirect(), "http://"+httpAddr+"/devices", "127.0.0.1")
	if resp.StatusCode != http.StatusPermanentRedirect || resp.Header.Get("Location") != "https://127.0.0.1:"+consolePort+"/devices" {
		t.Errorf("redirect: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}

	// An internal mode edge without its authority refuses to start.
	e := &edge{cfg: cfg, handler: h, hold: notHeld(t), log: discard()}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := e.run(ctx); err == nil {
		t.Error("internal mode without a CA started")
	}
}
