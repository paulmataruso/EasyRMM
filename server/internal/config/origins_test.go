package config

import (
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"testing"
)

func origins(c *Config) []string {
	var out []string
	for _, o := range c.Origins() {
		s := o.Console.String()
		if o.Mesh != nil {
			s += " " + o.Mesh.String()
		}
		if o.Internal {
			s += " internal"
		}
		out = append(out, s)
	}
	return out
}

func TestIPOnlyDeployment(t *testing.T) {
	m := base()
	delete(m, "EASYRMM_ACME_EMAIL")
	m["EASYRMM_PUBLIC_URL"] = "https://203.0.113.10"
	c, err := LoadFrom(env(m), noFiles)
	if err != nil {
		t.Fatal(err)
	}
	// No ACME for an IP address: the internal certificate authority, and
	// MeshCentral on its own port of the same address.
	if c.TLSMode != TLSInternal {
		t.Errorf("TLS mode = %s", c.TLSMode)
	}
	if c.MeshPublicURL.String() != "https://203.0.113.10:4443" {
		t.Errorf("mesh URL = %s", c.MeshPublicURL)
	}
	if c.Mesh.CertURL != "https://127.0.0.1:4443" {
		t.Errorf("cert URL = %s", c.Mesh.CertURL)
	}
	if got := origins(c); !slices.Equal(got, []string{"https://203.0.113.10 https://203.0.113.10:4443 internal"}) {
		t.Errorf("origins = %q", got)
	}
	if !c.NeedsInternalCA() {
		t.Error("no internal CA for an IP address")
	}
	if got := c.MeshListeners(); !slices.Equal(got, []string{":4443"}) {
		t.Errorf("mesh listeners = %q", got)
	}
	// The primary address is not repeated by IP access.
	c.IPAddresses = []netip.Addr{netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("198.51.100.7")}
	if got := origins(c); len(got) != 2 || got[1] != "https://198.51.100.7 https://198.51.100.7:4443 internal" {
		t.Errorf("origins = %q", got)
	}
	if got := c.MeshListeners(); !slices.Equal(got, []string{":4443"}) {
		t.Errorf("mesh listeners = %q", got)
	}

	// IPv6, a custom port, and a listener bound to the address.
	m["EASYRMM_PUBLIC_URL"] = "https://[2001:db8::10]:8443"
	m["EASYRMM_LISTEN_HTTPS"] = "[2001:db8::10]:8443"
	m["EASYRMM_IP_MESH_PORT"] = "9443"
	if c, err = LoadFrom(env(m), noFiles); err != nil {
		t.Fatal(err)
	}
	if c.MeshPublicURL.String() != "https://[2001:db8::10]:9443" || c.Mesh.CertURL != "https://[2001:db8::10]:9443" {
		t.Errorf("mesh %s, cert URL %s", c.MeshPublicURL, c.Mesh.CertURL)
	}
	if got := c.MeshListeners(); !slices.Equal(got, []string{"[2001:db8::10]:9443"}) {
		t.Errorf("mesh listeners = %q", got)
	}

	// An operator certificate for the address works too; ACME cannot.
	m = base()
	m["EASYRMM_PUBLIC_URL"] = "https://203.0.113.10"
	m["EASYRMM_TLS_MODE"] = "manual"
	m["EASYRMM_TLS_CERT_FILE"], m["EASYRMM_TLS_KEY_FILE"] = "/c.pem", "/k.pem"
	m["EASYRMM_IP_ADDRESSES"] = "198.51.100.7"
	if c, err = LoadFrom(env(m), noFiles); err != nil {
		t.Fatal(err)
	}
	if got := origins(c); len(got) != 2 || strings.Contains(strings.Join(got, ","), "internal") || c.NeedsInternalCA() {
		t.Errorf("manual certificate for an IP address: %q", got)
	}
	m["EASYRMM_TLS_MODE"] = "acme"
	if _, err = LoadFrom(env(m), noFiles); err == nil || !strings.Contains(err.Error(), "cannot get a certificate from ACME") {
		t.Errorf("acme for an IP address: %v", err)
	}
}

func TestIPAccessAlongsideDNS(t *testing.T) {
	m := base()
	m["EASYRMM_IP_ADDRESSES"] = "203.0.113.10, ::ffff:198.51.100.7,2001:db8::10"
	c, err := LoadFrom(env(m), noFiles)
	if err != nil {
		t.Fatal(err)
	}
	if !c.IPAccess {
		t.Error("IP access is off by default")
	}
	want := []string{
		"https://rmm.example.com https://mesh.rmm.example.com",
		"https://203.0.113.10 https://203.0.113.10:4443 internal",
		"https://198.51.100.7 https://198.51.100.7:4443 internal",
		"https://[2001:db8::10] https://[2001:db8::10]:4443 internal",
	}
	if got := origins(c); !slices.Equal(got, want) {
		t.Errorf("origins =\n%q\nwant\n%q", got, want)
	}
	// MeshCentral keeps reading the DNS certificate from the main listener.
	if c.Mesh.CertURL != "https://127.0.0.1:443" || !c.NeedsInternalCA() {
		t.Errorf("cert URL %s, internal CA %v", c.Mesh.CertURL, c.NeedsInternalCA())
	}
	if got := c.MeshListeners(); !slices.Equal(got, []string{":4443"}) {
		t.Errorf("mesh listeners = %q", got)
	}
	// Detection does not override configured addresses.
	c.DetectAddresses(func() []netip.Addr { t.Error("detected despite configuration"); return nil })

	// Without remote access, IP access serves the console only.
	m["EASYRMM_MESH_ENABLED"] = "false"
	if c, err = LoadFrom(env(m), noFiles); err != nil {
		t.Fatal(err)
	}
	if got := origins(c); got[1] != "https://203.0.113.10 internal" || c.MeshListeners() != nil {
		t.Errorf("origins without remote access = %q, listeners %q", got, c.MeshListeners())
	}

	// Turned off, only the public URL answers.
	m = base()
	m["EASYRMM_IP_ACCESS"] = "false"
	m["EASYRMM_IP_ADDRESSES"] = "203.0.113.10"
	if c, err = LoadFrom(env(m), noFiles); err != nil {
		t.Fatal(err)
	}
	if got := origins(c); len(got) != 1 || c.NeedsInternalCA() || c.MeshListeners() != nil {
		t.Errorf("IP access off: %q", got)
	}
	c.DetectAddresses(func() []netip.Addr { t.Error("detected with IP access off"); return nil })
}

func TestDetectAddresses(t *testing.T) {
	c, err := LoadFrom(env(base()), noFiles)
	if err != nil {
		t.Fatal(err)
	}
	found := []netip.Addr{netip.MustParseAddr("192.0.2.44")}
	c.DetectAddresses(func() []netip.Addr { return found })
	if !slices.Equal(c.IPAddresses, found) {
		t.Errorf("addresses = %v", c.IPAddresses)
	}
	// Behind an offloading proxy, the proxy's configuration names them.
	m := base()
	m["EASYRMM_TLS_MODE"] = "offload"
	m["EASYRMM_TRUSTED_PROXIES"] = "127.0.0.1"
	if c, err = LoadFrom(env(m), noFiles); err != nil {
		t.Fatal(err)
	}
	c.DetectAddresses(func() []netip.Addr { t.Error("detected in offload mode"); return found })
	if c.IPAddresses != nil || c.MeshListeners() != nil {
		t.Errorf("offload: %v %v", c.IPAddresses, c.MeshListeners())
	}
	// Offload with addresses: routed, but the proxy serves the certificate.
	m["EASYRMM_IP_ADDRESSES"] = "203.0.113.10"
	if c, err = LoadFrom(env(m), noFiles); err != nil {
		t.Fatal(err)
	}
	if got := origins(c); len(got) != 2 || got[1] != "https://203.0.113.10 https://203.0.113.10:4443" {
		t.Errorf("offload origins = %q", got)
	}
	// The real detector returns usable unicast addresses, or none.
	for _, a := range PrimaryAddresses() {
		if !a.IsGlobalUnicast() || a.Is4In6() {
			t.Errorf("detected %s", a)
		}
	}
}

func TestIPAccessValidation(t *testing.T) {
	for _, c := range []struct {
		env  map[string]string
		want string
	}{
		{map[string]string{"EASYRMM_IP_ADDRESSES": "rmm.example.com"}, "is not an IP address"},
		{map[string]string{"EASYRMM_IP_ADDRESSES": "0.0.0.0"}, "cannot be served"},
		{map[string]string{"EASYRMM_IP_ADDRESSES": "ff02::1"}, "cannot be served"},
		{map[string]string{"EASYRMM_IP_MESH_PORT": "0"}, "EASYRMM_IP_MESH_PORT"},
		{map[string]string{"EASYRMM_IP_MESH_PORT": "443"}, "must differ from the console's port"},
		{map[string]string{"EASYRMM_IP_ADDRESSES": "203.0.113.10", "EASYRMM_LISTEN_HTTPS": ":4443"}, "same as EASYRMM_LISTEN_HTTPS"},
		{map[string]string{"EASYRMM_PUBLIC_URL": "https://203.0.113.10", "EASYRMM_MESH_PUBLIC_URL": "https://203.0.113.10:443"}, "must differ from EASYRMM_PUBLIC_URL"},
		{map[string]string{"EASYRMM_PUBLIC_URL": "https://203.0.113.10", "EASYRMM_MESH_PUBLIC_URL": "https://198.51.100.7:4443"}, "must share a parent domain"},
		{map[string]string{"EASYRMM_TLS_MODE": "internal", "EASYRMM_DEV_INSECURE_COOKIES": "true"}, "only allowed with EASYRMM_TLS_MODE=offload"},
	} {
		m := base()
		for k, v := range c.env {
			m[k] = v
		}
		_, err := LoadFrom(env(m), noFiles)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v: %v, want an error mentioning %q", c.env, err, c.want)
		}
	}
	// A DNS name in internal mode (a LAN with its own DNS) is fine, as is a
	// MeshCentral origin on another port of the same name.
	m := base()
	m["EASYRMM_TLS_MODE"] = "internal"
	m["EASYRMM_MESH_PUBLIC_URL"] = "https://rmm.example.com:4443"
	if c, err := LoadFrom(env(m), noFiles); err != nil || !c.NeedsInternalCA() {
		t.Errorf("internal mode with a DNS name: %v", err)
	}
}

func TestAuthority(t *testing.T) {
	for in, want := range map[string]string{
		"https://RMM.Example.com.":      "rmm.example.com:443",
		"https://rmm.example.com:8443":  "rmm.example.com:8443",
		"https://203.0.113.10":          "203.0.113.10:443",
		"https://[2001:DB8::10]:4443":   "[2001:db8::10]:4443",
		"https://[::ffff:203.0.113.10]": "203.0.113.10:443",
	} {
		u, _ := url.Parse(in)
		if got := Authority(u); got != want {
			t.Errorf("Authority(%s) = %s, want %s", in, got, want)
		}
	}
	for in, want := range map[string]string{
		"RMM.example.com":     "rmm.example.com:443",
		"rmm.example.com:443": "rmm.example.com:443",
		"203.0.113.10:4443":   "203.0.113.10:4443",
		"[2001:db8::10]":      "[2001:db8::10]:443",
		"[2001:db8::10]:4443": "[2001:db8::10]:4443",
	} {
		if got := HostAuthority(in); got != want {
			t.Errorf("HostAuthority(%s) = %s, want %s", in, got, want)
		}
	}
	if hostPort("2001:db8::1", "") != "[2001:db8::1]" || hostPort("h", "") != "h" || hostPort("h", "1") != "h:1" {
		t.Error("hostPort")
	}
}
