package app

import (
	"net/netip"
	"slices"
	"testing"
)

// tlsSettings names the certificate service's names (the console's and the
// remote-access one's, sorted, once each), its ports, and the addresses this
// server answers on, with the operator's own among them.
func TestTLSSettings(t *testing.T) {
	cfg := testConfig(t)
	cfg.ListenHTTPS, cfg.ListenHTTP = ":8443", ":8080"
	cfg.ACMEDirectory, cfg.ACMEEmail = "https://ca.test/dir", "ops@rmm.test"
	cfg.IPAddresses = []netip.Addr{netip.MustParseAddr("192.0.2.7")}
	set := tlsSettings(cfg)
	if !slices.Equal(set.Names, []string{"mesh.rmm.test", "rmm.test"}) || set.MeshName != "mesh.rmm.test" {
		t.Errorf("names: %v mesh %q", set.Names, set.MeshName)
	}
	if set.TLSPort != "8443" || set.HTTPPort != "8080" || set.Directory != "https://ca.test/dir" || set.Email != "ops@rmm.test" {
		t.Errorf("settings: %+v", set)
	}
	if !slices.Contains(set.Own(), netip.MustParseAddr("192.0.2.7")) {
		t.Errorf("own addresses: %v", set.Own())
	}

	// Without a plain HTTP listener, and with a listener address that has no
	// port, there is no port to report.
	cfg.ListenHTTP, cfg.ListenHTTPS = "", "no-port"
	set = tlsSettings(cfg)
	if set.HTTPPort != "" || set.TLSPort != "" {
		t.Errorf("ports without listeners: %q %q", set.HTTPPort, set.TLSPort)
	}
}
