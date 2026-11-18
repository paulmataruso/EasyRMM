package netguard

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestRefused(t *testing.T) {
	for addr, refused := range map[string]bool{
		"169.254.169.254":        true,
		"169.254.0.1":            true,
		"::ffff:169.254.169.254": true,
		"fe80::1":                true,
		"fd00:ec2::254":          true,
		"100.100.100.200":        true,
		"224.0.0.251":            true, // link-local multicast (mDNS)
		"ff02::1":                true, // link-local multicast
		"127.0.0.1":              false,
		"::1":                    false,
		"10.0.0.5":               false,
		"192.168.1.10":           false,
		"172.16.0.9":             false,
		"100.64.0.1":             false,
		"203.0.113.7":            false,
		"2001:db8::1":            false,
	} {
		if got := Refused(netip.MustParseAddr(addr)) != ""; got != refused {
			t.Errorf("%s: refused %v, want %v", addr, got, refused)
		}
	}
}

func TestControlOnADialer(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	d := &net.Dialer{Timeout: 5 * time.Second, Control: Control}
	c, err := d.DialContext(context.Background(), "tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("loopback refused: %v", err)
	}
	_ = c.Close()

	// Refused before any packet is sent, so this needs no network.
	start := time.Now()
	_, err = d.DialContext(context.Background(), "tcp", "169.254.169.254:80")
	if err == nil || !strings.Contains(err.Error(), "does not connect to 169.254.169.254") || time.Since(start) > time.Second {
		t.Fatalf("metadata address: %v after %v", err, time.Since(start))
	}
	if _, err := d.DialContext(context.Background(), "udp", "[fe80::1%lo]:514"); err == nil || !strings.Contains(err.Error(), "link-local") {
		t.Fatalf("link-local over UDP: %v", err)
	}
}

// Control gets an address after name resolution; anything else is refused,
// and an address without a port is still checked.
func TestControlAddresses(t *testing.T) {
	if err := Control("tcp", "rmm.example.com:443", nil); err == nil || !strings.Contains(err.Error(), "is not an address") {
		t.Errorf("a host name: %v", err)
	}
	if err := Control("udp", "169.254.169.254", nil); err == nil || !strings.Contains(err.Error(), "does not connect to 169.254.169.254") {
		t.Errorf("an address without a port: %v", err)
	}
	if err := Control("tcp", "[::ffff:169.254.169.254]:80", nil); err == nil {
		t.Error("a link-local address mapped into IPv6 was allowed")
	}
	if err := Control("tcp", "192.0.2.10:443", nil); err != nil {
		t.Errorf("a public address: %v", err)
	}
}
