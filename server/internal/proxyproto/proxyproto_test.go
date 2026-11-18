package proxyproto_test

import (
	"bytes"
	"encoding/hex"
	"net"
	"testing"

	"github.com/paulmataruso/easyrmm/server/internal/proxyproto"
)

func tcp(ip string, port int) *net.TCPAddr { return &net.TCPAddr{IP: net.ParseIP(ip), Port: port} }

// The expected bytes are written out from the specification, section 2.2,
// not computed the way Header computes them.
func TestHeader(t *testing.T) {
	sig := "0d0a0d0a000d0a515549540a"
	cases := []struct {
		name     string
		src, dst net.Addr
		want     string
	}{
		{"IPv4", tcp("203.0.113.7", 50123), tcp("192.0.2.10", 443),
			sig + "21" + "11" + "000c" + "cb007107" + "c000020a" + "c3cb" + "01bb"},
		{"IPv4-mapped is IPv4", tcp("::ffff:203.0.113.7", 1), tcp("::ffff:192.0.2.10", 2),
			sig + "2111000c" + "cb007107c000020a" + "0001" + "0002"},
		{"IPv6", tcp("2001:db8::1", 50123), tcp("2001:db8::2", 443),
			sig + "21" + "21" + "0024" + "20010db8000000000000000000000001" + "20010db8000000000000000000000002" + "c3cb" + "01bb"},
		{"mixed families use IPv6", tcp("203.0.113.7", 1), tcp("2001:db8::2", 2),
			sig + "21210024" + "00000000000000000000ffffcb007107" + "20010db8000000000000000000000002" + "0001" + "0002"},
		{"not TCP is LOCAL", &net.UnixAddr{Name: "/run/x", Net: "unix"}, tcp("192.0.2.10", 443), sig + "20" + "00" + "0000"},
		{"no address is LOCAL", &net.TCPAddr{}, tcp("192.0.2.10", 443), sig + "20000000"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			want, err := hex.DecodeString(c.want)
			if err != nil {
				t.Fatal(err)
			}
			if got := proxyproto.Header(c.src, c.dst); !bytes.Equal(got, want) {
				t.Fatalf("Header =\n%x\nwant\n%x", got, want)
			}
		})
	}
	if !bytes.HasPrefix(proxyproto.Header(nil, nil), proxyproto.Signature) {
		t.Fatal("nil addresses lost the signature")
	}
}
