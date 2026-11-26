// Package netguard keeps the connections the server makes to integrations
// a Super Administrator configures (EasyPatch, audit forwarding) away from
// addresses no integration lives at: link-local addresses, where cloud
// providers serve each instance its metadata and credentials, and the
// providers' other metadata addresses.
//
// The check runs on the address actually dialed, after name resolution, so
// a name that resolves to such an address is refused too. Loopback and
// private addresses stay allowed: an integration often runs on the same
// host or network as EasyRMM.
package netguard

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"
)

// metadata are instance metadata addresses outside the link-local ranges.
var metadata = map[netip.Addr]string{
	netip.MustParseAddr("fd00:ec2::254"):   "AWS instance metadata",
	netip.MustParseAddr("100.100.100.200"): "Alibaba Cloud instance metadata",
}

var (
	nat64WellKnown = netip.MustParsePrefix("64:ff9b::/96")
	sixToFour      = netip.MustParsePrefix("2002::/16")
)

// Embedded lists the IPv4 addresses an IPv6 address carries, beyond an
// IPv4-mapped one: NAT64 (64:ff9b::/96), 6to4 (2002::/16) and
// IPv4-compatible (::a.b.c.d) addresses, plus the extra /96 prefixes given
// (the network's own NAT64 prefix, RFC 7050). An address checked as the IPv6
// address must also be checked as each of these (ADR-0053).
func Embedded(a netip.Addr, nat64 ...netip.Prefix) []netip.Addr {
	a = a.Unmap()
	if !a.Is6() {
		return nil
	}
	b := a.As16()
	var out []netip.Addr
	v4 := func(o int) { out = append(out, netip.AddrFrom4([4]byte{b[o], b[o+1], b[o+2], b[o+3]})) }
	switch {
	case nat64WellKnown.Contains(a):
		v4(12)
	case sixToFour.Contains(a):
		v4(2)
	}
	for _, p := range nat64 {
		if p.Bits() == 96 && p.Contains(a) {
			v4(12)
		}
	}
	// IPv4-compatible: ::a.b.c.d with the first 96 bits zero (not :: or ::1).
	zero := true
	for _, x := range b[:12] {
		if x != 0 {
			zero = false
		}
	}
	if zero && a != netip.IPv6Unspecified() && a != netip.IPv6Loopback() {
		v4(12)
	}
	return out
}

// Refused says why the server does not connect to an address, or "" when
// it does. An IPv6 address that carries an IPv4 one (see Embedded) is
// refused when either is.
func Refused(a netip.Addr) string {
	if why := refused(a); why != "" {
		return why
	}
	for _, e := range Embedded(a) {
		if why := refused(e); why != "" {
			return why
		}
	}
	return ""
}

func refused(a netip.Addr) string {
	a = a.Unmap()
	if why, ok := metadata[a]; ok {
		return why
	}
	if a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() {
		return "a link-local address, where cloud providers serve instance metadata"
	}
	return ""
}

// Control is a net.Dialer Control function that refuses the addresses
// Refused names.
func Control(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("netguard: %q is not an address", address)
	}
	if why := Refused(a); why != "" {
		return fmt.Errorf("EasyRMM does not connect to %s: %s", a, why)
	}
	return nil
}
