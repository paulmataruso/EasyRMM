// Package netguard keeps the connections the server makes to integrations
// a Super Administrator configures (EasyPatch, audit forwarding) away from
// addresses no integration lives at: link-local addresses, where cloud
// providers serve each instance its metadata and credentials, and the
// providers' other metadata addresses (Phase 9 security review).
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

// Refused says why the server does not connect to an address, or "" when
// it does.
func Refused(a netip.Addr) string {
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
