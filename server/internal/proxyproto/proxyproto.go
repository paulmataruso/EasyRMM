// Package proxyproto writes PROXY protocol version 2 headers
// (https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt), which
// tell a server behind EasyRMM's edge who the client really is. EasyRMM
// sends them to a co-hosted EasyPatch (ADR-0035); it never accepts them.
package proxyproto

import (
	"encoding/binary"
	"net"
)

// Signature starts every version 2 header.
var Signature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

const (
	cmdLocal = 0x20 // version 2, LOCAL: use the connection's own addresses
	cmdProxy = 0x21 // version 2, PROXY: the addresses follow
	tcp4     = 0x11
	tcp6     = 0x21
)

// Header is a version 2 header for a TCP connection from src to dst.
// Addresses that are not TCP get the LOCAL command, which tells the
// receiver to use the connection's own addresses.
func Header(src, dst net.Addr) []byte {
	h := append([]byte{}, Signature...)
	s, ok1 := src.(*net.TCPAddr)
	d, ok2 := dst.(*net.TCPAddr)
	if !ok1 || !ok2 || s.IP == nil || d.IP == nil {
		return append(h, cmdLocal, 0x00, 0x00, 0x00)
	}
	var body []byte
	if s4, d4 := s.IP.To4(), d.IP.To4(); s4 != nil && d4 != nil {
		h = append(h, cmdProxy, tcp4)
		body = append(append(body, s4...), d4...)
	} else {
		h = append(h, cmdProxy, tcp6)
		body = append(append(body, s.IP.To16()...), d.IP.To16()...)
	}
	body = binary.BigEndian.AppendUint16(body, uint16(s.Port)) //nolint:gosec // a TCP port
	body = binary.BigEndian.AppendUint16(body, uint16(d.Port)) //nolint:gosec // a TCP port
	h = binary.BigEndian.AppendUint16(h, uint16(len(body)))    //nolint:gosec // 12 or 36 bytes
	return append(h, body...)
}
