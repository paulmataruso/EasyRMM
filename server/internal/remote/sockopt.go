package remote

import (
	"crypto/tls"
	"net"
)

// desktopSendQueue bounds how much of a desktop stream may wait unsent in
// the kernel on the browser's connection (ADR-0025). Without a bound the
// kernel queues as much as its send buffer grows to (megabytes) when the
// browser's link is slower than the agent produces frames, and every key
// press waits behind it. With it the queue backs up into MeshCentral and the
// agent, which then skips frames instead of sending stale ones.
var desktopSendQueue = 16 << 10

// agentDesktopBuffer is the receive buffer on the agent's side of a desktop
// relay (ADR-0025). When the viewer falls behind, MeshCentral stops reading
// the agent, and everything the agent has sent by then is shown late. The
// kernel doubles the value for its bookkeeping, so about 256 KB can wait
// here instead of the megabytes receive autotuning allows; the window it
// leaves still carries about 2 MB/s at a 100 ms round trip. A fixed buffer
// is used because the kernel recomputes TCP_WINDOW_CLAMP as it autotunes.
const agentDesktopBuffer = 128 << 10

// Relay connections to MeshCentral are kept small too (ADR-0025). On
// loopback the kernel lets either side get megabytes ahead of the other.
// MeshCentral's desktop multiplexer drops tiles a newer one replaces, but
// only while they wait in its own queue: written to the viewer's socket
// they are sent in order, and when the viewer falls behind it stops reading
// the agent, whose queued tiles then drain at the viewer's speed.
//
// Toward the viewer, MeshCentral's send buffer grows to about four times
// the window this side advertises, so a small receive buffer (and segment
// size) keeps it to tens of kilobytes. Toward MeshCentral, this side holds
// back at most relayUpstreamUnsent unsent, and on the agent's side of a
// desktop relay it waits while MeshCentral has more than meshUnreadLimit
// received but unread (pace), so the agent stops soon after the viewer
// falls behind. Loopback is fast enough that throughput does not suffer.
const (
	relayUpstreamBuffer  = 8 << 10
	relayUpstreamSegment = 1400
	relayUpstreamUnsent  = 32 << 10
	meshUnreadLimit      = 32 << 10
)

// tcpConn returns the TCP connection under c, if there is one.
func tcpConn(c net.Conn) *net.TCPConn {
	for {
		switch v := c.(type) {
		case *net.TCPConn:
			return v
		case *tls.Conn:
			c = v.NetConn()
		case interface{ NetConn() net.Conn }:
			c = v.NetConn()
		default:
			return nil
		}
	}
}
