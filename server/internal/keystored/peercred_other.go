//go:build !linux

package keystored

import (
	"errors"
	"net"
)

// peerUID cannot be answered off Linux, so no connection is accepted: the
// keystore runs only in its Linux container.
func peerUID(net.Conn) (uint32, error) {
	return 0, errors.New("keystore: peer credentials are available on Linux only")
}
