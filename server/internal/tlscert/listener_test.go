//go:build integration

package tlscert

import (
	"net"
	"testing"
)

func tlsListener(t *testing.T) (net.Listener, error) {
	t.Helper()
	return net.Listen("tcp", "127.0.0.1:0")
}
