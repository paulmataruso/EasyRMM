//go:build linux

package keystored

import (
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

func openTPMDevice(path string) (transport.TPMCloser, error) { return linuxtpm.Open(path) }
