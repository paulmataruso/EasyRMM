//go:build !linux

package keystored

import (
	"errors"

	"github.com/google/go-tpm/tpm2/transport"
)

func openTPMDevice(string) (transport.TPMCloser, error) {
	return nil, errors.New("keystore: a TPM is read only on Linux")
}
