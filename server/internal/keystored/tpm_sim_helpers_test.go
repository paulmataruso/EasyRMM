//go:build cgo

package keystored

import (
	"bytes"
	"os"
	"testing"
)

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p) //nolint:gosec // test
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func contains(b, sub []byte) bool { return bytes.Contains(b, sub) }

func (p tpmProtector) unsealErr(blob []byte) error { _, err := p.Unseal(1, blob); return err }
