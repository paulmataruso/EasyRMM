// Package keystored is the keystore process (ADR-0081): it holds the
// key-encryption key (KEK), wraps and unwraps organization keys, opens
// escrow records only to compare fingerprints, and keeps the recovery
// bundles. It has no network, no database and no way to answer the server
// with a plaintext key in this slice.
package keystored

// Secret is memory for a key the keystore holds: on Linux an anonymous,
// locked mapping that is kept out of core dumps (mlock and MADV_DONTDUMP),
// not ordinary Go heap, so the key neither swaps nor is dumped. Elsewhere
// (tests on other systems) it is a plain slice. Zero it when done.
type Secret struct {
	b       []byte
	release func([]byte)
}

// NewSecret copies src into protected memory. The caller zeroes src.
func NewSecret(src []byte) (*Secret, error) {
	b, release, err := alloc(len(src))
	if err != nil {
		return nil, err
	}
	copy(b, src)
	return &Secret{b: b, release: release}, nil
}

// Bytes returns the key's bytes, valid until Destroy. Do not keep them.
func (s *Secret) Bytes() []byte {
	if s == nil {
		return nil
	}
	return s.b
}

// Destroy overwrites and releases the memory.
func (s *Secret) Destroy() {
	if s == nil || s.b == nil {
		return
	}
	clear(s.b)
	if s.release != nil {
		s.release(s.b)
	}
	s.b, s.release = nil, nil
}

func zero(b []byte) { clear(b) }
