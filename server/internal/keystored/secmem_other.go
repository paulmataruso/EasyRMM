//go:build !linux

package keystored

// alloc is plain memory where the platform has no locked mappings; the
// keystore runs in a Linux container, and this keeps the package building
// and testable elsewhere.
func alloc(n int) ([]byte, func([]byte), error) { return make([]byte, n), nil, nil }
