//go:build !linux

package keystored

// Harden does nothing off Linux; the keystore runs only in its container.
func Harden() error { return nil }
