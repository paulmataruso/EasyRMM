//go:build !linux

package escrow

// SystemLUKS is the LUKS backend of this platform: none off Linux.
func SystemLUKS() LUKS { return nil }
