//go:build !linux

package agentchannel

// processDescriptors: descriptors are not measured off Linux; the
// configured maximum is the only bound.
func processDescriptors() (open, limit uint64, ok bool) { return 0, 0, false }
