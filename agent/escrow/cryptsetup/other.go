//go:build !linux

// Package cryptsetup is the Linux LUKS backend of the agent's escrow; off Linux there is none.
package cryptsetup

import "github.com/paulmataruso/easyrmm/agent/escrow"

// System is the LUKS backend of this platform: none off Linux.
func System() escrow.LUKS { return nil }
