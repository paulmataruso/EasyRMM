//go:build integration && windows

package main

import "errors"

// sendTerm: the server runs in a Linux container; Windows has no SIGTERM.
func sendTerm() error { return errors.New("SIGTERM is not available on Windows") }
