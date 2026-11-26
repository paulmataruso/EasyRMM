//go:build windows

package grouppolicy

import "os"

func writeScript(path, text string) error { return os.WriteFile(path, []byte(text), 0o600) }
