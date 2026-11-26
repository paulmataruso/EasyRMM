//go:build windows

package activedirectory

import "os"

func writeScript(path, text string) error { return os.WriteFile(path, []byte(text), 0o600) }
