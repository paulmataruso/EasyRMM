// Command genlibrary writes the compliance control library (ADR-0078,
// slice C1) from the settings lists the hardening scripts check, so a
// control can only name a setting that exists. Run it from the repository
// root after a setting is added or changed, then run packlint -update.
//
//	go run ./server/cmd/genlibrary
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/paulmataruso/easyrmm/server/internal/compliance/library"
)

func main() {
	dir := "server/internal/compliance/content/controls"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	for name, f := range map[string]library.File{"windows.json": library.GenerateWindows(), "linux.json": library.GenerateLinux()} {
		b, err := json.MarshalIndent(f, "", "  ")
		if err != nil {
			fail(err)
		}
		b = append(b, '\n')
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil { //nolint:gosec // content files are public
			fail(err)
		}
		fmt.Printf("%s: %d controls\n", name, len(f.Controls))
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "genlibrary:", err)
	os.Exit(1)
}
