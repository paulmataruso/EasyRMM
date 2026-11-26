// Command packlint is the build check of the compliance content (ADR-0078,
// section 10). It fails when a content file is not in the manifest or does
// not match its hash, when an edition would carry a class it must not, when
// a review is still needed in a commercial build, when NOTICE.generated is
// out of date, when a text field holds a banned marker, or when a pack does
// not validate against the control library.
//
//	go run ./server/cmd/packlint                      check the dev edition
//	go run ./server/cmd/packlint -edition commercial  check what a release carries
//	go run ./server/cmd/packlint -dir <content dir>   check a directory (a built image's, a fixture)
//	go run ./server/cmd/packlint -update              rewrite manifest.json hashes and NOTICE.generated
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/paulmataruso/easyrmm/server/internal/compliance"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/content"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/packs"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("packlint", flag.ContinueOnError)
	fl.SetOutput(stderr)
	edition := fl.String("edition", compliance.EditionDev, "build edition to check: dev or commercial")
	dir := fl.String("dir", "", "content directory (default: the embedded content, from the source tree)")
	update := fl.Bool("update", false, "rewrite manifest.json hashes and NOTICE.generated in the content directory")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if *edition != compliance.EditionDev && *edition != compliance.EditionCommercial {
		fmt.Fprintln(stderr, "packlint: edition must be dev or commercial")
		return 2
	}
	fsys := content.FS
	root := *dir
	if root == "" {
		root = "server/internal/compliance/content"
	}
	if *dir != "" || *update {
		fsys = os.DirFS(root)
	}
	if *update {
		mf, notice, err := content.Update(fsys)
		if err != nil {
			fmt.Fprintln(stderr, "packlint:", err)
			return 1
		}
		for name, b := range map[string][]byte{"manifest.json": mf, "NOTICE.generated": notice} {
			if err := os.WriteFile(filepath.Join(root, name), b, 0o644); err != nil { //nolint:gosec // content files are public
				fmt.Fprintln(stderr, "packlint:", err)
				return 1
			}
		}
		fmt.Fprintln(stdout, "packlint: manifest.json and NOTICE.generated updated")
		return 0
	}
	errs := packs.Lint(fsys, *edition)
	for _, e := range errs {
		fmt.Fprintln(stderr, "packlint:", e)
	}
	if len(errs) > 0 {
		fmt.Fprintf(stderr, "packlint: %d problem(s) for the %s edition\n", len(errs), *edition)
		return 1
	}
	fmt.Fprintf(stdout, "packlint: content is clean for the %s edition\n", *edition)
	return 0
}
