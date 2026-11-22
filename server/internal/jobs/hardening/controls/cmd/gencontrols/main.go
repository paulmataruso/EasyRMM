// Command gencontrols regenerates the Windows hardening modules'
// related-controls tables (server/internal/jobs/hardening/controls).
//
//	go run ./server/internal/jobs/hardening/controls/cmd/gencontrols
//
// rewrites related.json from cites.json and data/. With -extract DIR it
// first extracts data/ again from DISA's and NIST's files in DIR, refusing
// any whose SHA-256 is not the recorded one (see data/SOURCES.md); that
// needs poppler's pdftotext.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/paulmataruso/easyrmm/server/internal/jobs/hardening/controls"
	"github.com/paulmataruso/easyrmm/server/internal/jobs/hardening/controls/extract"
)

func main() {
	dir := flag.String("dir", "server/internal/jobs/hardening/controls", "the controls package directory")
	src := flag.String("extract", "", "extract data/ from the downloaded files in this directory first")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, *dir, *src); err != nil {
		fmt.Fprintln(os.Stderr, "gencontrols:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, dir, src string) error {
	if src != "" {
		if err := extract.Run(ctx, extract.Options{SourceDir: src, PackageDir: dir}); err != nil {
			return err
		}
	}
	b, err := controls.Generate(os.DirFS(dir))
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	return root.WriteFile(controls.RelatedFile, b, 0o644) //nolint:gosec // a file checked into the repository
}
