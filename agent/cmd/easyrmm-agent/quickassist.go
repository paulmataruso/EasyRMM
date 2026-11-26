package main

import (
	"context"
	"errors"
	"flag"
	"strconv"
	"time"

	"github.com/paulmataruso/easyrmm/agent/quickassist"
)

// quickAssist is the Quick Assist runner (ADR-0080): one session, no
// service, no state in the agent's folder. The agent's own state store is
// never opened.
func (e *env) quickAssist(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("quick-assist", flag.ContinueOnError)
	clean := fs.Bool("clean", false, "remove what a crashed session left, and exit")
	self := fs.String("self", "", "the file that carries the ticket (default: this program)")
	base := fs.String("base-dir", "", "where the session folder is made (default: the user's runtime or temp folder)")
	caFile := fs.String("ca-file", "", "PEM file of a private certificate authority to trust")
	server := fs.String("server", "", "reach the server at this address instead of the one in the ticket (shown in the consent text)")
	poll := fs.Duration("poll", 0, "how often to ask the server about the session (default: the server's)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("quick-assist takes no arguments")
	}
	if *poll < 0 || (*poll != 0 && *poll < 100*time.Millisecond) {
		return errors.New("--poll is too short")
	}
	opts := quickassist.Options{Self: *self, BaseDir: *base, CAFile: *caFile, Server: *server, Version: Version, Poll: *poll, Elevated: e.isRoot(), Out: e.stdout}
	if *clean {
		b := opts.BaseDir
		if b == "" {
			b = quickassist.DefaultBase()
		}
		n, err := quickassist.Clean(b)
		if err != nil {
			return err
		}
		_, _ = e.stdout.Write([]byte("Removed " + strconv.Itoa(n) + " leftover session folder(s).\n"))
		return nil
	}
	err := quickassist.Run(ctx, opts)
	if errors.Is(err, quickassist.ErrDeclined) {
		return nil
	}
	return err
}
