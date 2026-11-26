//go:build windows

package enrollfile

import (
	"errors"
	"io"

	"github.com/paulmataruso/easyrmm/agent/host"
)

// open checks the file on the handle it reads through, as the platform's
// owner and access list rules say (host.OpenPrivate).
func open(p Policy) (raw, error) {
	f, err := host.OpenPrivate(p.Path, p.Top)
	if err != nil {
		var prob *host.Problem
		if errors.As(err, &prob) {
			return raw{}, &Refusal{Path: p.Path, Reason: prob.Reason, Readable: prob.Readable}
		}
		return raw{}, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return raw{}, err
	}
	data, err := io.ReadAll(io.LimitReader(f.File, MaxSize+1))
	if err != nil {
		return raw{}, err
	}
	if len(data) > MaxSize {
		return raw{}, &Refusal{Path: p.Path, Reason: "is too large"}
	}
	return raw{data: data, meta: f.Meta, changed: fi.ModTime()}, nil
}
