//go:build !windows

package enrollfile

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// open opens the file without following a link, then checks it as opened:
// a regular file with one link, owned by root, with no permission for group
// or others; and each folder from the file's up to Top owned by root and
// writable by no one else.
func open(p Policy) (raw, error) {
	f, err := os.OpenFile(p.Path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return raw{}, &Refusal{Path: p.Path, Reason: "is a symbolic link"}
		}
		return raw{}, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return raw{}, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return raw{}, errors.New("cannot read the file's owner")
	}
	mode := fi.Mode()
	readable := mode.Perm()&0o077 != 0
	switch {
	case !mode.IsRegular():
		return raw{}, &Refusal{Path: p.Path, Reason: "is not a regular file"}
	case st.Nlink != 1:
		return raw{}, &Refusal{Path: p.Path, Reason: fmt.Sprintf("has %d hard links", st.Nlink), Readable: readable}
	case st.Uid != p.UID:
		return raw{}, &Refusal{Path: p.Path, Reason: fmt.Sprintf("is owned by user %d, not by root", st.Uid), Readable: readable}
	case readable:
		return raw{}, &Refusal{Path: p.Path, Reason: fmt.Sprintf("has mode %04o; it must be 0600 or stricter", mode.Perm()), Readable: true}
	case mode&(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky) != 0:
		return raw{}, &Refusal{Path: p.Path, Reason: "has special mode bits"}
	}
	if err := folders(p); err != nil {
		return raw{}, err
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxSize+1))
	if err != nil {
		return raw{}, err
	}
	if len(data) > MaxSize {
		return raw{}, &Refusal{Path: p.Path, Reason: "is too large"}
	}
	changed := fi.ModTime()
	if c := ctime(st); c.After(changed) {
		changed = c
	}
	return raw{data: data, changed: changed,
		meta: fmt.Sprintf("%d|%d|%o|%d|%d", fi.Size(), st.Uid, mode.Perm(), fi.ModTime().UnixNano(), ctime(st).UnixNano())}, nil
}

// folders checks every folder from the file's own up to p.Top.
func folders(p Policy) error {
	top := filepath.Clean(p.Top)
	for dir := filepath.Dir(filepath.Clean(p.Path)); ; dir = filepath.Dir(dir) {
		fi, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return errors.New("cannot read a folder's owner")
		}
		switch {
		case fi.Mode()&fs.ModeSymlink != 0 || !fi.IsDir():
			return &Refusal{Path: p.Path, Reason: dir + " is not a plain folder"}
		case st.Uid != p.UID:
			return &Refusal{Path: p.Path, Reason: fmt.Sprintf("its folder %s is owned by user %d, not by root", dir, st.Uid)}
		case fi.Mode().Perm()&0o022 != 0:
			return &Refusal{Path: p.Path, Reason: fmt.Sprintf("its folder %s can be changed by others (mode %04o)", dir, fi.Mode().Perm())}
		}
		if dir == top || dir == filepath.Dir(dir) || !strings.HasPrefix(dir, top) {
			return nil
		}
	}
}

func ctime(st *syscall.Stat_t) time.Time { return statCtime(st) }
