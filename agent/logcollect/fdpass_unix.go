//go:build !windows

package logcollect

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// maxAuditFiles bounds the descriptors passed at once.
const maxAuditFiles = 16

// AuditFiles opens auditd's current log and each rotated one read-only, oldest
// first, current last: audit.log.N ... audit.log.1, audit.log. The agent
// (root) calls it; only it can read them.
func AuditFiles(dir string) ([]*os.File, error) {
	des, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	type rot struct {
		n int
		p string
	}
	var rots []rot
	for _, de := range des {
		if n, ok := strings.CutPrefix(de.Name(), "audit.log."); ok {
			if i, err := strconv.Atoi(n); err == nil {
				rots = append(rots, rot{i, filepath.Join(dir, de.Name())})
			}
		}
	}
	sort.Slice(rots, func(i, j int) bool { return rots[i].n > rots[j].n })
	paths := make([]string, 0, len(rots)+1)
	for _, r := range rots {
		paths = append(paths, r.p)
	}
	paths = append(paths, filepath.Join(dir, "audit.log"))
	if len(paths) > maxAuditFiles {
		paths = paths[len(paths)-maxAuditFiles:]
	}
	var out []*os.File
	for _, p := range paths {
		f, err := os.Open(p) //nolint:gosec // p is audit.log or a rotated name found in auditd's directory
		if err != nil {
			continue // rotated away since the listing, or no audit.log yet
		}
		out = append(out, f)
	}
	if len(out) == 0 {
		return nil, errors.New("no audit log to read")
	}
	return out, nil
}

// SendFiles writes the files' descriptors to conn in one message.
func SendFiles(conn *net.UnixConn, files []*os.File) error {
	fds := make([]int, 0, len(files))
	for _, f := range files {
		fds = append(fds, int(f.Fd()))
	}
	oob := syscall.UnixRights(fds...)
	n, oobn, err := conn.WriteMsgUnix([]byte{byte(len(files))}, oob, nil) //nolint:gosec // at most maxAuditFiles
	if err != nil {
		return err
	}
	if n != 1 || oobn != len(oob) {
		return errors.New("logcollect: a short write passing descriptors")
	}
	return nil
}

// ReceiveFiles reads one message of descriptors from conn.
func ReceiveFiles(conn *net.UnixConn) ([]*os.File, error) {
	buf := make([]byte, 1)
	oob := make([]byte, syscall.CmsgSpace(4*maxAuditFiles))
	_, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
	if err != nil {
		return nil, err
	}
	msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return nil, err
	}
	var files []*os.File
	for _, m := range msgs {
		fds, err := syscall.ParseUnixRights(&m)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			files = append(files, os.NewFile(uintptr(fd), "audit"))
		}
	}
	return files, nil
}

// ServeAudit listens on a Unix socket at path and passes the audit files to
// each collector that connects, until ctx ends. The socket is made owner-only
// by the caller's umask and directory; files is called on each connection, so
// a rotation is seen at once (ADR-0060).
func ServeAudit(ctx context.Context, path string, files func() ([]*os.File, error)) error {
	_ = os.Remove(path)
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return err
	}
	defer l.Close()
	// Anyone who can reach the socket is the collector: the spool's directory,
	// where it lives, admits only that user and root.
	if err := os.Chmod(path, 0o666); err != nil { //nolint:gosec // see above
		return err
	}
	go func() { <-ctx.Done(); _ = l.Close() }()
	for {
		c, err := l.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		fs, ferr := files()
		if ferr == nil {
			_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_ = SendFiles(c, fs)
		}
		for _, f := range fs {
			_ = f.Close()
		}
		_ = c.Close()
	}
}

// FetchAudit connects to the agent's socket and returns the descriptors it
// passes. The caller closes them.
func FetchAudit(path string) ([]*os.File, error) {
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("the agent's audit socket: %w", err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	return ReceiveFiles(c)
}
