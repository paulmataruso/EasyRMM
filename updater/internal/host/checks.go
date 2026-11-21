package host

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/paulmataruso/easyrmm/updater/internal/fetch"
	"github.com/paulmataruso/easyrmm/updater/internal/release"
)

// checkPostgresMajor refuses a release whose PostgreSQL major version is
// not the one the data root's database was made with: such a release says
// so, and is upgraded by hand, by its guide. PostgreSQL 18's image keeps
// its data in <data root>/postgres/<major>/docker.
func checkPostgresMajor(dataRoot string, want int) error {
	dirs, err := os.ReadDir(filepath.Join(dataRoot, "postgres"))
	if err != nil {
		return fmt.Errorf("PostgreSQL's data: %w", err)
	}
	var found []int
	for _, e := range dirs {
		data, err := readSmall(filepath.Join(dataRoot, "postgres", e.Name(), "docker", "PG_VERSION"), 16)
		if err != nil {
			continue
		}
		if n, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
			found = append(found, n)
		}
	}
	switch {
	case len(found) == 0:
		return fmt.Errorf("no PostgreSQL data under %s", filepath.Join(dataRoot, "postgres"))
	case !slices.Contains(found, want):
		return fmt.Errorf("the release runs PostgreSQL %d, and this deployment's database is PostgreSQL %v: upgrade PostgreSQL by hand, as the release's guide says", want, found)
	}
	return nil
}

// readSmall reads a small regular file in a directory a container can
// write: without following a link at its name, without blocking on a
// pipe, and no more than limit bytes.
func readSmall(path string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) //nolint:gosec // a path the updater builds, opened as the comment says
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	return io.ReadAll(io.LimitReader(f, limit))
}

// treeSize is the space a directory's files take, links not followed.
func treeSize(dir string) (int64, error) {
	var total int64
	err := filepath.WalkDir(dir, func(_ string, e fs.DirEntry, err error) error {
		// The running deployment's files come and go while they are
		// counted.
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		fi, err := e.Info()
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			total += st.Blocks * 512
		}
		return nil
	})
	return total, err
}

// mountInfo lists the host's mount points; the tests' lists their own.
var mountInfo = "/proc/self/mountinfo"

// mountPoints lists the mount points mountInfo names.
func mountPoints() ([]string, error) {
	data, err := os.ReadFile(mountInfo)
	if err != nil {
		return nil, fmt.Errorf("listing mount points: %w", err)
	}
	var points []string
	for _, line := range strings.Split(string(data), "\n") {
		// ID, parent ID, major:minor, root, then the mount point, with
		// space, tab, newline and backslash written in octal.
		if f := strings.Fields(line); len(f) > 4 {
			points = append(points, unescapeOctal(f[4]))
		}
	}
	return points, nil
}

func unescapeOctal(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// within reports whether path is dir or lies under it, by their names or
// by where their links lead.
func within(path, dir string) bool {
	for _, p := range resolved(path) {
		for _, d := range resolved(dir) {
			if rel, err := filepath.Rel(d, p); err == nil && rel != ".." && !strings.HasPrefix(rel, "../") {
				return true
			}
		}
	}
	return false
}

// resolved is a path by its name and by where its links lead, when that
// differs.
func resolved(path string) []string {
	paths := []string{filepath.Clean(path)}
	if r, err := filepath.EvalSymlinks(path); err == nil && r != paths[0] {
		paths = append(paths, r)
	}
	return paths
}

// checkDataRoot refuses a data root that a backup and a restore would not
// cover, and measures it. A backup copies each entry with cp -a, which
// copies a link as the link, not what it leads to; a restore moves each
// entry aside, which a mount point refuses (EBUSY). So an entry that is a
// link, and a mount point anywhere under the data root (another disk, or a
// directory bound there), are refused, before anything stops. Links deeper
// down are the services' own, which they follow inside their containers,
// and are copied as they are. The data root itself may be a mount point.
func checkDataRoot(dataRoot string) (int64, error) {
	points, err := mountPoints()
	if err != nil {
		return 0, err
	}
	for _, p := range points {
		if within(p, dataRoot) && !within(dataRoot, p) && !skippedPath(dataRoot, p) {
			return 0, fmt.Errorf("%s is a mount point in the data root %s: a restore cannot move it aside, and a backup copies it onto the backup's disk. Mount the data root as a whole instead (docs/operations/updater.md#the-data-root)", p, dataRoot)
		}
	}
	entries, err := os.ReadDir(dataRoot)
	if err != nil {
		return 0, err
	}
	var total int64
	for _, e := range entries {
		if skippedEntry(e.Name()) {
			continue
		}
		path := filepath.Join(dataRoot, e.Name())
		if e.Type()&fs.ModeSymlink != 0 {
			target, _ := os.Readlink(path)
			return 0, fmt.Errorf("%s is a link (to %s): a backup copies the link, not what it leads to, and a restore puts the link back. Move what it leads to into the data root, or mount it there as a whole (docs/operations/updater.md#the-data-root)", path, target)
		}
		size, err := treeSize(path)
		if err != nil {
			return 0, fmt.Errorf("measuring the data root: %w", err)
		}
		total += size
	}
	return total, nil
}

// skippedPath reports whether path lies in an entry of the data root that
// backups leave out.
func skippedPath(dataRoot, path string) bool {
	for _, root := range resolved(dataRoot) {
		for _, p := range resolved(path) {
			if rel, err := filepath.Rel(root, p); err == nil && rel != "." {
				if skippedEntry(strings.SplitN(rel, "/", 2)[0]) {
					return true
				}
			}
		}
	}
	return false
}

// freeSpace is the room left for root on the filesystem holding path; the
// tests' disks are as full as they say.
var freeSpace = func(path string) (int64, error) {
	var s syscall.Statfs_t
	if err := syscall.Statfs(path, &s); err != nil {
		return 0, err
	}
	return int64(s.Bavail) * s.Bsize, nil //nolint:gosec // block counts fit
}

// bundleSpace is the room counted for a bundle, downloaded and again
// unpacked: it holds the updater for two architectures, about 20 MiB each.
const bundleSpace = 128 << 20

// noSpace reports whether err is a disk, or a quota, that ran out of room:
// a later attempt may have the room.
func noSpace(err error) bool {
	return errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT) ||
		strings.Contains(strings.ToLower(err.Error()), "no space left on device")
}

// checkSpace makes sure each filesystem has room for what the attempt may
// write on it, the needs on one filesystem added up: in backup_dir, the
// backup (a full copy of the data root, the deployment's tree and the
// configuration: reflinks, where there are any, only save room); in the
// data root, a restore's copy of it, should the upgrade fail; in Docker's
// data directory, the new images; in the updater's state directory and its
// bundle directory, the bundle downloaded and unpacked.
func (up *upgrade) checkSpace(ctx context.Context, dataSize int64) error {
	u, d := up.u, up.d
	treeSize, err := deploymentSize(d.dir)
	if err != nil {
		return err
	}
	if err := ensureRootDir(u.Config.BackupDir, 0o700); err != nil {
		return err
	}
	dockerRoot, err := u.Docker.RootDir(ctx)
	if err != nil {
		return err
	}
	type fsNeed struct {
		path  string
		bytes int64
		what  []string
	}
	var order []uint64
	needs := map[uint64]*fsNeed{}
	for _, n := range []struct {
		path, what string
		bytes      int64
	}{
		{u.Config.BackupDir, "the backup", dataSize + treeSize},
		{d.dataRoot, "a restore's copy of the data root", dataSize},
		{dockerRoot, "the new images", minImageSpace},
		{u.StateDir, "the bundle's download", bundleSpace},
		{u.BundleDir, "the unpacked bundle", bundleSpace},
	} {
		var st syscall.Stat_t
		if err := syscall.Stat(n.path, &st); err != nil {
			return fmt.Errorf("%s: %w", n.path, err)
		}
		f, ok := needs[st.Dev]
		if !ok {
			f = &fsNeed{path: n.path}
			needs[st.Dev] = f
			order = append(order, st.Dev)
		}
		f.bytes += n.bytes
		f.what = append(f.what, fmt.Sprintf("%s %d MiB (%s)", n.what, n.bytes>>20, n.path))
	}
	for _, dev := range order {
		f := needs[dev]
		free, err := freeSpace(f.path)
		if err != nil {
			return err
		}
		if free < f.bytes {
			return fmt.Errorf("the filesystem of %s has %d MiB free, and the upgrade needs %d MiB on it: %s", f.path, free>>20, f.bytes>>20, strings.Join(f.what, ", "))
		}
	}
	return nil
}

// deploymentSize is the space the deployment's tree takes: its deploy/ and
// docker/ directories, which a backup copies.
func deploymentSize(deployDir string) (int64, error) {
	var total int64
	for _, name := range []string{"deploy", "docker"} {
		n, err := treeSize(filepath.Join(filepath.Dir(deployDir), name))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return 0, err
		}
		total += n
	}
	return total, nil
}

// ensureRootPath makes dir, root's with mode 755, unless it is there, and
// makes sure no one but root can change it or a directory above it: each
// is root's, and only root can write it, or it is sticky (as /tmp is),
// where no one can rename or remove what is not theirs.
func ensureRootPath(dir string) error {
	if err := ensureRootDir(dir, 0o755); err != nil {
		return err
	}
	for p := filepath.Dir(dir); p != checkedBelow; p = filepath.Dir(p) {
		fi, err := os.Stat(p)
		if err != nil {
			return err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		switch {
		case !ok || (st.Uid != 0 && st.Uid != rootUID):
			return fmt.Errorf("%s, above %s, does not belong to root", p, dir)
		case fi.Mode().Perm()&0o022 != 0 && fi.Mode()&fs.ModeSticky == 0:
			return fmt.Errorf("%s, above %s, can be written by others than root (mode %o)", p, dir, fi.Mode().Perm())
		}
		if p == filepath.Dir(p) {
			return nil
		}
	}
	return nil
}

// checkedBelow, when set, is where ensureRootPath stops: the directories
// from it up are not checked. It is "" on a host, so every directory up
// to / is; the tests set it to their TMPDIR, which is the developer's.
var checkedBelow string

// downloadBundle downloads a verified manifest's bundle and checks it
// against the manifest's SHA-256.
func downloadBundle(ctx context.Context, src fetch.Source, m *release.Manifest, path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // a new file in the updater's own directory
	if err != nil {
		return err
	}
	h := sha256.New()
	if err := src.Bundle(ctx, m.Version, io.MultiWriter(f, h)); err != nil {
		_ = f.Close()
		return &transientError{err}
	}
	if err := f.Close(); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != m.BundleSHA256 {
		return fmt.Errorf("the bundle's SHA-256 is %s, not the manifest's %s", got, m.BundleSHA256)
	}
	return nil
}

// runSetup runs the new bundle's setup.sh --upgrade --no-updater in its
// deploy/ directory, with a fixed environment and nothing to read, and
// logs what it says.
func runSetup(ctx context.Context, deployDir string, log *slog.Logger) error {
	cmd := exec.CommandContext(ctx, filepath.Join(deployDir, "scripts", "setup.sh"), "--upgrade", "--no-updater") //nolint:gosec // the verified bundle's setup.sh
	cmd.Dir = deployDir
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", "LANG=C.UTF-8"}
	cmd.SysProcAttr = ownGroup()
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	sc := bufio.NewScanner(&out)
	for sc.Scan() {
		log.Info("setup.sh: " + sc.Text())
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return fmt.Errorf("setup.sh --upgrade failed (exit %d)", exit.ExitCode())
	}
	return err
}
