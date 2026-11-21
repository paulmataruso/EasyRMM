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

// freeSpace is the room left for root on the filesystem holding path.
func freeSpace(path string) (int64, error) {
	var s syscall.Statfs_t
	if err := syscall.Statfs(path, &s); err != nil {
		return 0, err
	}
	return int64(s.Bavail) * s.Bsize, nil //nolint:gosec // block counts fit
}

// checkSpace makes sure there is room for a copy of the data root (a full
// copy: reflinks, where there are any, only save room) and for new images.
func (up *upgrade) checkSpace(ctx context.Context) error {
	u, d := up.u, up.d
	need, err := treeSize(d.dataRoot)
	if err != nil {
		return fmt.Errorf("measuring the data root: %w", err)
	}
	if err := ensureRootDir(u.Config.BackupDir, 0o700); err != nil {
		return err
	}
	if free, err := freeSpace(u.Config.BackupDir); err != nil {
		return err
	} else if free < need {
		return fmt.Errorf("%s has %d MiB free; the backup needs %d MiB", u.Config.BackupDir, free>>20, need>>20)
	}
	dockerRoot, err := u.Docker.RootDir(ctx)
	if err != nil {
		return err
	}
	if free, err := freeSpace(dockerRoot); err != nil {
		return err
	} else if free < minImageSpace {
		return fmt.Errorf("the Docker root %s has %d MiB free; the new images need at least %d MiB", dockerRoot, free>>20, minImageSpace>>20)
	}
	return nil
}

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
