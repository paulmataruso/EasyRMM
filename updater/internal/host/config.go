// Package host is the updater on the host (ADR-0052): it upgrades the
// Compose deployment to a verified build and rolls it back, as root.
package host

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/paulmataruso/easyrmm/updater/internal/release"
)

// DefaultConfigPath is where setup.sh writes the configuration.
const DefaultConfigPath = "/etc/easyrmm/updater.conf"

// DefaultBackupDir is where backups go when the configuration names no
// other place.
const DefaultBackupDir = "/var/backups/easyrmm-updater"

// Config is /etc/easyrmm/updater.conf: root's, mode 600. The server never
// writes it and a request cannot change it; the updater itself rewrites
// only its deployment line, when an upgrade or a rollback moves the
// deployment to another directory.
//
//	# comments and blank lines are kept
//	deployment = /opt/easyrmm/easyrmm-v1.2.3/deploy
//	channel = stable
//	auto_upgrade = no
//	auto_upgrade_hours = 2-5
//	backup_dir = /var/backups/easyrmm-updater
type Config struct {
	Path string
	// Deployment is the deploy/ directory of the running version: its
	// docker-compose.yml and .env.
	Deployment string
	Channel    release.Channel
	// AutoUpgrade has the hourly timer upgrade to the newest version the
	// channel offers, in Hours.
	AutoUpgrade bool
	Hours       Hours
	// BackupDir holds the backups each upgrade takes.
	BackupDir string
}

// Hours is the part of the day, in the host's time zone, when automatic
// upgrades may start: from From:00 to before To:00, across midnight when
// To is not after From. 0-24 is any time.
type Hours struct{ From, To int }

// Contains reports whether t is within the hours.
func (h Hours) Contains(t time.Time) bool {
	hr := t.Hour()
	if h.From < h.To {
		return hr >= h.From && hr < h.To
	}
	return hr >= h.From || hr < h.To
}

func (h Hours) String() string { return fmt.Sprintf("%02d:00 to %02d:00", h.From, h.To) }

var hoursRE = regexp.MustCompile(`^([0-9]{1,2})-([0-9]{1,2})$`)

func parseHours(s string) (Hours, error) {
	m := hoursRE.FindStringSubmatch(s)
	if m == nil {
		return Hours{}, fmt.Errorf("%q is not hours such as 2-5", s)
	}
	from, _ := strconv.Atoi(m[1])
	to, _ := strconv.Atoi(m[2])
	if from > 23 || to > 24 || from == to {
		return Hours{}, fmt.Errorf("%q is not hours such as 2-5 (from 0 to 23, until 1 to 24, not the same)", s)
	}
	return Hours{From: from, To: to}, nil
}

// absPath is an absolute path the updater accepts in its configuration:
// clean, without spaces or quotes.
var absPath = regexp.MustCompile(`^/[A-Za-z0-9_./+@-]*$`)

// LoadConfig reads the configuration, which must be a regular file of
// root's that nobody else can read or write (it decides what root runs).
func LoadConfig(path string) (*Config, error) {
	data, err := readOwnFile(path, 64<<10)
	if err != nil {
		return nil, err
	}
	c := &Config{Path: path, Channel: release.ChannelStable, Hours: Hours{0, 24}, BackupDir: DefaultBackupDir}
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if !ok || key == "" {
			return nil, fmt.Errorf("%s:%d: not key = value", path, n)
		}
		if seen[key] {
			return nil, fmt.Errorf("%s:%d: %s is set twice", path, n, key)
		}
		seen[key] = true
		if err := c.set(key, value); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, n, err)
		}
	}
	if c.Deployment == "" {
		return nil, fmt.Errorf("%s names no deployment", path)
	}
	return c, nil
}

func (c *Config) set(key, value string) error {
	var err error
	switch key {
	case "deployment":
		if !absPath.MatchString(value) || filepath.Clean(value) != value {
			return fmt.Errorf("deployment %q is not a clean absolute path", value)
		}
		c.Deployment = value
	case "channel":
		c.Channel, err = release.ParseChannel(value)
	case "auto_upgrade":
		switch value {
		case "yes", "true":
			c.AutoUpgrade = true
		case "no", "false":
			c.AutoUpgrade = false
		default:
			return fmt.Errorf("auto_upgrade %q is not yes or no", value)
		}
	case "auto_upgrade_hours":
		c.Hours, err = parseHours(value)
	case "backup_dir":
		if !absPath.MatchString(value) || filepath.Clean(value) != value || value == "/" {
			return fmt.Errorf("backup_dir %q is not a clean absolute path", value)
		}
		c.BackupDir = value
	default:
		return fmt.Errorf("unknown setting %q", key)
	}
	return err
}

// SetDeployment rewrites the deployment line, keeping every other line, by
// writing a new file beside it and renaming it into place.
func (c *Config) SetDeployment(dir string) error {
	if !absPath.MatchString(dir) || filepath.Clean(dir) != dir {
		return fmt.Errorf("deployment %q is not a clean absolute path", dir)
	}
	data, err := readOwnFile(c.Path, 64<<10)
	if err != nil {
		return err
	}
	var out bytes.Buffer
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		if key, _, ok := strings.Cut(strings.TrimSpace(line), "="); ok && strings.TrimSpace(key) == "deployment" {
			line = "deployment = " + dir
		}
		out.WriteString(line + "\n")
	}
	if err := writeFileAtomic(c.Path, out.Bytes(), 0o600); err != nil {
		return err
	}
	c.Deployment = dir
	return nil
}

// readOwnFile reads a small regular file that belongs to root and that no
// one else can write, without following a link to it.
func readOwnFile(path string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) //nolint:gosec // root's own file, checked below
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !fi.Mode().IsRegular():
		return nil, fmt.Errorf("%s is not a regular file", path)
	case !ok || st.Uid != rootUID:
		return nil, fmt.Errorf("%s does not belong to root", path)
	case fi.Mode().Perm()&0o022 != 0:
		return nil, fmt.Errorf("%s can be written by others than root (mode %o)", path, fi.Mode().Perm())
	case fi.Size() > limit:
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	return b, nil
}

// rootUID is the owner the updater's own files must have: root, except in
// the package's tests, which run as anyone.
var rootUID uint32

// writeFileAtomic writes a file of root's in a directory only root can
// write, through a new file, synced, renamed into place, and the directory
// synced: once it returns, the new file is what a power cut leaves.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".new-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := syncDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("syncing %s after writing %s: %w", filepath.Dir(path), filepath.Base(path), err)
	}
	return nil
}

// syncDir makes a directory's entries durable: a file renamed into it is
// there after a power cut once it returns. The tests watch it.
var syncDir = func(dir string) error {
	f, err := os.Open(dir) //nolint:gosec // a directory the updater writes
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// syncFS writes what the kernel holds of the filesystem of path to its disk
// (syncfs(2)): the copies cp made there are durable once it returns. The
// tests watch it.
var syncFS = func(path string) error {
	f, err := os.Open(path) //nolint:gosec // a directory the updater writes
	if err != nil {
		return err
	}
	defer f.Close()
	return unix.Syncfs(int(f.Fd())) //nolint:gosec // a file descriptor
}
