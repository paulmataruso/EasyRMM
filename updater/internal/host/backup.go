package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// A backup (ADR-0052, step 4) is a copy of the whole data root, the
// deployment's tree (deploy/, with .env, and the docker/ files it mounts)
// and updater.conf, taken while every service is stopped:
//
//	<backup dir>/<UTC time>-<version>/     root's, mode 700
//	    data/                              the data root's entries
//	    tree/deploy/  tree/docker/
//	    updater.conf
//	    backup.json                        written last: the backup is complete
//
// Copies are made with cp -a, with reflinks where the filesystem has them,
// into directories that do not exist yet: links in what is copied are
// copied as links, and nothing is written through one.

// KeepBackups is how many backups are kept.
const KeepBackups = 2

// The data root's entries a backup leaves out: the updater's own
// directory, and failed data roots kept for diagnosis.
const (
	updaterEntry = "updater"
	failedPrefix = ".failed-"
)

func skippedEntry(name string) bool {
	return name == updaterEntry || strings.HasPrefix(name, failedPrefix)
}

// BackupMeta describes a backup, in its backup.json.
type BackupMeta struct {
	// Version is the version the backup holds, its Deployment that
	// version's deploy/ directory.
	Version    string    `json:"version"`
	Deployment string    `json:"deployment"`
	DataRoot   string    `json:"dataRoot"`
	Taken      time.Time `json:"taken"`
}

// Backup is one backup directory.
type Backup struct {
	Dir  string
	Meta BackupMeta
}

// copyTree copies src to dst, which must not exist, preserving owners,
// modes, times, links and hard links.
func copyTree(ctx context.Context, src, dst string) error {
	if _, err := os.Lstat(dst); !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("will not copy into %s: it exists", dst)
	}
	cmd := exec.CommandContext(ctx, "cp", "-a", "--reflink=auto", "--no-target-directory", "--", src, dst) //nolint:gosec // paths the updater builds
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	cmd.SysProcAttr = ownGroup()
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("copying %s to %s: %w: %s", src, dst, err, lastLines(string(out), 3))
	}
	return nil
}

// takeBackup copies the stopped deployment into a new backup directory.
func takeBackup(ctx context.Context, backupDir string, meta BackupMeta, configPath string) (*Backup, error) {
	if err := ensureRootDir(backupDir, 0o700); err != nil {
		return nil, err
	}
	dir := filepath.Join(backupDir, meta.Taken.UTC().Format("20060102T150405Z")+"-"+meta.Version)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, err
	}
	b := &Backup{Dir: dir, Meta: meta}
	if err := os.Mkdir(filepath.Join(dir, "data"), 0o700); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(meta.DataRoot)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if skippedEntry(e.Name()) {
			continue
		}
		if err := copyTree(ctx, filepath.Join(meta.DataRoot, e.Name()), filepath.Join(dir, "data", e.Name())); err != nil {
			return nil, err
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "tree"), 0o700); err != nil {
		return nil, err
	}
	root := filepath.Dir(meta.Deployment)
	for _, name := range []string{"deploy", "docker"} {
		if err := copyTree(ctx, filepath.Join(root, name), filepath.Join(dir, "tree", name)); err != nil {
			return nil, err
		}
	}
	if err := copyTree(ctx, configPath, filepath.Join(dir, "updater.conf")); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(filepath.Join(dir, "backup.json"), append(data, '\n'), 0o600); err != nil {
		return nil, err
	}
	return b, nil
}

// openBackup reads a complete backup.
func openBackup(dir string) (*Backup, error) {
	data, err := readOwnFile(filepath.Join(dir, "backup.json"), 64<<10)
	if err != nil {
		return nil, fmt.Errorf("backup %s is not complete: %w", dir, err)
	}
	b := &Backup{Dir: dir}
	if err := json.Unmarshal(data, &b.Meta); err != nil {
		return nil, fmt.Errorf("backup %s: %w", dir, err)
	}
	return b, nil
}

// rotateBackups removes every backup but the newest KeepBackups complete
// ones and keep (a backup a rollback may still restore), and incomplete
// ones (an attempt that failed while copying) other than keep.
func rotateBackups(backupDir string, keep ...string) error {
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		return err
	}
	var complete []string
	for _, e := range entries {
		dir := filepath.Join(backupDir, e.Name())
		if !e.IsDir() || e.Type()&fs.ModeSymlink != 0 {
			continue
		}
		if _, err := openBackup(dir); err == nil {
			complete = append(complete, dir)
		} else if !slices.Contains(keep, dir) {
			if err := os.RemoveAll(dir); err != nil {
				return err
			}
		}
	}
	// Names start with the time they were taken.
	slices.Sort(complete)
	for i, dir := range complete {
		if i >= len(complete)-KeepBackups || slices.Contains(keep, dir) {
			continue
		}
		if err := os.RemoveAll(dir); err != nil {
			return err
		}
	}
	return nil
}

// restoreData puts the backup's data root back: the failed data root's
// entries moved aside into a directory only root can reach, kept for
// diagnosis, and the backup's copied into the emptied data root, so that
// root writes into no directory a container could have written. It returns
// where the failed entries went.
func (b *Backup) restoreData(ctx context.Context, dataRoot, aside string) (string, error) {
	asideDir := filepath.Join(dataRoot, failedPrefix+aside)
	if err := os.Mkdir(asideDir, 0o700); err != nil {
		return "", err
	}
	entries, err := os.ReadDir(dataRoot)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if skippedEntry(e.Name()) {
			continue
		}
		if err := os.Rename(filepath.Join(dataRoot, e.Name()), filepath.Join(asideDir, e.Name())); err != nil {
			return "", err
		}
	}
	saved, err := os.ReadDir(filepath.Join(b.Dir, "data"))
	if err != nil {
		return "", err
	}
	for _, e := range saved {
		if err := copyTree(ctx, filepath.Join(b.Dir, "data", e.Name()), filepath.Join(dataRoot, e.Name())); err != nil {
			return "", err
		}
	}
	return asideDir, nil
}

// restoreTree puts the backup's deploy/ and docker/ back under root.
func (b *Backup) restoreTree(ctx context.Context, root, aside string) error {
	if err := os.MkdirAll(root, 0o755); err != nil { //nolint:gosec // the deployment's files, which containers read
		return err
	}
	for _, name := range []string{"deploy", "docker"} {
		dst := filepath.Join(root, name)
		old := filepath.Join(root, "."+name+".replaced-"+aside)
		if err := os.Rename(dst, old); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if err := copyTree(ctx, filepath.Join(b.Dir, "tree", name), dst); err != nil {
			return err
		}
		if err := os.RemoveAll(old); err != nil {
			return err
		}
	}
	return nil
}

// removeFailedData removes the failed data roots kept for diagnosis, once
// an upgrade succeeds.
func removeFailedData(dataRoot string) error {
	entries, err := os.ReadDir(dataRoot)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), failedPrefix) {
			if err := os.RemoveAll(filepath.Join(dataRoot, e.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}
