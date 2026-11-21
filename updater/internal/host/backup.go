package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
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
// copied as links, and nothing is written through one. Each copy is then
// checked against its source (verifyCopy), both ways: a backup and a
// restore alike.
//
// The data root holds every volume of deploy/docker-compose.yml that holds
// state: PostgreSQL's whole cluster (EasyRMM's, the engine's and, when
// installed, Authentik's databases, copied stopped), the server's,
// MeshCentral's, the engine's and Authentik's directories. The other
// volumes are the deployment's own docker/ files, in the tree, the
// updater's own status, and EASYRMM_TLS_DIR, the operator's certificates
// in manual TLS mode: setup.sh puts it in the data root, as tls/, and an
// operator who points it elsewhere keeps it there, mounted read-only and
// never changed by an upgrade (TestBackupCoversEveryVolume).

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

// cpProgram is the cp that copies; the tests' runs out of room.
var cpProgram = "cp"

// copyTree copies src to dst, which must not exist, preserving owners,
// modes, times, links and hard links. A copy that runs out of room fails
// with syscall.ENOSPC (or EDQUOT): a later attempt may have the room.
func copyTree(ctx context.Context, src, dst string) error {
	if _, err := os.Lstat(dst); !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("will not copy into %s: it exists", dst)
	}
	cmd := exec.CommandContext(ctx, cpProgram, "-a", "--reflink=auto", "--no-target-directory", "--", src, dst) //nolint:gosec // paths the updater builds
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	cmd.SysProcAttr = ownGroup()
	if out, err := cmd.CombinedOutput(); err != nil {
		for errno, text := range map[syscall.Errno]string{syscall.ENOSPC: "No space left on device", syscall.EDQUOT: "Disk quota exceeded"} {
			if strings.Contains(string(out), text) {
				err = fmt.Errorf("%w (%w)", err, errno)
			}
		}
		return fmt.Errorf("copying %s to %s: %w: %s", src, dst, err, lastLines(string(out), 3))
	}
	return verifyCopy(src, dst)
}

// treeEntry is what verifyCopy compares of each entry: its type and
// permissions, its owner, a regular file's size and a link's target.
type treeEntry struct {
	mode     fs.FileMode
	uid, gid uint32
	size     int64
	link     string
}

func (e treeEntry) String() string {
	s := fmt.Sprintf("%v %d:%d", e.mode, e.uid, e.gid)
	if e.mode.IsRegular() {
		s += fmt.Sprintf(" %d bytes", e.size)
	}
	if e.link != "" {
		s += " -> " + e.link
	}
	return s
}

// verifyCopy checks that dst holds exactly what src holds, entry by entry.
// cp -a fails on what it cannot copy; this also catches what changed while
// it copied, or a copy cut short.
func verifyCopy(src, dst string) error {
	want, err := listTree(src)
	if err != nil {
		return err
	}
	got, err := listTree(dst)
	if err != nil {
		return err
	}
	for _, name := range slices.Sorted(maps.Keys(want)) {
		g, ok := got[name]
		switch {
		case !ok:
			return fmt.Errorf("the copy of %s lacks %s", src, name)
		case g != want[name]:
			return fmt.Errorf("the copy of %s differs at %s: %s, not %s", src, name, g, want[name])
		}
	}
	for _, name := range slices.Sorted(maps.Keys(got)) {
		if _, ok := want[name]; !ok {
			return fmt.Errorf("the copy of %s has %s, which it does not", src, name)
		}
	}
	return nil
}

// listTree lists every entry under root, root itself as ".", without
// following links.
func listTree(root string) (map[string]treeEntry, error) {
	entries := map[string]treeEntry{}
	err := filepath.WalkDir(root, func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := os.Lstat(path)
		if err != nil {
			return err
		}
		e := treeEntry{mode: fi.Mode()}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			e.uid, e.gid = st.Uid, st.Gid
		}
		switch {
		case fi.Mode().IsRegular():
			e.size = fi.Size()
		case fi.Mode()&fs.ModeSymlink != 0:
			if e.link, err = os.Readlink(path); err != nil {
				return err
			}
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		entries[rel] = e
		return nil
	})
	return entries, err
}

// backupDirFor is the directory a backup described by meta goes in.
func backupDirFor(backupDir string, meta BackupMeta) string {
	return filepath.Join(backupDir, meta.Taken.UTC().Format("20060102T150405Z")+"-"+meta.Version)
}

// takeBackup copies the stopped deployment into dir, a new directory in
// backup_dir, and calls made once dir exists, to record it. A backup that
// fails is removed, so that it takes no room from the version started
// again.
func takeBackup(ctx context.Context, dir string, meta BackupMeta, configPath string, made func() error) (b *Backup, err error) {
	if err := ensureRootDir(filepath.Dir(dir), 0o700); err != nil {
		return nil, err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, err
	}
	defer func() {
		if err == nil {
			return
		}
		if rerr := os.RemoveAll(dir); rerr != nil {
			err = fmt.Errorf("%w; removing the incomplete backup %s: %w", err, dir, rerr)
		}
	}()
	if err := made(); err != nil {
		return nil, err
	}
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
	return &Backup{Dir: dir, Meta: meta}, nil
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
	// A restore done again in the same second, after an interrupted one,
	// moves the half restored entries aside beside the first's.
	asideDir := filepath.Join(dataRoot, failedPrefix+aside)
	for i := 2; ; i++ {
		err := os.Mkdir(asideDir, 0o700)
		if err == nil {
			break
		}
		if !errors.Is(err, fs.ErrExist) {
			return "", err
		}
		asideDir = filepath.Join(dataRoot, fmt.Sprintf("%s%s.%d", failedPrefix, aside, i))
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
		// Left by an interrupted restore.
		if err := os.RemoveAll(old); err != nil {
			return err
		}
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
