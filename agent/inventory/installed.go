package inventory

import (
	"context"
	"crypto/md5" //nolint:gosec // reported next to SHA-256 for allow lists that ask for MD5; never trusted (ADR-0070)
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// Installed hashes the programs the agents install (ADR-0070): the EasyRMM
// agent, MeshAgent and the EasyPatch agent's folder. It sends a report when
// something changed, so a device never shows hashes of a build it no longer
// runs, and once a day.
type Installed struct {
	// AgentExe, MeshExe and PatchDir are where the programs are; "" skips
	// one. PatchDir is hashed file by file.
	AgentExe, MeshExe, PatchDir string
	AgentVersion                string
	// MeshVersion and PatchVersion name a build; each is asked again only
	// when that program's files changed.
	MeshVersion  func(ctx context.Context) string
	PatchVersion func(ctx context.Context) string
	Now          func() time.Time

	mu       sync.Mutex
	cache    map[string]hashed
	lastFP   string
	lastSent time.Time
	versions map[string]versionAt
}

type hashed struct {
	key      string // size and modification time
	md5, sha string
}

type versionAt struct{ key, version string }

// Every is how often the report is sent when nothing changed.
const Every = 24 * time.Hour

func (i *Installed) now() time.Time {
	if i.Now != nil {
		return i.Now()
	}
	return time.Now()
}

// Due returns the report when it is due: the first time, when a program's
// files or version changed, and once a day. nil when nothing is due.
func (i *Installed) Due(ctx context.Context) *agentproto.InstalledFiles {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.cache == nil {
		i.cache, i.versions = map[string]hashed{}, map[string]versionAt{}
	}
	paths := i.paths()
	fp := i.fingerprint(paths)
	if fp == i.lastFP && i.now().Sub(i.lastSent) < Every {
		return nil
	}
	rep := &agentproto.InstalledFiles{AgentVersion: i.AgentVersion, ObservedAt: i.now().UTC()}
	for _, f := range paths {
		h, size, err := i.hash(f.path)
		if err != nil {
			continue // missing or unreadable: absent from the report
		}
		rep.Files = append(rep.Files, agentproto.InstalledFile{Program: f.program, Name: f.name, Size: size, MD5: h.md5, SHA256: h.sha})
	}
	rep.MeshAgentVersion = i.version(ctx, "mesh", i.MeshExe, i.MeshVersion)
	if i.PatchDir != "" {
		rep.PatchAgentVersion = i.version(ctx, "patch", filepath.Join(i.PatchDir, "EasyPatch.Agent.exe"), i.PatchVersion)
	}
	if rep.Check() != nil {
		// Too many files: keep the first MaxInstalledFiles, in name order.
		rep.Files = rep.Files[:min(len(rep.Files), agentproto.MaxInstalledFiles)]
	}
	i.lastFP, i.lastSent = i.fingerprint(i.paths()), i.now()
	return rep
}

type installedPath struct{ program, name, path string }

func (i *Installed) paths() []installedPath {
	var out []installedPath
	if i.AgentExe != "" {
		out = append(out, installedPath{agentproto.InstalledAgent, filepath.Base(i.AgentExe), i.AgentExe})
	}
	if i.MeshExe != "" {
		out = append(out, installedPath{agentproto.InstalledMeshAgent, filepath.Base(i.MeshExe), i.MeshExe})
	}
	if i.PatchDir != "" {
		var files []installedPath
		_ = filepath.WalkDir(i.PatchDir, func(p string, d fs.DirEntry, err error) error {
			if err == nil && d.Type().IsRegular() && len(filepath.Base(p)) <= agentproto.MaxInstalledName {
				files = append(files, installedPath{agentproto.InstalledPatchAgent, filepath.Base(p), p})
			}
			return nil
		})
		slices.SortFunc(files, func(a, b installedPath) int { return strings.Compare(a.path, b.path) })
		out = append(out, files...)
	}
	return out
}

func stat(p string) string {
	st, err := os.Stat(p)
	if err != nil {
		return "-"
	}
	return fmt.Sprintf("%d@%d", st.Size(), st.ModTime().UnixNano())
}

func (i *Installed) fingerprint(paths []installedPath) string {
	var b strings.Builder
	b.WriteString(i.AgentVersion)
	for _, p := range paths {
		b.WriteString("|" + p.path + "=" + stat(p.path))
	}
	return b.String()
}

func (i *Installed) hash(path string) (hashed, int64, error) {
	key := stat(path)
	if h, ok := i.cache[path]; ok && h.key == key {
		var size int64
		_, _ = fmt.Sscanf(key, "%d@", &size)
		return h, size, nil
	}
	f, err := os.Open(path) //nolint:gosec // the agents' own program files
	if err != nil {
		return hashed{}, 0, err
	}
	defer func() { _ = f.Close() }()
	m, s := md5.New(), sha256.New() //nolint:gosec // see the import
	n, err := io.Copy(io.MultiWriter(m, s), f)
	if err != nil {
		return hashed{}, 0, err
	}
	h := hashed{key: key, md5: hex.EncodeToString(m.Sum(nil)), sha: hex.EncodeToString(s.Sum(nil))}
	i.cache[path] = h
	return h, n, nil
}

func (i *Installed) version(ctx context.Context, name, exe string, get func(context.Context) string) string {
	if get == nil || exe == "" {
		return ""
	}
	key := stat(exe)
	if v, ok := i.versions[name]; ok && v.key == key {
		return v.version
	}
	v := strings.Join(strings.Fields(get(ctx)), " ")
	if len(v) > 64 {
		v = v[:64]
	}
	i.versions[name] = versionAt{key, v}
	return v
}
