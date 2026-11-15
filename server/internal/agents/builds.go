package agents

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Build is an EasyRMM agent binary the server hands out.
type Build struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	File   string `json:"file"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`

	modTime time.Time
}

// buildName is how agent builds are named in the build directory.
var buildName = regexp.MustCompile(`^easyrmm-agent-(linux|windows)-(amd64|arm64|386|arm)(\.exe)?$`)

// Builds is the set of agent builds in a directory, read once at startup.
type Builds struct {
	root  *os.Root
	items []Build
}

// LoadBuilds reads the agent builds in dir. A missing directory is an empty
// set: the server then offers no downloads.
func LoadBuilds(dir string) (*Builds, error) {
	if dir == "" {
		return &Builds{}, nil
	}
	root, err := os.OpenRoot(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return &Builds{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("agent builds: %w", err)
	}
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("agent builds: %w", err)
	}
	b := &Builds{root: root}
	for _, e := range entries {
		m := buildName.FindStringSubmatch(e.Name())
		if m == nil || !e.Type().IsRegular() || (m[1] == "windows") != (m[3] == ".exe") {
			continue
		}
		item, err := b.describe(e.Name())
		if err != nil {
			_ = root.Close()
			return nil, err
		}
		item.OS, item.Arch = m[1], m[2]
		b.items = append(b.items, item)
	}
	slices.SortFunc(b.items, func(x, y Build) int { return strings.Compare(x.File, y.File) })
	return b, nil
}

func (b *Builds) describe(name string) (Build, error) {
	f, err := b.root.Open(name)
	if err != nil {
		return Build{}, fmt.Errorf("agent builds: %w", err)
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return Build{}, fmt.Errorf("agent builds: %w", err)
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return Build{}, fmt.Errorf("agent builds: reading %s: %w", name, err)
	}
	return Build{File: name, Size: st.Size(), SHA256: hex.EncodeToString(h.Sum(nil)), modTime: st.ModTime()}, nil
}

// List returns the builds, by file name.
func (b *Builds) List() []Build { return append([]Build{}, b.items...) }

// Find returns the build with a file name.
func (b *Builds) Find(file string) (Build, bool) {
	for _, it := range b.items {
		if it.File == file {
			return it, true
		}
	}
	return Build{}, false
}

// Open opens a build for reading. Only files List returned can be opened.
func (b *Builds) Open(file string) (*os.File, Build, error) {
	it, ok := b.Find(file)
	if !ok {
		return nil, Build{}, fs.ErrNotExist
	}
	f, err := b.root.Open(file)
	return f, it, err
}

// ModTime is when the build was written.
func (b Build) ModTime() time.Time { return b.modTime }

// Checksums renders the builds' SHA-256 sums in sha256sum's format.
func (b *Builds) Checksums() string {
	var sb strings.Builder
	for _, it := range b.items {
		sb.WriteString(it.SHA256 + "  " + it.File + "\n")
	}
	return sb.String()
}
