package agents

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// Build is an EasyRMM agent binary the server hands out.
type Build struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	File   string `json:"file"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	// Version is what the build's "version" command prints, from the
	// directory's VERSION file; empty without one.
	Version string `json:"version"`
	// Signed is the operator's signature on a Windows build they signed
	// and uploaded (ADR-0049); nil for the release's build.
	Signed *Signer `json:"signed,omitempty"`

	modTime time.Time
}

// Signer describes the certificate that signed a build, as the console
// shows it.
type Signer struct {
	Subject string `json:"subject"`
	Issuer  string `json:"issuer"`
	// Thumbprint is the SHA-1 of the certificate, as Windows shows it.
	Thumbprint  string    `json:"thumbprint"`
	NotBefore   time.Time `json:"notBefore"`
	NotAfter    time.Time `json:"notAfter"`
	Timestamped bool      `json:"timestamped"`
}

// VersionFile names the file in the build directory that holds the builds'
// version: one line, as "git describe" prints it. The build writes it.
const VersionFile = "VERSION"

// Builds is the set of agent builds the server serves: the release's, in a
// directory read once at startup, with signed Windows builds in place of
// some of them (ADR-0049).
type Builds struct {
	root    *os.Root
	items   []Build
	version string

	mu sync.RWMutex
	// signed is served in place of the release's build of the same file
	// name; withheld release builds are not served at all, because only
	// signed builds are and there is none for them.
	signed   map[string]signedContent
	withheld map[string]bool
}

// signedContent is a signed build and its file. older says it was signed
// from another release build than the one served now.
type signedContent struct {
	build   Build
	content []byte
	older   bool
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
	if v, err := fs.ReadFile(root.FS(), VersionFile); err == nil {
		b.version = strings.TrimSpace(string(v))
		if !agentproto.ValidVersion(b.version) {
			_ = root.Close()
			return nil, fmt.Errorf("agent builds: %s holds %q, which is not a version", VersionFile, b.version)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		_ = root.Close()
		return nil, fmt.Errorf("agent builds: %w", err)
	}
	for _, e := range entries {
		goos, goarch, ok := agentproto.BuildFile(e.Name())
		if !ok || !e.Type().IsRegular() {
			continue
		}
		item, err := b.describe(e.Name())
		if err != nil {
			_ = root.Close()
			return nil, err
		}
		item.OS, item.Arch, item.Version = goos, goarch, b.version
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

// List returns the builds the server serves, by file name: a signed build
// in place of the release's, and none that is withheld.
func (b *Builds) List() []Build {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]Build, 0, len(b.items))
	for _, it := range b.items {
		if sc, ok := b.signed[it.File]; ok {
			out = append(out, sc.build)
		} else if !b.withheld[it.File] {
			out = append(out, it)
		}
	}
	return out
}

// Release returns the release's builds, by file name, whatever is served.
func (b *Builds) Release() []Build { return append([]Build{}, b.items...) }

// Find returns the build served with a file name.
func (b *Builds) Find(file string) (Build, bool) {
	for _, it := range b.List() {
		if it.File == file {
			return it, true
		}
	}
	return Build{}, false
}

// For returns the build served for a platform and architecture, as the
// agent reports them.
func (b *Builds) For(goos, goarch string) (Build, bool) {
	for _, it := range b.List() {
		if it.OS == goos && it.Arch == goarch {
			return it, true
		}
	}
	return Build{}, false
}

// Withheld says whether the release's build for a platform and architecture
// is not served, because only signed builds are and there is none for it.
func (b *Builds) Withheld(goos, goarch string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, it := range b.items {
		if it.OS == goos && it.Arch == goarch {
			return b.withheld[it.File]
		}
	}
	return false
}

// Waiting returns the release's version for a platform and architecture
// when only signed builds are handed out and none was signed from the
// release's build: the server serves an older signed build, or none.
func (b *Builds) Waiting(goos, goarch string) string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, it := range b.items {
		if it.OS != goos || it.Arch != goarch {
			continue
		}
		if sc, ok := b.signed[it.File]; (ok && sc.older) || b.withheld[it.File] {
			return nonEmpty(it.Version, "unknown")
		}
	}
	return ""
}

// Version is the builds' version from the VERSION file, or "".
func (b *Builds) Version() string { return b.version }

// Open opens a build served for reading. Only files List returned can be
// opened.
func (b *Builds) Open(file string) (io.ReadSeekCloser, Build, error) {
	b.mu.RLock()
	sc, signed := b.signed[file]
	b.mu.RUnlock()
	if signed {
		return nopCloser{bytes.NewReader(sc.content)}, sc.build, nil
	}
	it, ok := b.Find(file)
	if !ok {
		return nil, Build{}, fs.ErrNotExist
	}
	f, err := b.root.Open(file)
	return f, it, err
}

// OpenRelease opens the release's build with a file name, whatever is
// served: the file an operator signs.
func (b *Builds) OpenRelease(file string) (*os.File, Build, error) {
	i := slices.IndexFunc(b.items, func(it Build) bool { return it.File == file })
	if i < 0 {
		return nil, Build{}, fs.ErrNotExist
	}
	f, err := b.root.Open(file)
	return f, b.items[i], err
}

// readRelease reads the release's build with a file name.
func (b *Builds) readRelease(file string) ([]byte, error) {
	f, _, err := b.OpenRelease(file)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(f)
}

// serve sets the signed builds served in place of the release's, by file
// name, and the release builds withheld.
func (b *Builds) serve(signed map[string]signedContent, withheld map[string]bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.signed, b.withheld = signed, withheld
}

// nopCloser is a bytes.Reader with a Close that does nothing.
type nopCloser struct{ *bytes.Reader }

func (nopCloser) Close() error { return nil }

// ModTime is when the build was written.
func (b Build) ModTime() time.Time { return b.modTime }

// Checksums renders the SHA-256 sums of the builds served, in sha256sum's
// format.
func (b *Builds) Checksums() string {
	var sb strings.Builder
	for _, it := range b.List() {
		sb.WriteString(it.SHA256 + "  " + it.File + "\n")
	}
	return sb.String()
}
