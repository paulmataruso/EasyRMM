package host

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Limits on what a bundle unpacks to: it holds the Compose files, the
// guides and the updater for two architectures.
const (
	maxUnpackedBytes = 1 << 30
	maxUnpackedFiles = 10000
)

// unpackBundle unpacks a verified deployment bundle, whose entries all lie
// under top/ (easyrmm-v1.2.3/), into parent/top. It unpacks into a new
// directory beside it and renames that into place, so that a bundle
// directory is either whole or absent. Only directories and regular files
// are unpacked, owned by root, with no more than mode 755.
func unpackBundle(archive, parent, top string) (string, error) {
	f, err := os.Open(archive) //nolint:gosec // the bundle the updater downloaded
	if err != nil {
		return "", err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", fmt.Errorf("the bundle is not gzip: %w", err)
	}
	defer gz.Close()
	tmp, err := os.MkdirTemp(parent, "."+top+".unpack-")
	if err != nil {
		return "", err
	}
	done := false
	defer func() {
		if !done {
			_ = os.RemoveAll(tmp)
		}
	}()
	tr := tar.NewReader(gz)
	var total int64
	for files := 0; ; files++ {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", fmt.Errorf("the bundle: %w", err)
		}
		if files >= maxUnpackedFiles {
			return "", fmt.Errorf("the bundle has more than %d entries", maxUnpackedFiles)
		}
		name := path.Clean(h.Name)
		if name != top && !strings.HasPrefix(name, top+"/") {
			return "", fmt.Errorf("the bundle has %q outside %s/", h.Name, top)
		}
		dst := filepath.Join(tmp, filepath.FromSlash(name))
		mode := h.FileInfo().Mode().Perm() & 0o755
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dst, 0o755); err != nil { //nolint:gosec // the deployment's files, which containers read
				return "", err
			}
			if err := os.Chmod(dst, mode|0o700); err != nil {
				return "", err
			}
		case tar.TypeReg:
			total += h.Size
			if total > maxUnpackedBytes {
				return "", fmt.Errorf("the bundle unpacks to more than %d bytes", maxUnpackedBytes)
			}
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil { //nolint:gosec // the deployment's files, which containers read
				return "", err
			}
			if err := writeEntry(dst, tr, h.Size, mode); err != nil {
				return "", err
			}
		default:
			return "", fmt.Errorf("the bundle has %q, which is neither a file nor a directory", h.Name)
		}
	}
	final := filepath.Join(parent, top)
	if err := os.Rename(filepath.Join(tmp, top), final); err != nil {
		return "", fmt.Errorf("the bundle: %w", err)
	}
	done = true
	return final, os.RemoveAll(tmp)
}

func writeEntry(dst string, r io.Reader, size int64, mode os.FileMode) error {
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode) //nolint:gosec // checked to be under the new directory
	if err != nil {
		return err
	}
	if _, err := io.CopyN(out, r, size); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Chmod(mode); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
