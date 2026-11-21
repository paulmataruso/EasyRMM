package vmtest

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// CacheEnv names the directory for downloaded images and running machines'
// disks. Keep it off a small tmpfs: images are up to 2 GB each.
const CacheEnv = "EASYRMM_VM_CACHE"

const defaultCache = "/var/tmp/easyrmm-vmtest"

func cacheDir() string {
	if dir := os.Getenv(CacheEnv); dir != "" {
		return dir
	}
	return defaultCache
}

// file is the image's name in the cache; a new pin gets a new file.
func (img Image) file() string {
	_, sum, _ := strings.Cut(img.Digest, ":")
	return fmt.Sprintf("%s-%.16s.qcow2", img.Name, sum)
}

func newHash(digest string) (hash.Hash, string, error) {
	algo, sum, _ := strings.Cut(digest, ":")
	switch algo {
	case "sha256":
		return sha256.New(), sum, nil
	case "sha512":
		return sha512.New(), sum, nil
	}
	return nil, "", fmt.Errorf("digest %q: not sha256 or sha512", digest)
}

// prepared images, verified once per test process.
var (
	preparedMu sync.Mutex
	prepared   = map[string]*preparation{}
)

type preparation struct {
	once sync.Once
	path string
	err  error
}

// fetch returns the path of the image in dir, downloading it when it is
// missing and checking its digest in either case: a cache restored in CI is
// checked like a download. logf reports progress.
func fetch(ctx context.Context, dir string, img Image, logf func(string, ...any)) (string, error) {
	key := dir + "\x00" + img.Name
	preparedMu.Lock()
	p := prepared[key]
	if p == nil {
		p = &preparation{}
		prepared[key] = p
	}
	preparedMu.Unlock()
	p.once.Do(func() { p.path, p.err = fetchOnce(ctx, dir, img, logf) })
	return p.path, p.err
}

func fetchOnce(ctx context.Context, dir string, img Image, logf func(string, ...any)) (string, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	path := filepath.Join(dir, img.file())
	if _, err := os.Stat(path); err == nil {
		err := verify(path, img.Digest)
		if err == nil {
			return path, nil
		}
		logf("%s: cached image is not the pinned one (%v); downloading it again", img.Name, err)
		if err := os.Remove(path); err != nil {
			return "", err
		}
	}
	var errs []error
	for _, url := range img.URLs {
		err := download(ctx, url, path, img.Digest, logf)
		if err == nil {
			return path, nil
		}
		errs = append(errs, err)
		logf("%s: %v", img.Name, err)
	}
	return "", fmt.Errorf("downloading %s: %w", img.Name, errors.Join(errs...))
}

func verify(path, digest string) error {
	h, want, err := newHash(digest)
	if err != nil {
		return err
	}
	f, err := os.Open(path) //nolint:gosec // a file in the harness's cache
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return fmt.Errorf("digest %s, pinned %s", got, want)
	}
	return nil
}

// downloadTimeout bounds each attempt, so that a stalled server leaves time
// for the next URL.
const downloadTimeout = 20 * time.Minute

// download fetches url to path, through a temporary file that becomes path
// only when its digest matches.
func download(ctx context.Context, url, path, digest string, logf func(string, ...any)) (err error) {
	h, want, err := newHash(digest)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.partial")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	start := time.Now()
	if resp.ContentLength >= 0 {
		logf("downloading %s (%d MB)", url, resp.ContentLength>>20)
	} else {
		logf("downloading %s", url)
	}
	progress := &progressWriter{total: resp.ContentLength, every: 30 * time.Second, last: start, logf: logf}
	if _, err := io.Copy(io.MultiWriter(tmp, h, progress), resp.Body); err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return fmt.Errorf("GET %s: digest %s, pinned %s", url, got, want)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	logf("downloaded and verified %s in %s", filepath.Base(path), time.Since(start).Round(time.Second))
	return nil
}

type progressWriter struct {
	n, total int64
	every    time.Duration
	last     time.Time
	logf     func(string, ...any)
}

func (p *progressWriter) Write(b []byte) (int, error) {
	p.n += int64(len(b))
	if now := time.Now(); now.Sub(p.last) >= p.every {
		p.last = now
		if p.total >= 0 {
			p.logf("  %d of %d MB", p.n>>20, p.total>>20)
		} else {
			p.logf("  %d MB", p.n>>20)
		}
	}
	return len(b), nil
}
