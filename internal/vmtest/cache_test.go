package vmtest

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
)

var imageBytes = []byte(strings.Repeat("not really a qcow2 image\n", 1000))

func sha256Digest(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// imageServer serves the image at /good, other bytes at /bad and nothing
// elsewhere, and counts requests.
func imageServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		switch r.URL.Path {
		case "/good":
			_, _ = w.Write(imageBytes)
		case "/bad":
			_, _ = w.Write([]byte("tampered"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

func collect(lines *[]string) func(string, ...any) {
	return func(format string, args ...any) { *lines = append(*lines, fmt.Sprintf(format, args...)) }
}

func TestFetchDownloadsVerifiesAndReuses(t *testing.T) {
	srv, requests := imageServer(t)
	dir := t.TempDir()
	img := Image{Name: "test-1", URLs: []string{srv.URL + "/missing", srv.URL + "/bad", srv.URL + "/good"}, Digest: sha256Digest(imageBytes)}
	var log []string
	path, err := fetchOnce(t.Context(), dir, img, collect(&log))
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(dir, img.file()) {
		t.Errorf("path %s", path)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != string(imageBytes) {
		t.Errorf("cached file: %v", err)
	}
	if joined := strings.Join(log, "\n"); !strings.Contains(joined, "404") || !strings.Contains(joined, "pinned") {
		t.Errorf("the failed attempts are not logged:\n%s", joined)
	}
	assertNoPartials(t, dir)

	// A cached image is checked and used without the network.
	srv.Close()
	before := requests.Load()
	if again, err := fetchOnce(t.Context(), dir, img, t.Logf); err != nil || again != path {
		t.Errorf("from the cache: %s, %v", again, err)
	}
	if requests.Load() != before {
		t.Error("the cached image was downloaded again")
	}
}

func TestFetchReplacesATamperedCache(t *testing.T) {
	srv, _ := imageServer(t)
	dir := t.TempDir()
	img := Image{Name: "test-1", URLs: []string{srv.URL + "/good"}, Digest: sha256Digest(imageBytes)}
	if err := os.WriteFile(filepath.Join(dir, img.file()), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	var log []string
	path, err := fetchOnce(t.Context(), dir, img, collect(&log))
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != string(imageBytes) {
		t.Error("the tampered image was kept")
	}
	if !strings.Contains(strings.Join(log, "\n"), "not the pinned one") {
		t.Errorf("log %q", log)
	}
}

func TestFetchFailsWithoutAMatchingDownload(t *testing.T) {
	srv, _ := imageServer(t)
	dir := t.TempDir()
	img := Image{Name: "test-1", URLs: []string{srv.URL + "/bad", srv.URL + "/missing"}, Digest: sha256Digest(imageBytes)}
	_, err := fetchOnce(t.Context(), dir, img, t.Logf)
	if err == nil || !strings.Contains(err.Error(), "pinned") || !strings.Contains(err.Error(), "404") {
		t.Errorf("got %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, img.file())); err == nil {
		t.Error("an unverified image is in the cache")
	}
	assertNoPartials(t, dir)
}

func TestFetchSHA512AndOncePerProcess(t *testing.T) {
	srv, requests := imageServer(t)
	dir := t.TempDir()
	sum := sha512.Sum512(imageBytes)
	img := Image{Name: "test-512", URLs: []string{srv.URL + "/good"}, Digest: "sha512:" + hex.EncodeToString(sum[:])}
	first, err := fetch(t.Context(), dir, img, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	second, err := fetch(t.Context(), dir, img, t.Logf)
	if err != nil || second != first || requests.Load() != 1 {
		t.Errorf("second fetch: %s, %v, %d requests", second, err, requests.Load())
	}
}

func TestDigests(t *testing.T) {
	if _, _, err := newHash("md5:abc"); err == nil {
		t.Error("md5 accepted")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := os.WriteFile(path, imageBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verify(path, sha256Digest(imageBytes)); err != nil {
		t.Error(err)
	}
	if err := verify(path, sha256Digest([]byte("other"))); err == nil {
		t.Error("a wrong digest verified")
	}
	if err := verify(filepath.Join(dir, "missing"), sha256Digest(imageBytes)); err == nil {
		t.Error("a missing file verified")
	}
}

func TestProgress(t *testing.T) {
	var log []string
	known := &progressWriter{total: 3 << 20, logf: collect(&log)}
	unknown := &progressWriter{total: -1, logf: collect(&log)}
	for _, p := range []*progressWriter{known, unknown} {
		if n, err := p.Write(make([]byte, 2<<20)); n != 2<<20 || err != nil {
			t.Errorf("write: %d, %v", n, err)
		}
	}
	if want := []string{"  2 of 3 MB", "  2 MB"}; !slices.Equal(log, want) {
		t.Errorf("log %q, want %q", log, want)
	}
}

func TestCacheDir(t *testing.T) {
	t.Setenv(CacheEnv, "")
	if cacheDir() != "/var/tmp/easyrmm-vmtest" {
		t.Errorf("default %s", cacheDir())
	}
	t.Setenv(CacheEnv, "/srv/cache")
	if cacheDir() != "/srv/cache" {
		t.Errorf("from %s: %s", CacheEnv, cacheDir())
	}
}

func assertNoPartials(t *testing.T, dir string) {
	t.Helper()
	partials, _ := filepath.Glob(filepath.Join(dir, "*.partial"))
	if len(partials) > 0 {
		t.Errorf("partial downloads left: %v", partials)
	}
}
