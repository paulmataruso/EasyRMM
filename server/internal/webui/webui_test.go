package webui

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

const indexHTML = `<!doctype html><title>EasyRMM</title><div id="root"></div>`

func testFS() fstest.MapFS {
	return fstest.MapFS{
		"index.html":           {Data: []byte(indexHTML)},
		"favicon.svg":          {Data: []byte("<svg/>")},
		"assets/app-abc123.js": {Data: []byte("console.log(1)")},
		"assets/app-abc123.css": {
			Data: []byte("body{}"),
		},
		"assets/fonts/inter.woff2": {Data: []byte("font")},
	}
}

func get(t *testing.T, h http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

func TestClientRoutesFallBackToIndex(t *testing.T) {
	h := Handler(testFS())
	for _, p := range []string{"/", "/index.html", "/login", "/organizations/123/sites", "/devices/", "/../../etc/passwd"} {
		rec := get(t, h, http.MethodGet, p)
		if rec.Code != http.StatusOK || rec.Body.String() != indexHTML {
			t.Errorf("%s: %d %q", p, rec.Code, rec.Body.String())
		}
		if rec.Header().Get("Cache-Control") != "no-cache" || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
			t.Errorf("%s: headers %v", p, rec.Header())
		}
	}
}

func TestAssetsAreCachedImmutably(t *testing.T) {
	h := Handler(testFS())
	rec := get(t, h, http.MethodGet, "/assets/app-abc123.js")
	if rec.Code != http.StatusOK || rec.Body.String() != "console.log(1)" {
		t.Fatalf("asset: %d %q", rec.Code, rec.Body.String())
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=31536000, immutable" {
		t.Fatalf("asset cache control = %q", cc)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Fatalf("asset content type = %q", ct)
	}
	rec = get(t, h, http.MethodGet, "/assets/fonts/inter.woff2")
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" {
		t.Fatalf("nested asset: %d %v", rec.Code, rec.Header())
	}
}

func TestOtherFilesRevalidate(t *testing.T) {
	rec := get(t, Handler(testFS()), http.MethodGet, "/favicon.svg")
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("favicon: %d %v", rec.Code, rec.Header())
	}
}

func TestMissingAssetIs404(t *testing.T) {
	h := Handler(testFS())
	for _, p := range []string{"/assets/app-old.js", "/robots.txt", "/missing.png"} {
		if rec := get(t, h, http.MethodGet, p); rec.Code != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", p, rec.Code)
		}
	}
}

func TestDirectoryFallsBackToIndex(t *testing.T) {
	// A directory name is a client route, not a listing.
	rec := get(t, Handler(testFS()), http.MethodGet, "/assets")
	if rec.Code != http.StatusOK || rec.Body.String() != indexHTML {
		t.Fatalf("directory: %d %q", rec.Code, rec.Body.String())
	}
}

func TestMethodNotAllowed(t *testing.T) {
	h := Handler(testFS())
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		rec := get(t, h, m, "/login")
		if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "GET, HEAD" {
			t.Errorf("%s: %d allow=%q", m, rec.Code, rec.Header().Get("Allow"))
		}
	}
}

func TestHeadHasNoBody(t *testing.T) {
	rec := get(t, Handler(testFS()), http.MethodHead, "/dashboard")
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Fatalf("HEAD: %d body %q", rec.Code, rec.Body.String())
	}
}

func TestMissingIndexIs503(t *testing.T) {
	rec := get(t, Handler(fstest.MapFS{}), http.MethodGet, "/")
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "not included in this build") {
		t.Fatalf("missing index: %d %q", rec.Code, rec.Body.String())
	}
}

type brokenFS struct{ fstest.MapFS }

func (b brokenFS) Open(name string) (fs.File, error) {
	if name == "broken.js" {
		return nil, fs.ErrPermission
	}
	return b.MapFS.Open(name)
}

func (b brokenFS) Stat(name string) (fs.FileInfo, error) {
	if name == "broken.js" {
		return nil, fs.ErrPermission
	}
	return b.MapFS.Stat(name)
}

func TestFilesystemErrorIs500(t *testing.T) {
	rec := get(t, Handler(brokenFS{testFS()}), http.MethodGet, "/broken.js")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestFSEmbedded(t *testing.T) {
	files, err := FS("")
	if err != nil {
		t.Fatal(err)
	}
	// The embedded tree is the dist directory itself, not its parent.
	if _, err := fs.Stat(files, "dist"); err == nil {
		t.Fatal("embedded FS should be rooted at dist/")
	}
	if _, err := fs.Stat(files, ".gitkeep"); err != nil {
		t.Fatalf("embedded FS lacks dist contents: %v", err)
	}
}

func TestFSDirectory(t *testing.T) {
	dir := t.TempDir()
	if _, err := FS(dir); err == nil {
		t.Fatal("a directory without index.html should be rejected")
	}
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte(indexHTML), 0o600); err != nil {
		t.Fatal(err)
	}
	files, err := FS(dir)
	if err != nil {
		t.Fatal(err)
	}
	rec := get(t, Handler(files), http.MethodGet, "/some/route")
	if rec.Code != http.StatusOK || rec.Body.String() != indexHTML {
		t.Fatalf("dir FS: %d %q", rec.Code, rec.Body.String())
	}
}
