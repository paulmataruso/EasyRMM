// Package webui serves the single-page web interface.
//
// The production build of web/ is copied into dist/ before the server is
// compiled (see the Makefile and Dockerfile), and embedded in the binary.
package webui

import (
	"embed"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path"
	"strings"
)

//go:embed all:dist
var embedded embed.FS

// FS returns the UI files: dir when set (development), otherwise the
// embedded build.
func FS(dir string) (fs.FS, error) {
	if dir != "" {
		if _, err := os.Stat(path.Join(dir, "index.html")); err != nil {
			return nil, err
		}
		return os.DirFS(dir), nil
	}
	return fs.Sub(embedded, "dist")
}

// Handler serves static assets and falls back to index.html for client-side
// routes. Hashed assets under /assets/ are cached forever; everything else
// is revalidated so new releases take effect immediately.
func Handler(files fs.FS) http.Handler {
	index, indexErr := fs.ReadFile(files, "index.html")
	fileServer := http.FileServerFS(files)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if indexErr != nil {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("The web interface is not included in this build. Build it with `make web` or use the release image.\n"))
			return
		}
		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if name != "" && name != "index.html" {
			if st, err := fs.Stat(files, name); err == nil && !st.IsDir() {
				if strings.HasPrefix(name, "assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				} else {
					w.Header().Set("Cache-Control", "no-cache")
				}
				fileServer.ServeHTTP(w, r)
				return
			} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			// Missing files that look like assets are real 404s, not routes.
			if path.Ext(name) != "" {
				http.NotFound(w, r)
				return
			}
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write(index)
		}
	})
}
