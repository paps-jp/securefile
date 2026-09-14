package httpd

import (
	"io/fs"
	"net/http"
)

// reportFiles serves a directory of public documents (annual reports, financial
// statements) read-only at /report/. Directory listing is disabled, so only a
// known file URL resolves and a bare directory 404s — the same way the old site
// behaved, without exposing a browsable index of everything in the folder.
func (s *Server) reportFiles(dir string) http.Handler {
	fileServer := http.FileServer(noListDir{http.Dir(dir)})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// These are trusted, operator-published static documents served
		// same-origin. Drop the site's strict CSP so the browser's built-in
		// viewer renders a PDF inline, and allow ordinary caching.
		h.Del("Content-Security-Policy")
		h.Set("Cache-Control", "public, max-age=3600")
		h.Set("X-Content-Type-Options", "nosniff")
		// inline asks the browser to display the document (a PDF, an image) in
		// place rather than download it — these are meant to be read online. A
		// type the browser can't render (a zip) still falls back to a download.
		h.Set("Content-Disposition", "inline")
		fileServer.ServeHTTP(w, r)
	})
}

// noListDir wraps a filesystem so opening a directory fails. That turns both
// directory listing and index probing into a 404 while files still serve.
type noListDir struct{ fs http.FileSystem }

func (n noListDir) Open(name string) (http.File, error) {
	f, err := n.fs.Open(name)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if info.IsDir() {
		f.Close()
		return nil, fs.ErrNotExist
	}
	return f, nil
}
