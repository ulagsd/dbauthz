package server

import (
	"embed"
	"io/fs"
	"net/http"
	"os"
)

//go:embed web
var webFS embed.FS

// consoleHandler serves the console from the binary.
//
// Embedding is what keeps the deployment story to one image and one process:
// no nginx sidecar, no separate origin, and therefore no CORS to get wrong.
func consoleHandler() http.Handler {
	files := http.FileServer(http.FS(consoleFS()))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The console reaches a privileged database connection, so it should
		// not be framed by another site or have its type guessed.
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "+
				"connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
		files.ServeHTTP(w, r)
	})
}

// consoleFS returns the embedded console, or a directory on disk when
// DBIAM_WEB_DIR is set. The override exists so the console can be edited
// against a running stack without a rebuild; it is a development convenience
// and reads whatever that directory contains, so it stays off by default.
func consoleFS() fs.FS {
	if dir := os.Getenv("DBIAM_WEB_DIR"); dir != "" {
		return os.DirFS(dir)
	}
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		panic("server: embedded console is missing: " + err.Error())
	}
	return sub
}
