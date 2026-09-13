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
		// script-src and style-src are spelled out rather than left to fall
		// back to default-src. The fallback is what made an earlier version of
		// this policy look correct while it silently blocked the console's own
		// inline script: the page rendered and nothing worked. There is no
		// 'unsafe-inline' here because the console needs none.
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'")
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
