// Package web embeds the console's static shell (#536). The shell is the
// pairing page and, once paired, a connection panel over /console/v1/system;
// the operator pages are owned by #539 to #544 and are not here. No script,
// style or code is inline, so the strict CSP of internal/console/access
// applies without exceptions; no credential is ever placed in a URL, in the
// DOM or in browser storage.
package web

import (
	"bytes"
	"embed"
	"io/fs"
	"net/http"
	"strings"
	"time"
)

//go:embed static/*
var static embed.FS

// Handler serves the embedded shell: "/" is index.html, "/static/<file>" the
// assets. Anything else is 404 (the shell is not a catch-all; deep links are
// #539's contract).
func Handler() http.Handler {
	sub, err := fs.Sub(static, "static")
	if err != nil {
		panic(err) // embedded tree is fixed at build time
	}
	index, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		panic(err)
	}
	files := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/" || r.URL.Path == "/index.html":
			// Served directly: http.FileServer would 301 /index.html to /.
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			http.ServeContent(w, r, "index.html", time.Time{}, bytes.NewReader(index))
		case strings.HasPrefix(r.URL.Path, "/static/") && !strings.Contains(r.URL.Path, ".."):
			r.URL.Path = strings.TrimPrefix(r.URL.Path, "/static")
			files.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}
