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

// Handler serves the embedded single-page console: index.html for "/" and
// for exactly the application's routes (so a deep link or a refresh on a
// nested page works), "/static/<file>" for the built assets. It is not a
// catch-all: any other path, including unknown /console/* paths that reach
// it, is a plain 404, and it never shadows the API (the server routes
// /console/v1/* and /console/auth/* before this handler).
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
		case r.URL.Path == "/" || r.URL.Path == "/index.html" || IsAppRoute(r.URL.Path):
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

// appPages are the console's top-level routes; detailPages also take
// exactly one identifier segment (/use-cases/<name>, /sessions/<id>,
// /evidence/<id>). Kept in step with the frontend router.
var (
	appPages    = map[string]bool{"overview": true, "use-cases": true, "sessions": true, "costs": true, "configuration": true, "system": true}
	detailPages = map[string]bool{"use-cases": true, "sessions": true, "evidence": true}
)

// IsAppRoute reports whether path is one of the console's page routes.
func IsAppRoute(path string) bool {
	if !strings.HasPrefix(path, "/") || strings.Contains(path, "..") || strings.Contains(path, "//") {
		return false
	}
	parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(path, "/"), "/"), "/")
	switch len(parts) {
	case 1:
		return appPages[parts[0]]
	case 2:
		return detailPages[parts[0]] && parts[1] != ""
	default:
		return false
	}
}
