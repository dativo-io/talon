package internal

// deps_stub.go pins dependencies in go.mod before they're used in real code.
// Remove this file once each package is imported by actual production code.

import (
	_ "github.com/go-chi/chi/v5"
	_ "github.com/mattn/go-sqlite3"
	_ "github.com/robfig/cron/v3"
	_ "golang.org/x/crypto/nacl/secretbox"
	_ "golang.org/x/time/rate"
)
