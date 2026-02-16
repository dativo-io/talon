// This file ensures core dependencies are available for upcoming prompts.
// It will be removed once the dependencies are actually imported in Prompt 2+.
package deps

import (
	_ "github.com/go-chi/chi/v5"
	_ "github.com/mattn/go-sqlite3"
	_ "github.com/open-policy-agent/opa"
	_ "github.com/robfig/cron/v3"
	_ "golang.org/x/crypto"
	_ "golang.org/x/time"
)
