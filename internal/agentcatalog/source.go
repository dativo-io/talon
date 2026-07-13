package agentcatalog

import (
	"context"
	"fmt"
)

// Source names the agent-config input for one catalog build: agents_dir mode
// when Dir is set, otherwise single-file mode. Exactly one of the two modes
// is active — when agents_dir is configured it is authoritative for fleet
// membership and the default single file does not define an agent (no mode
// merging, #267 decision).
type Source struct {
	Dir  string
	File string
}

// String names the source for logs, evidence and errors.
func (s Source) String() string {
	if s.Dir != "" {
		return "agents_dir " + s.Dir
	}
	return s.File
}

// Scan produces a uniform ScanResult for either mode. Single-file mode runs
// the SAME strict pipeline the directory scan applies per file, so the two
// modes cannot drift. A single file with no key binding still yields a valid
// one-agent catalog (native-only use); gateway invariants are the caller's.
func (s Source) Scan(ctx context.Context) (*ScanResult, error) {
	if s.Dir != "" {
		return DiscoverAgents(ctx, s.Dir)
	}
	if s.File == "" {
		return &ScanResult{}, fmt.Errorf("agent config source is empty: set agents_dir or a policy file")
	}
	result := scanFiles(ctx, s.File, []string{s.File})
	result.Source = s.File
	return result, result.scanError()
}
