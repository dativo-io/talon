package agentcatalog

import (
	"context"
	"errors"
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
		return &ScanResult{}, errEmptySource
	}
	result := scanFiles(ctx, s.File, []string{s.File})
	result.Source = s.File
	return result, result.scanError()
}

// Digest returns the digest Scan would report for the files as they are
// now (ScanResult.Digest), computed from their raw bytes alone: the same
// walk, nothing parsed or validated (#575). An error means the digest could
// not be computed (the source is missing, not a directory, or the walk
// failed); an unreadable file is not an error, it is part of the digest.
func (s Source) Digest(ctx context.Context) (string, error) {
	if s.Dir != "" {
		paths, err := agentConfigPaths(ctx, s.Dir)
		if err != nil {
			return "", err
		}
		return digestFiles(ctx, s.Dir, paths)
	}
	if s.File == "" {
		return "", errEmptySource
	}
	return digestFiles(ctx, s.File, []string{s.File})
}

var errEmptySource = errors.New("agent config source is empty: set agents_dir or a policy file")
