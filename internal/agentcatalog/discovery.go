package agentcatalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/policy"
)

// AgentConfigFilename is the exact filename one AI use case's config must
// carry. Discovery matches it exactly — `foo.talon.yaml` is not an agent.
const AgentConfigFilename = "agent.talon.yaml"

// FileResult is the per-file outcome of one scan. This is the seam the fleet
// view (#270) consumes: "invalid config discovered" needs the cause per path.
type FileResult struct {
	Path  string
	Agent *CatalogAgent // nil when Err != nil
	Err   error         // read/schema/unknown-field/duplicate error for THIS file
}

// ScanResult is one complete pass over the agent-config source. Files, Issues
// and Digest are populated regardless of validity; Agents is authoritative
// only when the scan-level error is nil (fail closed: one invalid file or
// duplicate name rejects the whole scan).
type ScanResult struct {
	// Source names what was scanned (the directory or the single file).
	Source string
	// Files holds every agent.talon.yaml found, sorted by path.
	Files []FileResult
	// Agents is the loadable set, in Files order.
	Agents []CatalogAgent
	// Issues lists rejected files by path (never synthesized identities).
	Issues []FleetIssue
	// Digest is sha256 over the sorted (path, sha256(raw bytes)) pairs —
	// the generation identity and the reload change detector (#269). Invalid
	// files' bytes are included, so fixing a broken file changes the digest.
	Digest string
}

// LoadedAgents adapts the scanned set for gateway registry construction.
func (s *ScanResult) LoadedAgents() []gateway.LoadedAgent {
	out := make([]gateway.LoadedAgent, 0, len(s.Agents))
	for i := range s.Agents {
		out = append(out, s.Agents[i].LoadedAgent())
	}
	return out
}

// DiscoverAgents recursively walks dir; every file named exactly
// agent.talon.yaml is one AI use case. Fail closed: ANY invalid file or
// duplicate agent.name rejects the whole scan (non-nil error) while the
// per-file causes travel in the returned ScanResult regardless — the caller
// (startup: terminal; reload: keep last-known-good, #269) decides what a
// rejection means. Hidden directories (dot-prefixed) are skipped; symlinked
// directories are not followed (filepath.WalkDir semantics).
func DiscoverAgents(ctx context.Context, dir string) (*ScanResult, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return &ScanResult{Source: dir}, fmt.Errorf("agents_dir %s: %w", dir, err)
	}
	if !info.IsDir() {
		return &ScanResult{Source: dir}, fmt.Errorf("agents_dir %s is not a directory", dir)
	}

	var paths []string
	walkErr := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if d.IsDir() {
			if path != dir && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() == AgentConfigFilename {
			paths = append(paths, path)
		}
		return nil
	})
	if walkErr != nil {
		return &ScanResult{Source: dir}, fmt.Errorf("scanning agents_dir %s: %w", dir, walkErr)
	}
	sort.Strings(paths)

	result := scanFiles(ctx, dir, paths)
	return result, result.scanError()
}

// scanFiles loads every path through the strict gateway-agent pipeline and
// assembles the ScanResult (per-file outcomes, duplicate detection, digest).
// relBase anchors digest entries so the generation identity does not depend
// on where the tree is mounted.
func scanFiles(ctx context.Context, relBase string, paths []string) *ScanResult {
	result := &ScanResult{Source: relBase}
	digest := sha256.New()
	fmt.Fprintf(digest, "src\x00%d\n", len(paths))
	byName := make(map[string]string, len(paths)) // agent name → first path

	for _, path := range paths {
		entry := digestEntryName(relBase, path)
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			fmt.Fprintf(digest, "%s\x00!unreadable\n", entry)
			result.addFailure(path, IssueInvalidConfig, fmt.Errorf("reading agent config: %w", readErr))
			continue
		}
		sum := sha256.Sum256(raw)
		fmt.Fprintf(digest, "%s\x00%s\n", entry, hex.EncodeToString(sum[:]))

		agent, loadErr := loadCatalogAgent(ctx, path)
		if loadErr != nil {
			result.addFailure(path, IssueInvalidConfig, loadErr)
			continue
		}
		if prev, dup := byName[agent.Name]; dup {
			err := fmt.Errorf("duplicate agent name %q: defined in both %s and %s — agent names are unique per installation", agent.Name, prev, path)
			result.addFailure(path, IssueDuplicateName, err)
			continue
		}
		byName[agent.Name] = path
		result.Files = append(result.Files, FileResult{Path: path, Agent: agent})
		result.Agents = append(result.Agents, *agent)
	}

	result.Digest = hex.EncodeToString(digest.Sum(nil))
	return result
}

// loadCatalogAgent runs one file through the SAME strict pipeline gateway
// startup applies to the single default agent: full load + schema validation,
// then the unknown-key gate (a typo like `montly:` must fail loudly, #266
// review round 4 — every discovered agent is gateway-loadable, so all get
// the strict treatment).
func loadCatalogAgent(ctx context.Context, path string) (*CatalogAgent, error) {
	baseDir := filepath.Dir(path)
	pol, err := policy.LoadPolicy(ctx, filepath.Base(path), false, baseDir)
	if err != nil {
		return nil, err
	}
	if err := policy.ValidateNoUnknownFields(path); err != nil {
		return nil, err
	}
	return &CatalogAgent{
		Name:         pol.Agent.Name,
		TenantID:     pol.Agent.TenantID,
		Path:         path,
		PolicyDigest: pol.Hash,
		Enabled:      true, // #268 lands agent.enabled; until then every agent is on
		Policy:       pol,
	}, nil
}

// addFailure records a rejected file as both a FileResult and a FleetIssue.
// No agent identity is attached: a file that did not fully validate has no
// trustworthy name (last-known-good attribution is the reloader's job, #269).
func (s *ScanResult) addFailure(path, status string, err error) {
	s.Files = append(s.Files, FileResult{Path: path, Err: err})
	s.Issues = append(s.Issues, FleetIssue{Path: path, Status: status, Reason: err.Error()})
}

// scanError aggregates per-file failures into the scan-level rejection.
// Zero files found is NOT a scan error — callers enforce their own minimums
// (gateway mode requires ≥1 keyed agent).
func (s *ScanResult) scanError() error {
	if len(s.Issues) == 0 {
		return nil
	}
	return fmt.Errorf("agent config scan of %s rejected: %d of %d file(s) invalid — first: %s: %s (fail closed: an invalid set never activates; fix or remove the files)",
		s.Source, len(s.Issues), len(s.Files), s.Issues[0].Path, s.Issues[0].Reason)
}

// digestEntryName returns the path key used in the generation digest:
// relative to the scan base when possible, so the digest is stable across
// mounts of the same tree.
func digestEntryName(base, path string) string {
	if rel, err := filepath.Rel(base, path); err == nil && !strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(path)
}
