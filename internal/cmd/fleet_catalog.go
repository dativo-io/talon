package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/dativo-io/talon/internal/agentcatalog"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/llm"
	"github.com/dativo-io/talon/internal/policy"
)

// cliAgentScan scans the fleet source a CLI process runs against (#267): an
// explicit --policy file wins; otherwise agents_dir when configured;
// otherwise the default single policy file. File-mode paths get the same
// traversal safety and friendly not-found error the pre-fleet CLI applied.
func cliAgentScan(ctx context.Context, cfg *config.Config, explicitPolicyPath string) (*agentcatalog.ScanResult, error) {
	if explicitPolicyPath == "" && cfg.AgentsDir != "" {
		scan, err := agentcatalog.DiscoverAgents(ctx, cfg.AgentsDir)
		if err != nil {
			return nil, fmt.Errorf("discovering agents: %w", err)
		}
		if len(scan.Agents) == 0 {
			return nil, fmt.Errorf("no %s found under agents_dir %s", agentcatalog.AgentConfigFilename, cfg.AgentsDir)
		}
		return scan, nil
	}

	policyPath := explicitPolicyPath
	if policyPath == "" {
		policyPath = cfg.DefaultPolicy
	}
	safePath, err := resolveTrustedPolicyPath(policyPath)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(safePath); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("policy file not found: %s — create a project first with: talon init", safePath)
		}
		return nil, fmt.Errorf("policy file: %w", err)
	}
	scan, err := agentcatalog.Source{File: safePath}.Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading policy: %w", err)
	}
	return scan, nil
}

// resolveTrustedPolicyPath applies the CLI path contract: relative paths
// resolve under the working directory (traversal-guarded); operator-provided
// absolute paths are trusted so paths outside CWD work (e.g. Docker volumes).
func resolveTrustedPolicyPath(policyPath string) (string, error) {
	safePath, err := policy.ResolvePathUnderBase(".", policyPath)
	if err == nil {
		return safePath, nil
	}
	if filepath.IsAbs(filepath.Clean(policyPath)) {
		abs, absErr := filepath.Abs(filepath.Clean(policyPath))
		if absErr != nil {
			return "", fmt.Errorf("policy path: %w", absErr)
		}
		if _, err := policy.ResolvePathUnderBase(filepath.Dir(abs), abs); err != nil {
			return "", fmt.Errorf("policy path: %w", err)
		}
		return abs, nil
	}
	return "", fmt.Errorf("policy path: %w", err)
}

// resolveCatalogAgent picks a run's agent from the scanned set: an explicit
// name must exist; the ""/"default" sentinel resolves when exactly one agent
// is discovered and is ambiguous otherwise.
func resolveCatalogAgent(scan *agentcatalog.ScanResult, requested string) (*agentcatalog.CatalogAgent, error) {
	if requested != "" && requested != "default" {
		for i := range scan.Agents {
			if scan.Agents[i].Name == requested {
				return &scan.Agents[i], nil
			}
		}
		return nil, fmt.Errorf("unknown agent %q: discovered agents: %s", requested, scanAgentNames(scan))
	}
	switch len(scan.Agents) {
	case 1:
		return &scan.Agents[0], nil
	case 0:
		return nil, fmt.Errorf("no agents discovered (source %s)", scan.Source)
	default:
		return nil, fmt.Errorf("ambiguous agent: %d agents discovered (%s) — name one with --agent", len(scan.Agents), scanAgentNames(scan))
	}
}

func scanAgentNames(scan *agentcatalog.ScanResult) string {
	names := make([]string, 0, len(scan.Agents))
	for i := range scan.Agents {
		names = append(names, scan.Agents[i].Name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// cliPricingBaseDir decides where the pricing table resolves from (#267
// review): pricing is SHARED process infrastructure — in fleet mode it
// resolves from the operator/project root, NEVER the selected agent's
// directory (CLI and server must sign identical cost estimates). Explicit
// --policy and single-file mode keep the pre-fleet contract: pricing next to
// the policy file.
func cliPricingBaseDir(cfg *config.Config, explicitPolicyPath, agentPath string) string {
	if explicitPolicyPath == "" && cfg.AgentsDir != "" {
		return "."
	}
	return filepath.Dir(agentPath)
}

// buildCLICatalog compiles the scanned set into the ONE runtime catalog the
// CLI runner resolves against (no gateway registry — native execution only).
func buildCLICatalog(ctx context.Context, cfg *config.Config, scan *agentcatalog.ScanResult, providers map[string]llm.Provider) (*agentcatalog.RuntimeHolder, error) {
	bundles, err := agentcatalog.BuildRuntimeAgents(ctx, scan, agentcatalog.BundleDeps{Config: cfg, Providers: providers})
	if err != nil {
		return nil, fmt.Errorf("compiling agent runtime bundles: %w", err)
	}
	snap := agentcatalog.NewRuntimeSnapshot(scan, bundles, nil, time.Now().UTC())
	return agentcatalog.NewRuntimeHolder(snap), nil
}
