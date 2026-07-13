// Package context loads shared enterprise context mounts for agent prompts.
package context

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/dativo-io/talon/internal/memory"
	"github.com/dativo-io/talon/internal/policy"
)

// Mount represents a single loaded context mount.
type Mount struct {
	Name            string
	Path            string
	Description     string
	Classification  int
	Content         string // CleanContent (private sections stripped)
	RawContent      string // Full content including private sections
	PrivateStripped int
}

// SharedContext holds all loaded context mounts for a policy.
type SharedContext struct {
	Mounts []Mount
}

// LoadSharedContext reads all configured shared mounts from the policy.
// baseDir anchors RELATIVE mount paths to the DECLARING agent's directory
// (#267 review): in a fleet, two agents declaring `path: ./context` must
// each read their own directory — never the process CWD, where one agent
// could consume another's context source. Absolute paths stay operator-
// trusted as before; an empty baseDir keeps the legacy CWD resolution for
// single-file callers.
func LoadSharedContext(pol *policy.Policy, baseDir string) (*SharedContext, error) {
	if pol.Context == nil || len(pol.Context.SharedMounts) == 0 {
		return &SharedContext{}, nil
	}

	sc := &SharedContext{}
	for _, mount := range pol.Context.SharedMounts {
		if mount.Path == "" {
			continue
		}

		clean := filepath.Clean(mount.Path)
		if strings.Contains(clean, "..") {
			return nil, fmt.Errorf("mount %q has suspicious path traversal: %s", mount.Name, mount.Path)
		}
		if !filepath.IsAbs(clean) && baseDir != "" {
			resolved, err := resolveUnderBase(baseDir, clean)
			if err != nil {
				return nil, fmt.Errorf("mount %q: %w", mount.Name, err)
			}
			clean = resolved
		}

		info, err := os.Stat(clean)
		if err != nil {
			return nil, fmt.Errorf("mount %q path %s: %w", mount.Name, clean, err)
		}

		var rawContent string
		if info.IsDir() {
			rawContent, err = readDirectory(clean)
		} else {
			rawContent, err = readFile(clean)
		}
		if err != nil {
			return nil, fmt.Errorf("reading mount %q: %w", mount.Name, err)
		}

		privacy := memory.StripPrivateTags(rawContent)

		configTier := parseTier(mount.Classification)
		effectiveTier := configTier
		if privacy.MaxClassifiedTier > effectiveTier {
			effectiveTier = privacy.MaxClassifiedTier
		}

		sc.Mounts = append(sc.Mounts, Mount{
			Name:            mount.Name,
			Path:            clean,
			Description:     mount.Description,
			Classification:  effectiveTier,
			Content:         privacy.CleanContent,
			RawContent:      rawContent,
			PrivateStripped: privacy.PrivateSectionsStripped,
		})
	}

	return sc, nil
}

// resolveUnderBase joins a relative mount path under the agent's directory
// and guarantees the result stays beneath it (traversal protection).
func resolveUnderBase(baseDir, rel string) (string, error) {
	absBase, err := filepath.Abs(filepath.Clean(baseDir))
	if err != nil {
		return "", fmt.Errorf("mount base directory: %w", err)
	}
	resolved := filepath.Clean(filepath.Join(absBase, rel))
	relCheck, err := filepath.Rel(absBase, resolved)
	if err != nil || relCheck == ".." || strings.HasPrefix(relCheck, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %s escapes the agent directory %s", rel, baseDir)
	}
	return resolved, nil
}

// FormatForPrompt formats all mounts for inclusion in the LLM prompt.
// Uses RawContent so the agent sees <private> content in-session.
func (sc *SharedContext) FormatForPrompt() string {
	if len(sc.Mounts) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("[SHARED ENTERPRISE CONTEXT]\n\n")
	for _, m := range sc.Mounts {
		fmt.Fprintf(&b, "--- %s ---\n", m.Name)
		if m.Description != "" {
			fmt.Fprintf(&b, "(%s)\n", m.Description)
		}
		b.WriteString(m.RawContent)
		b.WriteString("\n\n")
	}
	b.WriteString("[END SHARED CONTEXT]\n")
	return b.String()
}

// GetMaxTier returns the highest data tier across all loaded mounts.
func (sc *SharedContext) GetMaxTier() int {
	max := 0
	for _, m := range sc.Mounts {
		if m.Classification > max {
			max = m.Classification
		}
	}
	return max
}

// parseTier extracts the tier number from a classification string like "tier_1".
func parseTier(classification string) int {
	if strings.HasPrefix(classification, "tier_") {
		if n, err := strconv.Atoi(strings.TrimPrefix(classification, "tier_")); err == nil {
			return n
		}
	}
	return 0
}

// readDirectory walks a directory and reads all supported text files.
func readDirectory(dir string) (string, error) {
	var b strings.Builder
	supportedExts := map[string]bool{".md": true, ".txt": true, ".yaml": true, ".yml": true}

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !supportedExts[filepath.Ext(path)] {
			return nil
		}
		//nolint:gosec // G122: path from filepath.Walk; dir is trusted mount path from policy
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		relPath, _ := filepath.Rel(dir, path)
		fmt.Fprintf(&b, "# %s\n%s\n\n", relPath, string(content))
		return nil
	})
	return b.String(), err
}

// readFile reads a single file's content.
func readFile(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(content), nil
}
