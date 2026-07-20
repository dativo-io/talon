package explanation

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestAllEmittedStageLiteralsKnown pins #360: the explanation stage set is
// CLOSED — every quoted `Stage: "..."` literal anywhere in production code
// must pass IsKnownStage, so a new emitter cannot introduce an unregistered
// stage that sorts into its own bucket and escapes stage-filtered consumers
// (same discipline as the evidence record-class registry).
func TestAllEmittedStageLiteralsKnown(t *testing.T) {
	root := filepath.Join("..", "..")
	stageLit := regexp.MustCompile(`Stage:\s*"([a-z_]+)"`)

	err := filepath.Walk(filepath.Join(root, "internal"), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range stageLit.FindAllStringSubmatch(string(raw), -1) {
			if !IsKnownStage(m[1]) {
				t.Errorf("%s emits unregistered explanation stage %q — register it in stages.go or use a canonical constant", path, m[1])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking source tree: %v", err)
	}
}
