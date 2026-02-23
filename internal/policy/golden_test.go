package policy

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Golden test pattern: load input from testdata/golden/, evaluate policy, compare to expected output.
// Add new golden tests by adding input/expected file pairs to testdata/golden/.

func TestGolden_PolicyDecisions(t *testing.T) {
	ctx := context.Background()
	pol := goldenTestPolicy()
	engine, err := NewEngine(ctx, pol)
	require.NoError(t, err)

	goldenDir := filepath.Join("testdata", "golden")
	entries, err := os.ReadDir(goldenDir)
	if err != nil {
		t.Skipf("no golden test data at %s: %v", goldenDir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".input.json") {
			continue
		}
		testName := strings.TrimSuffix(entry.Name(), ".input.json")
		t.Run(testName, func(t *testing.T) {
			inputPath := filepath.Join(goldenDir, entry.Name())
			expectedPath := filepath.Join(goldenDir, testName+".expected.json")

			inputData, err := os.ReadFile(inputPath)
			require.NoError(t, err)
			expectedData, err := os.ReadFile(expectedPath)
			require.NoError(t, err)

			var input map[string]interface{}
			require.NoError(t, json.Unmarshal(inputData, &input))

			result, err := engine.Evaluate(ctx, input)
			require.NoError(t, err)

			var expected map[string]interface{}
			require.NoError(t, json.Unmarshal(expectedData, &expected))

			assert.Equal(t, expected["allowed"], result.Allowed, "allowed")
			if a, ok := expected["action"].(string); ok {
				assert.Equal(t, a, result.Action, "action")
			}
			if reasons, ok := expected["reasons"].([]interface{}); ok && len(reasons) > 0 {
				assert.Equal(t, len(reasons), len(result.Reasons), "reasons length")
			}
			if reason, ok := expected["reason"].(string); ok && reason != "" {
				assert.NotEmpty(t, result.Reasons, "expected single reason")
				assert.Contains(t, strings.Join(result.Reasons, " "), reason, "reason substring")
			}
		})
	}
}

func goldenTestPolicy() *Policy {
	pol := &Policy{
		Agent: AgentConfig{
			Name:    "golden-agent",
			Version: "1.0.0",
		},
		Policies: PoliciesConfig{
			CostLimits: &CostLimitsConfig{
				PerRequest: 1.0,
				Daily:      10.0,
				Monthly:    100.0,
			},
			RateLimits: &RateLimitsConfig{
				RequestsPerMinute:    60,
				ConcurrentExecutions: 2,
			},
			TimeRestrictions: &TimeRestrictionsConfig{
				Enabled:  false,
				Weekends: true,
			},
		},
	}
	pol.ComputeHash([]byte("golden"))
	return pol
}
