package agent

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/policy"
)

// failingFacade is a scanner engine whose every operation fails, simulating an
// unreachable external adapter.
type failingFacade struct{}

var errEngineDown = errors.New("external PII scanner unavailable: engine down")

func (f *failingFacade) Analyze(context.Context, string) (*classifier.Classification, error) {
	return nil, errEngineDown
}
func (f *failingFacade) Detector() string { return "failing-engine" }
func (f *failingFacade) RedactText(context.Context, string) (string, error) {
	return "", errEngineDown
}
func (f *failingFacade) VerifyEgress(context.Context, string) error { return errEngineDown }

var _ classifier.Facade = (*failingFacade)(nil)

func TestToolArgumentPII_ScannerFailureBlocksFailClosed(t *testing.T) {
	pol := &policy.Policy{
		ToolPolicies: map[string]policy.ToolPIIPolicy{
			"_default": {ArgumentDefault: policy.PIIActionRedact},
		},
	}
	args, _ := json.Marshal(map[string]interface{}{"comment": "some text"})

	result := applyToolArgumentPII(context.Background(), &failingFacade{}, "any_tool", args, pol)

	require.True(t, result.Blocked, "unscannable tool arguments must block fail-closed")
	assert.Contains(t, result.BlockReason, "scanner unavailable")
	require.NotEmpty(t, result.Findings)
	assert.Equal(t, []string{"scanner_unavailable"}, result.Findings[0].PIITypes)
}

func TestToolResultPII_ScannerFailureBlocksFailClosed(t *testing.T) {
	pol := &policy.Policy{
		ToolPolicies: map[string]policy.ToolPIIPolicy{
			"_default": {Result: policy.PIIActionRedact},
		},
	}

	content, findings := applyToolResultPII(context.Background(), &failingFacade{}, "any_tool", `{"data":"value"}`, pol)

	assert.Contains(t, content, "scanner unavailable", "tool result must be replaced, not passed through")
	assert.NotContains(t, content, `"data":"value"`, "original result must not egress")
	require.NotEmpty(t, findings)
	assert.Equal(t, []string{"scanner_unavailable"}, findings[0].PIITypes)
}

func TestRedactGuard_ScannerFailureFailsClosed(t *testing.T) {
	guard := classifier.NewRedactGuard(&failingFacade{})
	err := guard.Verify(context.Background(), "any redacted text")
	require.Error(t, err, "an egress that cannot be verified must not proceed")
	assert.Contains(t, err.Error(), "fail-closed")
}
