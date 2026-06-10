package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDetectUnknownFields(t *testing.T) {
	tests := []struct {
		name        string
		yaml        string
		wantUnknown bool
	}{
		{
			name: "all known keys",
			yaml: `
agent:
  name: test-agent
  version: 1.0.0
policies:
  cost_limits:
    daily: 5.0
compliance:
  human_oversight: on-demand
  plan_review:
    require_for_tools: true
    volume_threshold: 50
`,
			wantUnknown: false,
		},
		{
			name: "typo in key",
			yaml: `
agent:
  name: test-agent
  version: 1.0.0
policies:
  cost_limitz:
    daily: 5.0
`,
			wantUnknown: true,
		},
		{
			name: "section at wrong nesting level",
			yaml: `
agent:
  name: test-agent
  version: 1.0.0
policies:
  plan_review:
    volume_threshold: 50
`,
			wantUnknown: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := detectUnknownFields([]byte(tt.yaml))
			if tt.wantUnknown {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
