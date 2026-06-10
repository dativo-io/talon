package gateway

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestParseTierLevel(t *testing.T) {
	tests := []struct {
		in      string
		want    TierLevel
		wantErr bool
	}{
		{in: "public", want: TierPublic},
		{in: "internal", want: TierInternal},
		{in: "confidential", want: TierConfidential},
		{in: "Confidential", want: TierConfidential}, // case-insensitive
		{in: "  internal  ", want: TierInternal},     // trimmed
		{in: "0", want: TierPublic},
		{in: "2", want: TierConfidential},
		{in: "restricted", wantErr: true},
		{in: "tier_2", wantErr: true},
		{in: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseTierLevel(tt.in)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "public, internal, confidential")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestTierLevel_String(t *testing.T) {
	assert.Equal(t, "public", TierPublic.String())
	assert.Equal(t, "internal", TierInternal.String())
	assert.Equal(t, "confidential", TierConfidential.String())
	assert.Equal(t, "7", TierLevel(7).String())
}

func TestTierLevel_UnmarshalYAML(t *testing.T) {
	var doc struct {
		Tier TierLevel `yaml:"tier"`
	}
	require.NoError(t, yaml.Unmarshal([]byte(`tier: confidential`), &doc))
	assert.Equal(t, TierConfidential, doc.Tier)

	require.NoError(t, yaml.Unmarshal([]byte(`tier: 1`), &doc))
	assert.Equal(t, TierInternal, doc.Tier)

	err := yaml.Unmarshal([]byte(`tier: restricted`), &doc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "public, internal, confidential")
}

func TestTierLevel_JSONRoundTrip(t *testing.T) {
	var doc struct {
		Tier TierLevel `json:"tier"`
	}
	require.NoError(t, json.Unmarshal([]byte(`{"tier":"confidential"}`), &doc))
	assert.Equal(t, TierConfidential, doc.Tier)

	require.NoError(t, json.Unmarshal([]byte(`{"tier":2}`), &doc))
	assert.Equal(t, TierConfidential, doc.Tier)

	// Marshals as a number: evidence and policy input stay numeric.
	out, err := json.Marshal(doc)
	require.NoError(t, err)
	assert.JSONEq(t, `{"tier":2}`, string(out))

	err = json.Unmarshal([]byte(`{"tier":"secret"}`), &doc)
	require.Error(t, err)
}
