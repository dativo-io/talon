package classifier

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRecognizerFile(t *testing.T) {
	yaml := `
recognizers:
  - name: "Test Email"
    supported_entity: "EMAIL_ADDRESS"
    enabled: true
    patterns:
      - name: "basic email"
        regex: '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
        score: 0.85
    sensitivity: 1
    countries: ["EU"]
  - name: "Test Phone"
    supported_entity: "PHONE_NUMBER"
    patterns:
      - name: "intl phone"
        regex: '\+[1-9]\d{6,14}\b'
        score: 0.7
    sensitivity: 1
`
	rf, err := ParseRecognizerFile([]byte(yaml))
	require.NoError(t, err)
	require.Len(t, rf.Recognizers, 2)

	assert.Equal(t, "Test Email", rf.Recognizers[0].Name)
	assert.Equal(t, "EMAIL_ADDRESS", rf.Recognizers[0].SupportedEntity)
	assert.True(t, rf.Recognizers[0].isEnabled())
	assert.Len(t, rf.Recognizers[0].Patterns, 1)
	assert.Equal(t, 1, rf.Recognizers[0].Sensitivity)
	assert.Equal(t, []string{"EU"}, rf.Recognizers[0].Countries)

	assert.Equal(t, "Test Phone", rf.Recognizers[1].Name)
	assert.True(t, rf.Recognizers[1].isEnabled(), "nil Enabled should default to true")
}

func TestParseRecognizerFileInvalidYAML(t *testing.T) {
	_, err := ParseRecognizerFile([]byte(`{{{invalid`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing recognizer YAML")
}

func TestLoadRecognizerFileMissing(t *testing.T) {
	rf, err := LoadRecognizerFile("/nonexistent/file.yaml")
	require.NoError(t, err, "missing file should not return error")
	assert.Nil(t, rf, "missing file should return nil")
}

func TestLoadRecognizerFileFromDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom.yaml")
	yaml := `
recognizers:
  - name: "Custom Pattern"
    supported_entity: "EMPLOYEE_ID"
    patterns:
      - name: "emp id"
        regex: '\bEMP-\d{6}\b'
        score: 0.95
    sensitivity: 2
`
	require.NoError(t, os.WriteFile(path, []byte(yaml), 0o644))

	rf, err := LoadRecognizerFile(path)
	require.NoError(t, err)
	require.NotNil(t, rf)
	require.Len(t, rf.Recognizers, 1)
	assert.Equal(t, "Custom Pattern", rf.Recognizers[0].Name)
}

func TestMergeRecognizers(t *testing.T) {
	enabled := true
	disabled := false

	defaults := []*RecognizerConfig{
		{Name: "Email", SupportedEntity: "EMAIL_ADDRESS", Sensitivity: 1, Enabled: &enabled},
		{Name: "Phone", SupportedEntity: "PHONE_NUMBER", Sensitivity: 1, Enabled: &enabled},
	}

	// Global override: disable Phone, add custom
	global := []*RecognizerConfig{
		{Name: "Phone", SupportedEntity: "PHONE_NUMBER", Sensitivity: 1, Enabled: &disabled},
		{Name: "Custom ID", SupportedEntity: "EMPLOYEE_ID", Sensitivity: 2, Enabled: &enabled},
	}

	// Agent layer: add another custom
	agent := []*RecognizerConfig{
		{Name: "Agent Custom", SupportedEntity: "AGENT_ID", Sensitivity: 1, Enabled: &enabled},
	}

	merged := MergeRecognizers(defaults, global, agent)
	require.Len(t, merged, 4)

	// Email: from defaults, unchanged
	assert.Equal(t, "Email", merged[0].Name)
	assert.True(t, merged[0].isEnabled())

	// Phone: overridden by global to disabled
	assert.Equal(t, "Phone", merged[1].Name)
	assert.False(t, merged[1].isEnabled())

	// Custom ID: added by global
	assert.Equal(t, "Custom ID", merged[2].Name)

	// Agent Custom: added by agent
	assert.Equal(t, "Agent Custom", merged[3].Name)
}

func TestMergeRecognizersLastWins(t *testing.T) {
	defaults := []*RecognizerConfig{
		{Name: "IP Address", SupportedEntity: "IP_ADDRESS", Sensitivity: 1},
	}
	override := []*RecognizerConfig{
		{Name: "IP Address", SupportedEntity: "IP_ADDRESS", Sensitivity: 2},
	}

	merged := MergeRecognizers(defaults, override)
	require.Len(t, merged, 1)
	assert.Equal(t, 2, merged[0].Sensitivity, "later layer should override sensitivity")
}

func TestFilterByEntitiesWhitelist(t *testing.T) {
	recognizers := []RecognizerConfig{
		{Name: "Email", SupportedEntity: "EMAIL_ADDRESS"},
		{Name: "Phone", SupportedEntity: "PHONE_NUMBER"},
		{Name: "IBAN", SupportedEntity: "IBAN_CODE"},
	}

	filtered := FilterByEntities(recognizers, []string{"EMAIL_ADDRESS", "IBAN_CODE"}, nil)
	require.Len(t, filtered, 2)
	assert.Equal(t, "Email", filtered[0].Name)
	assert.Equal(t, "IBAN", filtered[1].Name)
}

func TestFilterByEntitiesBlacklist(t *testing.T) {
	recognizers := []RecognizerConfig{
		{Name: "Email", SupportedEntity: "EMAIL_ADDRESS"},
		{Name: "Phone", SupportedEntity: "PHONE_NUMBER"},
		{Name: "IBAN", SupportedEntity: "IBAN_CODE"},
	}

	filtered := FilterByEntities(recognizers, nil, []string{"PHONE_NUMBER"})
	require.Len(t, filtered, 2)
	assert.Equal(t, "Email", filtered[0].Name)
	assert.Equal(t, "IBAN", filtered[1].Name)
}

func TestFilterByEntitiesBothWhitelistAndBlacklist(t *testing.T) {
	recognizers := []RecognizerConfig{
		{Name: "Email", SupportedEntity: "EMAIL_ADDRESS"},
		{Name: "Phone", SupportedEntity: "PHONE_NUMBER"},
		{Name: "IBAN", SupportedEntity: "IBAN_CODE"},
	}

	filtered := FilterByEntities(recognizers, []string{"EMAIL_ADDRESS", "PHONE_NUMBER"}, []string{"PHONE_NUMBER"})
	require.Len(t, filtered, 1)
	assert.Equal(t, "Email", filtered[0].Name)
}

func TestFilterByEntitiesEmptyFilters(t *testing.T) {
	recognizers := []RecognizerConfig{
		{Name: "Email", SupportedEntity: "EMAIL_ADDRESS"},
		{Name: "Phone", SupportedEntity: "PHONE_NUMBER"},
	}

	filtered := FilterByEntities(recognizers, nil, nil)
	require.Len(t, filtered, 2, "no filters should return all")
}

func TestCompilePIIPatterns(t *testing.T) {
	enabled := true
	disabled := false

	recognizers := []RecognizerConfig{
		{
			Name:            "Email",
			SupportedEntity: "EMAIL_ADDRESS",
			Enabled:         &enabled,
			Patterns: []PatternConfig{
				{Name: "basic", Regex: `\b[a-z]+@[a-z]+\.[a-z]+\b`, Score: 0.8},
			},
			Sensitivity: 1,
			Countries:   []string{"EU"},
		},
		{
			Name:            "Disabled Pattern",
			SupportedEntity: "DISABLED_THING",
			Enabled:         &disabled,
			Patterns: []PatternConfig{
				{Name: "never compiled", Regex: `abc`, Score: 0.5},
			},
			Sensitivity: 1,
		},
	}

	compiled, err := CompilePIIPatterns(recognizers)
	require.NoError(t, err)
	require.Len(t, compiled, 1, "disabled recognizer should be skipped")

	assert.Equal(t, "Email", compiled[0].Name)
	assert.Equal(t, "email", compiled[0].Type)
	assert.Equal(t, 1, compiled[0].Sensitivity)
	assert.NotNil(t, compiled[0].Pattern)
}

func TestCompilePIIPatternsInvalidRegex(t *testing.T) {
	recognizers := []RecognizerConfig{
		{
			Name:            "Bad Regex",
			SupportedEntity: "BAD",
			Patterns: []PatternConfig{
				{Name: "invalid", Regex: `[invalid`, Score: 0.5},
			},
		},
	}

	_, err := CompilePIIPatterns(recognizers)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "compiling pattern")
}

func TestEntityToType(t *testing.T) {
	tests := []struct {
		entity   string
		wantType string
	}{
		{"EMAIL_ADDRESS", "email"},
		{"PHONE_NUMBER", "phone"},
		{"IBAN_CODE", "iban"},
		{"CREDIT_CARD", "credit_card"},
		{"EU_VAT_ID", "vat_id"},
		{"DE_SSN", "ssn"},
		{"UK_NINO", "ssn"},
		{"FR_SSN", "ssn"},
		{"IP_ADDRESS", "ip_address"},
		{"PASSPORT", "passport"},
		{"UNKNOWN_ENTITY", "unknown_entity"},
	}
	for _, tt := range tests {
		t.Run(tt.entity, func(t *testing.T) {
			assert.Equal(t, tt.wantType, entityToType(tt.entity))
		})
	}
}

func TestDefaultRecognizers(t *testing.T) {
	recs, err := DefaultRecognizers()
	require.NoError(t, err)
	assert.Greater(t, len(recs), 0, "should have default recognizers loaded from embedded YAML")

	entities := make(map[string]bool)
	for _, r := range recs {
		entities[r.SupportedEntity] = true
	}
	assert.True(t, entities["EMAIL_ADDRESS"], "should include email")
	assert.True(t, entities["PHONE_NUMBER"], "should include phone")
	assert.True(t, entities["IBAN_CODE"], "should include IBAN")
	assert.True(t, entities["CREDIT_CARD"], "should include credit card")
}
