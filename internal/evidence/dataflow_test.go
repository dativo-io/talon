package evidence

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/classifier"
)

func TestCanonicalizeEntityValue(t *testing.T) {
	tests := []struct {
		name       string
		entityType string
		input      string
		want       string
	}{
		{"iban_spaces_stripped", "iban", "DE89 3704 0044 0532 0130 00", "DE89370400440532013000"},
		{"iban_lowercase_uppercased", "iban", "de89370400440532013000", "DE89370400440532013000"},
		{"credit_card_hyphens_stripped", "credit_card", "4111-1111-1111-1111", "4111111111111111"},
		{"email_lowercased", "email", " John.Doe@Example.COM ", "john.doe@example.com"},
		{"phone_formatting_stripped", "phone", "+49 (170) 123-45.67", "+491701234567"},
		{"default_trimmed_only", "name", "  Anna Schmidt  ", "Anna Schmidt"},
		{"nfc_normalization", "name", "Mu\u0308ller", "M\u00fcller"}, // decomposed u+umlaut -> precomposed ü
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, CanonicalizeEntityValue(tt.entityType, tt.input))
		})
	}
}

func TestFlowDigest(t *testing.T) {
	const tenant, corr = "acme", "corr_1"

	t.Run("deterministic", func(t *testing.T) {
		a := FlowDigest(tenant, corr, "email", "john@example.com")
		b := FlowDigest(tenant, corr, "email", "john@example.com")
		assert.Equal(t, a, b)
		assert.Len(t, a, 16)
		assert.Equal(t, strings.ToLower(a), a, "digest must be lowercase hex")
	})

	t.Run("canonicalization_equates_formats", func(t *testing.T) {
		spaced := FlowDigest(tenant, corr, "iban", "DE89 3704 0044 0532 0130 00")
		compact := FlowDigest(tenant, corr, "iban", "DE89370400440532013000")
		assert.Equal(t, spaced, compact, "spaced and compact IBAN must produce the same digest")

		upper := FlowDigest(tenant, corr, "email", "John@Example.com")
		lower := FlowDigest(tenant, corr, "email", "john@example.com")
		assert.Equal(t, upper, lower, "email digests must be case-insensitive")
	})

	t.Run("entity_type_is_part_of_digest", func(t *testing.T) {
		asEmail := FlowDigest(tenant, corr, "email", "same-value")
		asName := FlowDigest(tenant, corr, "name", "same-value")
		assert.NotEqual(t, asEmail, asName)
	})

	t.Run("salt_prevents_cross_request_linkage", func(t *testing.T) {
		r1 := FlowDigest(tenant, "corr_1", "email", "john@example.com")
		r2 := FlowDigest(tenant, "corr_2", "email", "john@example.com")
		assert.NotEqual(t, r1, r2, "different correlation IDs must produce different digests")

		t1 := FlowDigest("tenant-a", corr, "email", "john@example.com")
		t2 := FlowDigest("tenant-b", corr, "email", "john@example.com")
		assert.NotEqual(t, t1, t2, "different tenants must produce different digests")
	})

	t.Run("never_contains_raw_value", func(t *testing.T) {
		d := FlowDigest(tenant, corr, "email", "john@example.com")
		assert.NotContains(t, d, "john")
		assert.NotContains(t, d, "@")
	})
}

func TestNewDataFlowItem(t *testing.T) {
	entities := []classifier.PIIEntity{
		{Type: "iban", Value: "DE89370400440532013000", Position: 10, Sensitivity: 3},
		{Type: "email", Value: "b@example.com", Position: 40, Sensitivity: 1},
		{Type: "email", Value: "a@example.com", Position: 60, Sensitivity: 1},
		{Type: "email", Value: "a@example.com", Position: 60, Sensitivity: 1}, // duplicate value
	}
	dest := FlowDestination{Kind: FlowDestLLMProvider, Name: "openai", Model: "gpt-4o-mini", Region: "US"}
	item := NewDataFlowItem("acme", "corr_1", FlowSourcePrompt, "", 2, entities, FlowDispositionForwarded, dest)

	assert.Equal(t, FlowSourcePrompt, item.Source)
	assert.Equal(t, 2, item.Tier)
	assert.Equal(t, []string{"email", "iban"}, item.EntityTypes, "entity types must be deduped and sorted")
	assert.Equal(t, 4, item.EntityCount)
	assert.Len(t, item.ValueDigests, 3, "duplicate values must collapse to one digest")
	assert.True(t, sortedStrings(item.ValueDigests), "digests must be sorted for deterministic canonical JSON")
	require.NotEmpty(t, item.EntityAttributions)
	for _, attr := range item.EntityAttributions {
		assert.NotEmpty(t, attr.Type)
		assert.Equal(t, "messages[].content", attr.FieldPath, "default field path should be inferred for prompt source")
		require.NotNil(t, attr.Start)
		require.NotNil(t, attr.End)
		assert.GreaterOrEqual(t, *attr.End, *attr.Start)
	}
	assert.Equal(t, dest, item.Destination)

	for _, d := range item.ValueDigests {
		assert.NotContains(t, d, "example.com")
		assert.NotContains(t, d, "DE89")
	}
}

func TestNewDataFlowItem_UsesProvidedFieldPath(t *testing.T) {
	entities := []classifier.PIIEntity{
		{Type: "email", Value: "john@example.com", Position: 3, FieldPath: "choices[0].message.content"},
	}
	item := NewDataFlowItem("acme", "corr_1", FlowSourceResponse, "", 1, entities, FlowDispositionRedacted,
		FlowDestination{Kind: FlowDestClient, Name: "caller"})
	require.Len(t, item.EntityAttributions, 1)
	assert.Equal(t, "choices[0].message.content", item.EntityAttributions[0].FieldPath)
}

func TestNewDataFlowItemFromTypes(t *testing.T) {
	item := NewDataFlowItemFromTypes(FlowSourceAttachment, "report.pdf", 1,
		[]string{"iban", "email", "email"}, FlowDispositionBlocked,
		FlowDestination{Kind: FlowDestLLMProvider, Name: "openai"})
	assert.Equal(t, "report.pdf", item.SourceDetail)
	assert.Equal(t, []string{"email", "iban"}, item.EntityTypes)
	assert.Equal(t, 2, item.EntityCount)
	assert.Empty(t, item.ValueDigests, "type-only items must not carry digests")
	assert.Equal(t, FlowDispositionBlocked, item.Disposition)
}

// fakeAnalyzer simulates a third-party engine (e.g. a Presidio adapter): it
// implements classifier.Analyzer and produces a plain Classification. The
// data-flow pipeline must consume it identically to the built-in scanner.
type fakeAnalyzer struct{}

func (fakeAnalyzer) Analyze(_ context.Context, text string) (*classifier.Classification, error) {
	idx := strings.Index(text, "john@example.com")
	if idx < 0 {
		return &classifier.Classification{Tier: 0}, nil
	}
	return &classifier.Classification{
		Tier:   1,
		HasPII: true,
		Entities: []classifier.PIIEntity{
			{Type: "email", Value: "john@example.com", Position: idx, Confidence: 0.99, Sensitivity: 1},
		},
	}, nil
}

func (fakeAnalyzer) Detector() string { return "fake-presidio" }

func TestPluggableAnalyzerProducesEquivalentFlowItems(t *testing.T) {
	var a classifier.Analyzer = fakeAnalyzer{}
	text := "contact john@example.com today"
	cls, err := a.Analyze(context.Background(), text)
	require.NoError(t, err)
	require.True(t, cls.HasPII)

	merged := classifier.MergeEntitySpans(text, cls.Entities)
	item := NewDataFlowItem("acme", "corr_x", FlowSourcePrompt, "", cls.Tier, merged,
		FlowDispositionForwarded, FlowDestination{Kind: FlowDestLLMProvider, Name: "openai"})

	assert.Equal(t, []string{"email"}, item.EntityTypes)
	require.Len(t, item.ValueDigests, 1)
	// A different engine detecting the same canonical value yields the same digest.
	assert.Equal(t, FlowDigest("acme", "corr_x", "email", "John@Example.com"), item.ValueDigests[0])
	assert.Equal(t, "fake-presidio", a.Detector())
}

func TestDataFlowJSONRoundTrip(t *testing.T) {
	df := &DataFlow{
		Detector: "talon-regex",
		Items: []DataFlowItem{
			{
				Source:       FlowSourcePrompt,
				Tier:         2,
				EntityTypes:  []string{"iban"},
				EntityCount:  1,
				ValueDigests: []string{"abcdef0123456789"},
				Disposition:  FlowDispositionForwarded,
				Destination:  FlowDestination{Kind: FlowDestLLMProvider, Name: "openai", Region: "US"},
			},
		},
	}
	b, err := json.Marshal(df)
	require.NoError(t, err)
	var back DataFlow
	require.NoError(t, json.Unmarshal(b, &back))
	assert.Equal(t, *df, back)
}

func sortedStrings(s []string) bool {
	for i := 1; i < len(s); i++ {
		if s[i] < s[i-1] {
			return false
		}
	}
	return true
}
