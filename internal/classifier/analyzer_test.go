package classifier

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScannerImplementsAnalyzer(t *testing.T) {
	var a Analyzer = MustNewScanner()
	assert.Equal(t, DetectorTalonRegex, a.Detector())

	text := "My IBAN is DE89370400440532013000"
	cls, err := a.Analyze(context.Background(), text)
	require.NoError(t, err)
	require.NotNil(t, cls)
	assert.True(t, cls.HasPII)

	// Analyze must agree with Scan (same engine underneath).
	direct := MustNewScanner().Scan(context.Background(), text)
	assert.Equal(t, direct.Tier, cls.Tier)
	assert.Equal(t, len(direct.Entities), len(cls.Entities))
}

func TestMergeEntitySpans(t *testing.T) {
	tests := []struct {
		name     string
		text     string
		entities []PIIEntity
		want     []PIIEntity
	}{
		{
			name:     "empty",
			text:     "hello",
			entities: nil,
			want:     nil,
		},
		{
			name: "non_overlapping_preserved",
			text: "a@b.de and DE89370400440532013000",
			entities: []PIIEntity{
				{Type: "iban", Value: "DE89370400440532013000", Position: 11, Confidence: 0.9, Sensitivity: 3},
				{Type: "email", Value: "a@b.de", Position: 0, Confidence: 0.8, Sensitivity: 1},
			},
			want: []PIIEntity{
				{Type: "email", Value: "a@b.de", Position: 0, Confidence: 0.8, Sensitivity: 1},
				{Type: "iban", Value: "DE89370400440532013000", Position: 11, Confidence: 0.9, Sensitivity: 3},
			},
		},
		{
			name: "exact_duplicates_collapse",
			text: "a@b.de",
			entities: []PIIEntity{
				{Type: "email", Value: "a@b.de", Position: 0, Confidence: 0.8, Sensitivity: 1},
				{Type: "email", Value: "a@b.de", Position: 0, Confidence: 0.9, Sensitivity: 1},
			},
			want: []PIIEntity{
				{Type: "email", Value: "a@b.de", Position: 0, Confidence: 0.9, Sensitivity: 1},
			},
		},
		{
			name: "overlap_higher_sensitivity_wins_and_span_extends",
			text: "ID-12345-6789-X",
			entities: []PIIEntity{
				{Type: "custom_low", Value: "ID-12345", Position: 0, Confidence: 0.7, Sensitivity: 1},
				{Type: "custom_high", Value: "12345-6789-X", Position: 3, Confidence: 0.6, Sensitivity: 3},
			},
			want: []PIIEntity{
				// span extended to cover both, high-sensitivity type wins, max confidence kept
				{Type: "custom_high", Value: "ID-12345-6789-X", Position: 0, Confidence: 0.7, Sensitivity: 3},
			},
		},
		{
			name: "contained_span_absorbed",
			text: "DE89370400440532013000",
			entities: []PIIEntity{
				{Type: "iban", Value: "DE89370400440532013000", Position: 0, Confidence: 0.95, Sensitivity: 3},
				{Type: "national_id", Value: "370400440532", Position: 4, Confidence: 0.5, Sensitivity: 2},
			},
			want: []PIIEntity{
				{Type: "iban", Value: "DE89370400440532013000", Position: 0, Confidence: 0.95, Sensitivity: 3},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MergeEntitySpans(tt.text, tt.entities)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestRedactBehaviorUnchangedAfterMergeExtraction guards the refactor that
// moved span merging out of Redact into MergeEntitySpans: overlapping
// detections must still produce a single placeholder.
func TestRedactBehaviorUnchangedAfterMergeExtraction(t *testing.T) {
	s := MustNewScanner()
	text := "Contact john.doe@example.com or transfer to DE89370400440532013000."
	out := s.Redact(context.Background(), text)
	assert.NotContains(t, out, "john.doe@example.com")
	assert.NotContains(t, out, "DE89370400440532013000")
	assert.Contains(t, out, "[EMAIL]")
	assert.Contains(t, out, "[IBAN]")
}
