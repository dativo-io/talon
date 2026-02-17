package policy

import (
	"context"
	"testing"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestToClassifierRecognizers_OmittedScoreBecomesNil(t *testing.T) {
	// Custom recognizers from .talon.yaml with score omitted (unmarshals as 0).
	custom := []CustomRecognizerConfig{
		{
			Name:            "Order ID",
			SupportedEntity: "ORDER_ID",
			Patterns: []CustomPatternConfig{
				{Name: "order", Regex: `\bORD-\d{6}\b`, Score: 0}, // omitted in YAML
			},
			Sensitivity: 1,
		},
	}

	recs := ToClassifierRecognizers(custom)
	require.Len(t, recs, 1)
	require.Len(t, recs[0].Patterns, 1)
	assert.Nil(t, recs[0].Patterns[0].Score,
		"omitted score (0) must convert to nil so classifier uses DefaultMinScore")

	// Scanner should still match when built with these recognizers.
	scanner, err := classifier.NewScanner(classifier.WithCustomRecognizers(recs))
	require.NoError(t, err)
	ctx := context.Background()
	result := scanner.Scan(ctx, "See ORD-123456 for details")
	assert.True(t, result.HasPII, "pattern with omitted score must be effective")
}

func TestToClassifierRecognizers_ExplicitScorePreserved(t *testing.T) {
	score := 0.9
	custom := []CustomRecognizerConfig{
		{
			Name:            "Code",
			SupportedEntity: "CODE",
			Patterns: []CustomPatternConfig{
				{Name: "code", Regex: `\bCODE-\w+\b`, Score: score},
			},
			Sensitivity: 1,
		},
	}

	recs := ToClassifierRecognizers(custom)
	require.Len(t, recs, 1)
	require.Len(t, recs[0].Patterns, 1)
	require.NotNil(t, recs[0].Patterns[0].Score)
	assert.Equal(t, 0.9, *recs[0].Patterns[0].Score)
}

// TestPIIScannerOptions_FromDataClassification verifies that enabled_entities,
// disabled_entities, and custom_recognizers from policy are passed into classifier.NewScanner.
func TestPIIScannerOptions_FromDataClassification(t *testing.T) {
	ctx := context.Background()

	t.Run("enabled_entities whitelist", func(t *testing.T) {
		cfg := &DataClassificationConfig{
			EnabledEntities: []string{"EMAIL_ADDRESS"},
		}
		opts, err := PIIScannerOptions(cfg, "")
		require.NoError(t, err)
		scanner, err := classifier.NewScanner(opts...)
		require.NoError(t, err)
		// Only email should be detected; IP should be filtered out by whitelist
		emailResult := scanner.Scan(ctx, "Contact user@example.com for details")
		assert.True(t, emailResult.HasPII, "email should be detected when enabled_entities includes EMAIL_ADDRESS")
		ipResult := scanner.Scan(ctx, "Server at 192.168.1.100")
		assert.False(t, ipResult.HasPII, "IP should be ignored when only EMAIL_ADDRESS is enabled")
	})

	t.Run("disabled_entities blacklist", func(t *testing.T) {
		cfg := &DataClassificationConfig{
			DisabledEntities: []string{"IP_ADDRESS"},
		}
		opts, err := PIIScannerOptions(cfg, "")
		require.NoError(t, err)
		scanner, err := classifier.NewScanner(opts...)
		require.NoError(t, err)
		result := scanner.Scan(ctx, "Server at 192.168.1.100")
		assert.False(t, result.HasPII, "IP should be disabled by disabled_entities")
		emailResult := scanner.Scan(ctx, "Reply to admin@company.eu")
		assert.True(t, emailResult.HasPII, "email should still be detected")
	})

	t.Run("custom_recognizers", func(t *testing.T) {
		cfg := &DataClassificationConfig{
			CustomRecognizers: []CustomRecognizerConfig{
				{
					Name:            "Ticket ID",
					SupportedEntity: "TICKET_ID",
					Patterns:        []CustomPatternConfig{{Name: "ticket", Regex: `\bTKT-\d{5}\b`}},
					Sensitivity:     1,
				},
			},
		}
		opts, err := PIIScannerOptions(cfg, "")
		require.NoError(t, err)
		scanner, err := classifier.NewScanner(opts...)
		require.NoError(t, err)
		result := scanner.Scan(ctx, "See TKT-12345 for details")
		assert.True(t, result.HasPII, "custom recognizer TKT-12345 should be detected")
	})

	t.Run("nil config returns default options", func(t *testing.T) {
		opts, err := PIIScannerOptions(nil, "")
		require.NoError(t, err)
		scanner, err := classifier.NewScanner(opts...)
		require.NoError(t, err)
		result := scanner.Scan(ctx, "user@example.com and 192.168.1.1")
		assert.True(t, result.HasPII, "default scanner should detect PII")
	})
}

// TestNewPIIScannerForPolicy verifies the full policy→scanner path used at runtime.
func TestNewPIIScannerForPolicy(t *testing.T) {
	ctx := context.Background()

	t.Run("policy with data_classification", func(t *testing.T) {
		pol := &Policy{
			Policies: PoliciesConfig{
				DataClassification: &DataClassificationConfig{
					EnabledEntities: []string{"EMAIL_ADDRESS"},
				},
			},
		}
		scanner, err := NewPIIScannerForPolicy(pol, "")
		require.NoError(t, err)
		result := scanner.Scan(ctx, "Email user@example.com")
		assert.True(t, result.HasPII)
		result = scanner.Scan(ctx, "IP 192.168.1.1")
		assert.False(t, result.HasPII, "enabled_entities whitelist should restrict to email only")
	})

	t.Run("policy with nil data_classification uses defaults", func(t *testing.T) {
		pol := &Policy{}
		scanner, err := NewPIIScannerForPolicy(pol, "")
		require.NoError(t, err)
		result := scanner.Scan(ctx, "user@example.com")
		assert.True(t, result.HasPII)
	})

	t.Run("nil policy uses defaults", func(t *testing.T) {
		scanner, err := NewPIIScannerForPolicy(nil, "")
		require.NoError(t, err)
		result := scanner.Scan(ctx, "user@example.com")
		assert.True(t, result.HasPII)
	})
}
