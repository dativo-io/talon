package evidence

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func attemptRecord(id, provider, region string) *Evidence {
	return &Evidence{
		ID:            id,
		CorrelationID: "corr-1",
		Failover: &FailoverContext{
			Role:            FailoverRoleFailedAttempt,
			Provider:        provider,
			Region:          region,
			ErrorClass:      "upstream_5xx",
			SovereigntyMode: "eu_strict",
		},
	}
}

func decisionRecord(id, provider, region, check string, attemptIDs []string) *Evidence {
	return &Evidence{
		ID:            id,
		CorrelationID: "corr-1",
		Failover: &FailoverContext{
			Role:             FailoverRoleFallbackDecision,
			Provider:         provider,
			Region:           region,
			ChainPosition:    1,
			SovereigntyMode:  "eu_strict",
			SovereigntyCheck: check,
			FailedAttemptIDs: attemptIDs,
		},
	}
}

func failClosedRecord(id string, attemptIDs []string, skipped []SkippedCandidate) *Evidence {
	return &Evidence{
		ID:            id,
		CorrelationID: "corr-1",
		Failover: &FailoverContext{
			Role:              FailoverRoleFailClosed,
			SovereigntyMode:   "eu_strict",
			FailedAttemptIDs:  attemptIDs,
			SkippedCandidates: skipped,
		},
	}
}

func TestVerifyFailoverRecords(t *testing.T) {
	t.Run("no failover context returns nil", func(t *testing.T) {
		records := []*Evidence{{ID: "a", CorrelationID: "corr-1"}}
		assert.Nil(t, VerifyFailoverRecords("corr-1", records, nil))
	})

	t.Run("failed EU primary + successful EU secondary with matching correlation = valid fallback", func(t *testing.T) {
		records := []*Evidence{
			attemptRecord("att-1", "openai-eu", "EU"),
			decisionRecord("dec-1", "mistral", "EU", "allowed", []string{"att-1"}),
		}
		f := VerifyFailoverRecords("corr-1", records, nil)
		require.NotNil(t, f)
		assert.Equal(t, FailoverVerdictValidFallback, f.Verdict, "details: %v", f.Details)
	})

	t.Run("failed primary + only non-allowed secondary + no dispatch = valid fail-closed", func(t *testing.T) {
		records := []*Evidence{
			attemptRecord("att-1", "openai-eu", "EU"),
			failClosedRecord("fc-1", []string{"att-1"}, []SkippedCandidate{
				{Provider: "openai-us", Filter: "sovereignty", Reason: "region US not EU/LOCAL"},
			}),
		}
		f := VerifyFailoverRecords("corr-1", records, nil)
		require.NotNil(t, f)
		assert.Equal(t, FailoverVerdictValidFailClosed, f.Verdict, "details: %v", f.Details)
	})

	t.Run("fallback dispatch to sovereignty-rejected provider = invalid", func(t *testing.T) {
		records := []*Evidence{
			attemptRecord("att-1", "openai-eu", "EU"),
			decisionRecord("dec-1", "openai-us", "US", "allowed", []string{"att-1"}),
		}
		f := VerifyFailoverRecords("corr-1", records, nil)
		require.NotNil(t, f)
		assert.Equal(t, FailoverVerdictInvalid, f.Verdict)
	})

	t.Run("dispatch with sovereignty_check denied = invalid even in EU region", func(t *testing.T) {
		records := []*Evidence{
			attemptRecord("att-1", "openai-eu", "EU"),
			decisionRecord("dec-1", "mistral", "EU", "denied", []string{"att-1"}),
		}
		f := VerifyFailoverRecords("corr-1", records, nil)
		require.NotNil(t, f)
		assert.Equal(t, FailoverVerdictInvalid, f.Verdict)
	})

	t.Run("decision recording only final provider without failed attempt = insufficient", func(t *testing.T) {
		records := []*Evidence{
			decisionRecord("dec-1", "mistral", "EU", "allowed", nil),
		}
		f := VerifyFailoverRecords("corr-1", records, nil)
		require.NotNil(t, f)
		assert.Equal(t, FailoverVerdictInsufficient, f.Verdict)
	})

	t.Run("decision referencing missing attempt record = insufficient", func(t *testing.T) {
		records := []*Evidence{
			decisionRecord("dec-1", "mistral", "EU", "allowed", []string{"att-missing"}),
		}
		f := VerifyFailoverRecords("corr-1", records, nil)
		require.NotNil(t, f)
		assert.Equal(t, FailoverVerdictInsufficient, f.Verdict)
	})

	t.Run("failed attempts without decision context = insufficient", func(t *testing.T) {
		records := []*Evidence{attemptRecord("att-1", "openai-eu", "EU")}
		f := VerifyFailoverRecords("corr-1", records, nil)
		require.NotNil(t, f)
		assert.Equal(t, FailoverVerdictInsufficient, f.Verdict)
	})

	t.Run("fail-closed with no attempts and no skips = insufficient", func(t *testing.T) {
		records := []*Evidence{failClosedRecord("fc-1", nil, nil)}
		f := VerifyFailoverRecords("corr-1", records, nil)
		require.NotNil(t, f)
		assert.Equal(t, FailoverVerdictInsufficient, f.Verdict)
	})

	t.Run("multiple terminal records for one correlation id = invalid", func(t *testing.T) {
		records := []*Evidence{
			attemptRecord("att-1", "openai-eu", "EU"),
			decisionRecord("dec-1", "mistral", "EU", "allowed", []string{"att-1"}),
			failClosedRecord("fc-1", []string{"att-1"}, nil),
		}
		f := VerifyFailoverRecords("corr-1", records, nil)
		require.NotNil(t, f)
		assert.Equal(t, FailoverVerdictInvalid, f.Verdict)
	})

	t.Run("fallback decision at chain position 0 = invalid", func(t *testing.T) {
		dec := decisionRecord("dec-1", "mistral", "EU", "allowed", []string{"att-1"})
		dec.Failover.ChainPosition = 0
		records := []*Evidence{attemptRecord("att-1", "openai-eu", "EU"), dec}
		f := VerifyFailoverRecords("corr-1", records, nil)
		require.NotNil(t, f)
		assert.Equal(t, FailoverVerdictInvalid, f.Verdict)
	})

	t.Run("fallback provider equal to failed attempt provider = invalid", func(t *testing.T) {
		records := []*Evidence{
			attemptRecord("att-1", "mistral", "EU"),
			decisionRecord("dec-1", "mistral", "EU", "allowed", []string{"att-1"}),
		}
		f := VerifyFailoverRecords("corr-1", records, nil)
		require.NotNil(t, f)
		assert.Equal(t, FailoverVerdictInvalid, f.Verdict)
	})

	t.Run("attempt not referenced by the terminal record = insufficient", func(t *testing.T) {
		records := []*Evidence{
			attemptRecord("att-1", "openai-eu", "EU"),
			attemptRecord("att-orphan", "mistral-old", "EU"),
			decisionRecord("dec-1", "mistral", "EU", "allowed", []string{"att-1"}),
		}
		f := VerifyFailoverRecords("corr-1", records, nil)
		require.NotNil(t, f)
		assert.Equal(t, FailoverVerdictInsufficient, f.Verdict)
	})

	t.Run("invalid signature = invalid, outranks insufficient", func(t *testing.T) {
		records := []*Evidence{
			decisionRecord("dec-1", "mistral", "EU", "allowed", nil),
		}
		alwaysInvalid := func(*Evidence) bool { return false }
		f := VerifyFailoverRecords("corr-1", records, alwaysInvalid)
		require.NotNil(t, f)
		assert.Equal(t, FailoverVerdictInvalid, f.Verdict)
	})

	t.Run("non-eu_strict mode does not flag US fallback", func(t *testing.T) {
		records := []*Evidence{
			attemptRecord("att-1", "openai", "US"),
			{
				ID:            "dec-1",
				CorrelationID: "corr-1",
				Failover: &FailoverContext{
					Role:             FailoverRoleFallbackDecision,
					Provider:         "anthropic",
					Region:           "US",
					ChainPosition:    1,
					SovereigntyMode:  "global",
					SovereigntyCheck: "not_evaluated",
					FailedAttemptIDs: []string{"att-1"},
				},
			},
		}
		f := VerifyFailoverRecords("corr-1", records, nil)
		require.NotNil(t, f)
		assert.Equal(t, FailoverVerdictValidFallback, f.Verdict, "details: %v", f.Details)
	})
}
