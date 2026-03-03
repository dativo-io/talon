package feature

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAllFeatures_Order(t *testing.T) {
	all := AllFeatures()
	require.Len(t, all, 6)
	for i := 1; i < len(all); i++ {
		assert.LessOrEqual(t, all[i-1].Order, all[i].Order,
			"feature %q (order %d) should come before %q (order %d)",
			all[i-1].ID, all[i-1].Order, all[i].ID, all[i].Order)
	}
}

func TestDefaultsForWorkload_Proxy_ReturnsThree(t *testing.T) {
	features := DefaultsForWorkload("proxy")
	require.Len(t, features, 3, "proxy workload should get 3 features (pii, audit, cost)")
	ids := make([]string, len(features))
	for i, f := range features {
		ids[i] = f.ID
	}
	assert.Contains(t, ids, "pii")
	assert.Contains(t, ids, "audit")
	assert.Contains(t, ids, "cost")
	assert.NotContains(t, ids, "injection")
	assert.NotContains(t, ids, "eu-ai-act")
	assert.NotContains(t, ids, "dora")
}

func TestDefaultsForWorkload_Agent_ReturnsSix(t *testing.T) {
	features := DefaultsForWorkload("agent")
	require.Len(t, features, 6, "agent workload should get all 6 features")
	ids := make([]string, len(features))
	for i, f := range features {
		ids[i] = f.ID
	}
	assert.Contains(t, ids, "pii")
	assert.Contains(t, ids, "audit")
	assert.Contains(t, ids, "cost")
	assert.Contains(t, ids, "injection")
	assert.Contains(t, ids, "eu-ai-act")
	assert.Contains(t, ids, "dora")
}

func TestDefaultsForWorkload_Hybrid_ReturnsSix(t *testing.T) {
	features := DefaultsForWorkload("hybrid")
	require.Len(t, features, 6)
}

func TestDefaultsForWorkload_Unknown_ReturnsEmpty(t *testing.T) {
	features := DefaultsForWorkload("unknown")
	assert.Empty(t, features)
}

func TestValidFeatureIDs(t *testing.T) {
	ids := ValidFeatureIDs()
	assert.Contains(t, ids, "pii")
	assert.Contains(t, ids, "audit")
	assert.Contains(t, ids, "cost")
	assert.Contains(t, ids, "injection")
	assert.Contains(t, ids, "eu-ai-act")
	assert.Contains(t, ids, "dora")
	assert.Len(t, ids, 6)
}

func TestDefaultEnabledIDs(t *testing.T) {
	ids := DefaultEnabledIDs()
	assert.Contains(t, ids, "pii")
	assert.Contains(t, ids, "audit")
	assert.Contains(t, ids, "cost")
	assert.Contains(t, ids, "injection")
	assert.NotContains(t, ids, "eu-ai-act")
	assert.NotContains(t, ids, "dora")
}

func TestFindByID(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		f, ok := FindByID("pii")
		assert.True(t, ok)
		assert.Equal(t, "PII detection & redaction", f.DisplayName)
	})
	t.Run("not found", func(t *testing.T) {
		_, ok := FindByID("nonexistent")
		assert.False(t, ok)
	})
}
