package cache

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTierLabel(t *testing.T) {
	tests := []struct {
		tier int
		want string
	}{
		{0, "public"},
		{1, "internal"},
		{2, "confidential"},
		{-1, "confidential"},
		{99, "confidential"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, TierLabel(tt.tier), "tier %d", tt.tier)
	}
}

func TestTTLForTier(t *testing.T) {
	byTier := map[string]int{"public": 3600, "internal": 900}

	tests := []struct {
		name       string
		label      string
		byTier     map[string]int
		defaultTTL int
		want       time.Duration
	}{
		{"tier override wins", "internal", byTier, 7200, 900 * time.Second},
		{"falls back to default when tier missing", "confidential", byTier, 7200, 7200 * time.Second},
		{"falls back to default when map nil", "public", nil, 1800, 1800 * time.Second},
		{"one hour when nothing configured", "public", nil, 0, time.Hour},
		{"zero tier value ignored", "public", map[string]int{"public": 0}, 600, 600 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, TTLForTier(tt.label, tt.byTier, tt.defaultTTL))
		})
	}
}
