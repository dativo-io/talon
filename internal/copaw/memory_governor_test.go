package copaw

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/memory"
)

func TestNewMemoryGovernor(t *testing.T) {
	g := NewMemoryGovernor(nil, nil)
	require.NotNil(t, g)
	assert.Nil(t, g.Scanner)
}

func TestMemoryGovernor_ValidateWrite_ForbiddenCategory(t *testing.T) {
	g := NewMemoryGovernor(nil, nil)
	ctx := context.Background()

	err := g.ValidateWrite(ctx, "tenant1", "agent1", "policy_modifications", "some content")
	require.Error(t, err)
	assert.True(t, errors.Is(err, memory.ErrMemoryWriteDenied))
	assert.Contains(t, err.Error(), "forbidden")

	err = g.ValidateWrite(ctx, "tenant1", "agent1", "prompt_injection", "content")
	require.Error(t, err)
	assert.True(t, errors.Is(err, memory.ErrMemoryWriteDenied))

	err = g.ValidateWrite(ctx, "tenant1", "agent1", "credential_data", "content")
	require.Error(t, err)
	assert.True(t, errors.Is(err, memory.ErrMemoryWriteDenied))
}

func TestMemoryGovernor_ValidateWrite_ForbiddenPhrase(t *testing.T) {
	g := NewMemoryGovernor(nil, nil)
	ctx := context.Background()

	for _, phrase := range []string{"ignore policy", "bypass policy", "override policy", "disable policy", "policy: false", "allowed: true", "cost_limits: null", "budget: infinity"} {
		err := g.ValidateWrite(ctx, "t", "a", memory.CategoryDomainKnowledge, "text with "+phrase+" inside")
		require.Error(t, err, "phrase %q should be rejected", phrase)
		assert.True(t, errors.Is(err, memory.ErrMemoryWriteDenied))
	}
}

func TestMemoryGovernor_ValidateWrite_AllowedCategory_NoScanner(t *testing.T) {
	g := NewMemoryGovernor(nil, nil)
	ctx := context.Background()

	err := g.ValidateWrite(ctx, "tenant1", "agent1", memory.CategoryDomainKnowledge, "safe content")
	assert.NoError(t, err)

	err = g.ValidateWrite(ctx, "tenant1", "agent1", memory.CategoryFactualCorrections, "another safe content")
	assert.NoError(t, err)
}

func TestMemoryGovernor_ValidateWrite_PIIDetected(t *testing.T) {
	scanner, err := classifier.NewScanner()
	require.NoError(t, err)
	g := NewMemoryGovernor(scanner, nil)
	ctx := context.Background()

	err = g.ValidateWrite(ctx, "tenant1", "agent1", memory.CategoryDomainKnowledge, "contact user@example.com for details")
	require.Error(t, err)
	assert.True(t, errors.Is(err, memory.ErrPIIDetected))
	assert.Contains(t, err.Error(), "PII")
}

func TestMemoryGovernor_ValidateWrite_NoPII_Success(t *testing.T) {
	scanner, err := classifier.NewScanner()
	require.NoError(t, err)
	g := NewMemoryGovernor(scanner, nil)
	ctx := context.Background()

	err = g.ValidateWrite(ctx, "tenant1", "agent1", memory.CategoryDomainKnowledge, "plain factual content with no PII")
	assert.NoError(t, err)
}

func TestMemoryGovernor_ValidateWrite_CustomForbiddenPhrases(t *testing.T) {
	// Custom phrases from .talon.yaml copaw.memory.forbidden_phrases override defaults.
	g := NewMemoryGovernor(nil, []string{"custom_phrase", "another_custom"})
	ctx := context.Background()

	err := g.ValidateWrite(ctx, "t", "a", memory.CategoryDomainKnowledge, "content with custom_phrase")
	require.Error(t, err)
	assert.True(t, errors.Is(err, memory.ErrMemoryWriteDenied))

	err = g.ValidateWrite(ctx, "t", "a", memory.CategoryDomainKnowledge, "content with another_custom")
	require.Error(t, err)

	// Default built-in phrases are not applied when custom list is set.
	err = g.ValidateWrite(ctx, "t", "a", memory.CategoryDomainKnowledge, "content with ignore policy")
	assert.NoError(t, err)
}
