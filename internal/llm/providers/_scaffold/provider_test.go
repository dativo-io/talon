package scaffold

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/llm"
)

func TestScaffoldMetadata(t *testing.T) {
	p := &ScaffoldProvider{}
	meta := p.Metadata()
	assert.Equal(t, "scaffold", meta.ID)
	assert.NotEmpty(t, meta.DisplayName)
	assert.NotEmpty(t, meta.Jurisdiction)
}

func TestScaffoldGenerate_ReturnsNotImplemented(t *testing.T) {
	p := &ScaffoldProvider{}
	_, err := p.Generate(context.Background(), &llm.Request{Model: "scaffold-1", Messages: []llm.Message{{Role: "user", Content: "hi"}}})
	require.Error(t, err)
	assert.ErrorIs(t, err, llm.ErrNotImplemented)
}

func TestScaffoldEstimateCost(t *testing.T) {
	p := &ScaffoldProvider{}
	cost := p.EstimateCost("scaffold-1", 100, 50)
	assert.GreaterOrEqual(t, cost, 0.0)
}
