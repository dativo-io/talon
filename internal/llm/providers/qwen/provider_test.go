package qwen

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dativo-io/talon/internal/llm"
)

func TestQwenMetadata(t *testing.T) {
	p := &QwenProvider{}
	meta := p.Metadata()
	assert.Equal(t, "qwen", meta.ID)
	assert.Equal(t, "CN", meta.Jurisdiction)
	assert.Equal(t, 80, meta.Wizard.Order)
}

func TestQwenGenerate_NotImplemented(t *testing.T) {
	p := &QwenProvider{apiKey: "key"}
	_, err := p.Generate(context.Background(), &llm.Request{Model: "qwen-turbo", Messages: []llm.Message{{Role: "user", Content: "Hi"}}, MaxTokens: 10})
	assert.Error(t, err)
	assert.ErrorIs(t, err, llm.ErrNotImplemented)
}
