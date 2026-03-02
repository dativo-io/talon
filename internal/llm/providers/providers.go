// Package providers aggregates all LLM provider implementations via blank imports.
// Each provider's init() registers itself with the llm registry.
package providers

import (
	_ "github.com/dativo-io/talon/internal/llm/providers/anthropic"
	_ "github.com/dativo-io/talon/internal/llm/providers/azure_openai"
	_ "github.com/dativo-io/talon/internal/llm/providers/bedrock"
	_ "github.com/dativo-io/talon/internal/llm/providers/cohere"
	_ "github.com/dativo-io/talon/internal/llm/providers/generic_openai"
	_ "github.com/dativo-io/talon/internal/llm/providers/mistral"
	_ "github.com/dativo-io/talon/internal/llm/providers/ollama"
	_ "github.com/dativo-io/talon/internal/llm/providers/openai"
	_ "github.com/dativo-io/talon/internal/llm/providers/qwen"
	_ "github.com/dativo-io/talon/internal/llm/providers/vertex"
)
