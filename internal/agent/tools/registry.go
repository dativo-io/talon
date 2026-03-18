// Package tools provides a thread-safe registry for MCP-compatible tools
// that agents can invoke during execution. Tools are registered by name and
// looked up at runtime when an agent's plan includes tool calls.
package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/xeipuuv/gojsonschema"
)

// Tool is the interface all MCP-compatible tools must implement.
type Tool interface {
	Name() string
	Description() string
	InputSchema() json.RawMessage
	Execute(ctx context.Context, params json.RawMessage) (json.RawMessage, error)
}

// ArgumentValidator is an optional interface that tools can implement to
// provide custom argument validation beyond JSON Schema. The runner first
// performs automatic JSON Schema validation using InputSchema(), then calls
// ValidateArguments for tools that implement this interface.
type ArgumentValidator interface {
	ValidateArguments(params json.RawMessage) error
}

// ValidateAgainstSchema validates params against a JSON Schema definition.
// Returns nil when schema is empty/null or params are valid.
func ValidateAgainstSchema(schema json.RawMessage, params json.RawMessage) error {
	if len(schema) == 0 || string(schema) == "null" || string(schema) == "{}" {
		return nil
	}
	if len(params) == 0 {
		params = json.RawMessage("{}")
	}
	schemaLoader := gojsonschema.NewBytesLoader(schema)
	paramsLoader := gojsonschema.NewBytesLoader(params)
	result, err := gojsonschema.Validate(schemaLoader, paramsLoader)
	if err != nil {
		return fmt.Errorf("schema validation setup: %w", err)
	}
	if result.Valid() {
		return nil
	}
	var msgs []string
	for _, e := range result.Errors() {
		msgs = append(msgs, e.String())
	}
	return fmt.Errorf("schema validation failed: %v", msgs)
}

// ToolRegistry manages registered tools for agent execution.
// Thread-safe for concurrent access.
type ToolRegistry struct {
	tools map[string]Tool
	mu    sync.RWMutex
}

// NewRegistry creates an empty tool registry.
func NewRegistry() *ToolRegistry {
	return &ToolRegistry{
		tools: make(map[string]Tool),
	}
}

// Register adds a tool to the registry.
func (r *ToolRegistry) Register(tool Tool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tools[tool.Name()] = tool
}

// Get returns a tool by name.
func (r *ToolRegistry) Get(name string) (Tool, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	tool, exists := r.tools[name]
	return tool, exists
}

// List returns all registered tools.
func (r *ToolRegistry) List() []Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]Tool, 0, len(r.tools))
	for _, t := range r.tools {
		result = append(result, t)
	}
	return result
}
