// Package tools provides a thread-safe registry for MCP-compatible tools
// that agents can invoke during execution. Tools are registered by name and
// looked up at runtime when an agent's plan includes tool calls.
package tools

import (
	"context"
	"encoding/json"
	"sync"
)

// Tool is the interface all MCP-compatible tools must implement.
type Tool interface {
	Name() string
	Description() string
	InputSchema() json.RawMessage
	Execute(ctx context.Context, params json.RawMessage) (json.RawMessage, error)
}

// ArgumentValidator is an optional interface that tools can implement to
// validate arguments against their schema before execution. When a tool
// implements this interface, the runner calls ValidateArguments before Execute.
//
// Phase 2 will add automatic JSON Schema validation for all tools using
// the InputSchema() return value. For v1, tools opt in by implementing this.
type ArgumentValidator interface {
	ValidateArguments(params json.RawMessage) error
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
