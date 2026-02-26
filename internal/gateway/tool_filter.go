package gateway

import (
	"encoding/json"
	"fmt"
	"path"
	"strings"
)

// ToolGovernanceResult holds the outcome of tool policy evaluation.
type ToolGovernanceResult struct {
	Requested []string // Original tool names in the request.
	Kept      []string // Tool names that passed policy.
	Removed   []string // Tool names stripped by policy.
}

// EvaluateToolPolicy checks each tool name against the resolved allowed/forbidden
// lists. Returns which tools to keep and which to remove.
//
// Rules:
//   - If allowed is non-empty, only tools in allowed pass (allowlist mode).
//   - Any tool matching a forbidden pattern is removed (forbidden overrides allowed).
//   - Forbidden patterns use path.Match glob syntax (e.g. "delete_*", "admin_*").
func EvaluateToolPolicy(toolNames, allowed, forbidden []string) ToolGovernanceResult {
	res := ToolGovernanceResult{Requested: toolNames}

	allowSet := make(map[string]bool, len(allowed))
	for _, a := range allowed {
		allowSet[a] = true
	}
	hasAllowlist := len(allowed) > 0

	for _, name := range toolNames {
		if isForbiddenTool(name, forbidden) {
			res.Removed = append(res.Removed, name)
			continue
		}
		if hasAllowlist && !allowSet[name] {
			res.Removed = append(res.Removed, name)
			continue
		}
		res.Kept = append(res.Kept, name)
	}
	return res
}

// isForbiddenTool checks if a tool name matches any forbidden pattern.
func isForbiddenTool(name string, forbidden []string) bool {
	lower := strings.ToLower(name)
	for _, pattern := range forbidden {
		if matched, _ := path.Match(strings.ToLower(pattern), lower); matched {
			return true
		}
	}
	return false
}

// FilterRequestBodyTools removes tools not in keepSet from the JSON request body.
// Handles OpenAI (Chat Completions + Responses API) and Anthropic formats.
// If tool_choice references a removed tool, it is reset to the provider's auto
// format: "auto" (string) for OpenAI, {"type":"auto"} (object) for Anthropic.
func FilterRequestBodyTools(provider string, body []byte, keep []string) ([]byte, error) {
	switch provider {
	case "openai", "ollama":
		return filterOpenAITools(body, keep)
	case "anthropic":
		return filterAnthropicTools(body, keep)
	default:
		return filterOpenAITools(body, keep)
	}
}

func filterOpenAITools(body []byte, keep []string) ([]byte, error) {
	var m map[string]interface{}
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("parsing request body for tool filtering: %w", err)
	}

	rawTools, ok := m["tools"].([]interface{})
	if !ok || len(rawTools) == 0 {
		return body, nil
	}

	keepSet := makeSet(keep)
	filtered := make([]interface{}, 0, len(keep))
	for _, raw := range rawTools {
		tool, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		name := openAIToolName(tool)
		if name != "" && keepSet[name] {
			filtered = append(filtered, tool)
		}
	}

	if len(filtered) == 0 {
		delete(m, "tools")
		delete(m, "tool_choice")
	} else {
		m["tools"] = filtered
		fixToolChoice(m, keepSet, "openai")
	}

	return json.Marshal(m)
}

// openAIToolName extracts the function name from an OpenAI tool definition.
// Chat Completions: {"type":"function","function":{"name":"..."}}.
// Responses API:    {"type":"function","name":"..."}.
func openAIToolName(tool map[string]interface{}) string {
	if fn, ok := tool["function"].(map[string]interface{}); ok {
		if n, ok := fn["name"].(string); ok {
			return n
		}
	}
	if n, ok := tool["name"].(string); ok {
		return n
	}
	return ""
}

func filterAnthropicTools(body []byte, keep []string) ([]byte, error) {
	var m map[string]interface{}
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("parsing anthropic request body for tool filtering: %w", err)
	}

	rawTools, ok := m["tools"].([]interface{})
	if !ok || len(rawTools) == 0 {
		return body, nil
	}

	keepSet := makeSet(keep)
	filtered := make([]interface{}, 0, len(keep))
	for _, raw := range rawTools {
		tool, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if n, ok := tool["name"].(string); ok && keepSet[n] {
			filtered = append(filtered, tool)
		}
	}

	if len(filtered) == 0 {
		delete(m, "tools")
		delete(m, "tool_choice")
	} else {
		m["tools"] = filtered
		fixToolChoice(m, keepSet, "anthropic")
	}

	return json.Marshal(m)
}

// fixToolChoice resets tool_choice to "auto" if it references a tool not in keepSet.
// Handles both OpenAI object format ({"type":"function","function":{"name":"..."}})
// and Anthropic object format ({"type":"tool","name":"..."}).
// OpenAI expects the string "auto"; Anthropic expects {"type":"auto"}.
func fixToolChoice(m map[string]interface{}, keepSet map[string]bool, provider string) {
	tc, ok := m["tool_choice"]
	if !ok {
		return
	}
	switch v := tc.(type) {
	case string:
		// "auto", "none", "required" — leave as-is for OpenAI.
		// Anthropic uses objects but also accepts {"type":"auto"} via its own format;
		// string values here are not provider-specific, so leave them.
	case map[string]interface{}:
		name := ""
		if fn, ok := v["function"].(map[string]interface{}); ok {
			name, _ = fn["name"].(string)
		}
		if name == "" {
			name, _ = v["name"].(string)
		}
		if name != "" && !keepSet[name] {
			if provider == "anthropic" {
				m["tool_choice"] = map[string]interface{}{"type": "auto"}
			} else {
				m["tool_choice"] = "auto"
			}
		}
	default:
		_ = v
	}
}

func makeSet(items []string) map[string]bool {
	s := make(map[string]bool, len(items))
	for _, item := range items {
		s[item] = true
	}
	return s
}
