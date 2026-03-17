package agent

import (
	"encoding/json"
	"fmt"
	"strings"
)

// IntentClassification describes the inferred risk posture for a tool invocation.
type IntentClassification struct {
	ToolName       string `json:"tool_name"`
	OperationClass string `json:"operation_class"`
	RiskLevel      string `json:"risk_level"`
	IsBulk         bool   `json:"is_bulk"`
	RequiresReview bool   `json:"requires_review"`
	Reason         string `json:"reason"`
}

// IntentClassDefinition documents a supported operation class and example tool names.
type IntentClassDefinition struct {
	Class       string   `json:"class"`
	DefaultRisk string   `json:"default_risk"`
	Description string   `json:"description"`
	Examples    []string `json:"examples"`
}

const defaultIntentVolumeThreshold = 100

// IntentClassCatalog returns the supported intent classes for CLI/help output.
func IntentClassCatalog() []IntentClassDefinition {
	return []IntentClassDefinition{
		{Class: "read", DefaultRisk: "low", Description: "Read-only lookup and retrieval", Examples: []string{"file_read", "sql_query", "web_search"}},
		{Class: "write", DefaultRisk: "medium", Description: "Create or update state", Examples: []string{"file_write", "sql_insert", "email_send"}},
		{Class: "delete", DefaultRisk: "high", Description: "Delete targeted resources", Examples: []string{"file_delete", "record_delete", "email_delete"}},
		{Class: "bulk", DefaultRisk: "high", Description: "High-volume operations affecting many items", Examples: []string{"bulk_update", "batch_delete", "mass_notify"}},
		{Class: "execute", DefaultRisk: "high", Description: "Execute code or shell-like actions", Examples: []string{"shell_execute", "code_run", "script_exec"}},
		{Class: "install", DefaultRisk: "high", Description: "Install software or dependencies", Examples: []string{"npm_install", "pip_install", "apt_install"}},
		{Class: "purge", DefaultRisk: "critical", Description: "Irreversible destructive cleanup", Examples: []string{"purge_cache", "wipe_data", "truncate_all"}},
	}
}

// ClassifyToolIntent classifies a tool call into operation class and review posture.
func ClassifyToolIntent(toolName string, paramsJSON []byte, planReviewCfg *PlanReviewConfig) *IntentClassification {
	name := strings.ToLower(strings.TrimSpace(toolName))
	if name == "" {
		name = "unknown"
	}

	opClass := inferOperationClass(name)
	isBulk := nameSuggestsBulk(name)

	var paramsText string
	if len(paramsJSON) > 0 {
		paramsText = strings.TrimSpace(string(paramsJSON))
		if maxCount, ok := maxNumericValueFromJSON(paramsJSON); ok {
			threshold := intentVolumeThreshold(planReviewCfg)
			if maxCount >= float64(threshold) {
				isBulk = true
			}
		}
	}

	if isBulk {
		opClass = "bulk"
	}

	risk := inferRisk(opClass, name)
	if isBulk && (strings.Contains(name, "delete") || strings.Contains(name, "purge") || strings.Contains(name, "wipe")) {
		risk = "critical"
	}

	requiresReview := shouldRequireReview(opClass, isBulk, name, paramsText, planReviewCfg)
	reason := buildReason(opClass, risk, isBulk, requiresReview)

	return &IntentClassification{
		ToolName:       toolName,
		OperationClass: opClass,
		RiskLevel:      risk,
		IsBulk:         isBulk,
		RequiresReview: requiresReview,
		Reason:         reason,
	}
}

func inferOperationClass(name string) string {
	switch {
	case containsAnyIntent(name, "purge", "wipe", "destroy", "truncate"):
		return "purge"
	case containsAnyIntent(name, "execute", "exec", "run", "shell", "command", "script"):
		return "execute"
	case containsAnyIntent(name, "install", "setup", "deploy", "upgrade"):
		return "install"
	case containsAnyIntent(name, "delete", "remove", "drop"):
		return "delete"
	case containsAnyIntent(name, "write", "create", "insert", "update", "edit", "send", "post", "put"):
		return "write"
	default:
		return "read"
	}
}

func inferRisk(opClass, name string) string {
	switch opClass {
	case "purge":
		return "critical"
	case "delete", "execute", "install", "bulk":
		return "high"
	case "write":
		return "medium"
	default:
		if containsAnyIntent(name, "admin", "root", "sudo") {
			return "high"
		}
		return "low"
	}
}

func shouldRequireReview(opClass string, isBulk bool, name, paramsText string, cfg *PlanReviewConfig) bool {
	// Conservative defaults for safety even when plan review config is absent.
	if opClass == "purge" || opClass == "execute" || opClass == "install" {
		return true
	}
	if opClass == "delete" && isBulk {
		return true
	}

	if cfg == nil {
		return isBulk
	}
	if isBulk {
		return true
	}

	planText := name
	if paramsText != "" {
		planText = fmt.Sprintf("%s %s", name, paramsText)
	}
	return RequiresReview("on-demand", 0, 0, true, cfg, planText)
}

func buildReason(opClass, risk string, isBulk, requiresReview bool) string {
	reason := fmt.Sprintf("classified as %s (risk=%s)", opClass, risk)
	if isBulk {
		reason += ", bulk signals detected"
	}
	if requiresReview {
		reason += ", human review required"
	}
	return reason
}

func nameSuggestsBulk(name string) bool {
	return containsAnyIntent(name, "bulk", "batch", "mass", "all", "many")
}

func intentVolumeThreshold(cfg *PlanReviewConfig) int {
	if cfg != nil && cfg.VolumeThreshold > 0 {
		return cfg.VolumeThreshold
	}
	return defaultIntentVolumeThreshold
}

func maxNumericValueFromJSON(payload []byte) (float64, bool) {
	var decoded any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return 0, false
	}
	maxValue, ok := walkNumeric(decoded)
	return maxValue, ok
}

func walkNumeric(v any) (float64, bool) {
	switch val := v.(type) {
	case float64:
		return val, true
	case map[string]any:
		var (
			maxValue float64
			found    bool
		)
		for _, child := range val {
			childMax, ok := walkNumeric(child)
			if !ok {
				continue
			}
			if !found || childMax > maxValue {
				maxValue = childMax
				found = true
			}
		}
		return maxValue, found
	case []any:
		var (
			maxValue float64
			found    bool
		)
		for _, child := range val {
			childMax, ok := walkNumeric(child)
			if !ok {
				continue
			}
			if !found || childMax > maxValue {
				maxValue = childMax
				found = true
			}
		}
		return maxValue, found
	default:
		return 0, false
	}
}

func containsAnyIntent(value string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}
