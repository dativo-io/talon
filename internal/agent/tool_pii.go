package agent

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/policy"
)

// ToolPIIFinding records a PII detection in a tool argument or result.
type ToolPIIFinding struct {
	Field     string   `json:"field"`
	Action    string   `json:"action"`
	PIITypes  []string `json:"pii_types"`
	PIICount  int      `json:"pii_count"`
	Direction string   `json:"direction"` // "argument" or "result"
}

// toolPIIResult holds the outcome of applying per-tool PII policies.
type toolPIIResult struct {
	ModifiedArgs json.RawMessage  // args after scanning/redaction (nil if unchanged)
	Findings     []ToolPIIFinding // all PII findings regardless of action
	Blocked      bool             // true if any argument had pii_action: "block" and PII was detected
	BlockReason  string
}

// applyToolArgumentPII scans tool arguments per the tool's PII policy and returns
// the (possibly modified) arguments along with any findings.
//
//nolint:gocyclo // per-field PII scanning with action dispatch requires branching
func applyToolArgumentPII(ctx context.Context, scanner *classifier.Scanner, toolName string, args json.RawMessage, pol *policy.Policy) *toolPIIResult {
	if scanner == nil {
		return &toolPIIResult{}
	}

	tp := resolveToolPolicy(toolName, pol)
	if tp == nil {
		return &toolPIIResult{}
	}

	ctx, span := tracer.Start(ctx, "tool_pii.scan_arguments",
		trace.WithAttributes(attribute.String("tool_name", toolName)))
	defer span.End()

	result := &toolPIIResult{}

	var argsMap map[string]json.RawMessage
	if err := json.Unmarshal(args, &argsMap); err != nil {
		argStr := string(args)
		action := tp.ArgumentDefault
		if action == "" {
			action = policy.PIIActionRedact
		}
		result.Findings = append(result.Findings, applyPIIAction(ctx, scanner, "_raw", argStr, action, "argument")...)
		if action == policy.PIIActionBlock {
			for _, f := range result.Findings {
				if f.PIICount > 0 {
					result.Blocked = true
					result.BlockReason = fmt.Sprintf("PII detected in arguments (types: %v)", f.PIITypes)
					break
				}
			}
		}
		if action == policy.PIIActionRedact {
			redacted := scanner.Redact(ctx, argStr)
			if redacted != argStr {
				redactedJSON, _ := json.Marshal(redacted)
				result.ModifiedArgs = redactedJSON
			}
		}
		return result
	}

	modified := false
	for field, val := range argsMap {
		action := tp.Arguments[field]
		if action == "" {
			action = tp.ArgumentDefault
		}
		if action == "" {
			action = policy.PIIActionRedact
		}
		if action == policy.PIIActionAllow {
			continue
		}

		valStr := string(val)
		var textVal string
		if err := json.Unmarshal(val, &textVal); err == nil {
			valStr = textVal
		}

		findings := applyPIIAction(ctx, scanner, field, valStr, action, "argument")
		result.Findings = append(result.Findings, findings...)

		for _, f := range findings {
			if f.PIICount > 0 && action == policy.PIIActionBlock {
				result.Blocked = true
				result.BlockReason = fmt.Sprintf("PII detected in field %q (types: %v)", field, f.PIITypes)
			}
		}

		if action == policy.PIIActionRedact {
			redacted := scanner.Redact(ctx, valStr)
			if redacted != valStr {
				redactedJSON, _ := json.Marshal(redacted)
				argsMap[field] = redactedJSON
				modified = true
			}
		}
	}

	if modified {
		newArgs, _ := json.Marshal(argsMap)
		result.ModifiedArgs = newArgs
	}
	return result
}

// applyToolResultPII scans a tool result per the tool's result PII policy.
func applyToolResultPII(ctx context.Context, scanner *classifier.Scanner, toolName string, resultContent string, pol *policy.Policy) (string, []ToolPIIFinding) {
	if scanner == nil {
		return resultContent, nil
	}

	tp := resolveToolPolicy(toolName, pol)
	if tp == nil {
		return resultContent, nil
	}

	action := tp.Result
	if action == "" {
		action = policy.PIIActionRedact
	}
	if action == policy.PIIActionAllow {
		return resultContent, nil
	}

	ctx, span := tracer.Start(ctx, "tool_pii.scan_result",
		trace.WithAttributes(attribute.String("tool_name", toolName)))
	defer span.End()

	findings := applyPIIAction(ctx, scanner, "_result", resultContent, action, "result")

	if action == policy.PIIActionRedact {
		redacted := scanner.Redact(ctx, resultContent)
		return redacted, findings
	}

	return resultContent, findings
}

func applyPIIAction(ctx context.Context, scanner *classifier.Scanner, field, text string, action policy.PIIAction, direction string) []ToolPIIFinding {
	cls := scanner.Scan(ctx, text)
	if cls == nil || !cls.HasPII {
		return nil
	}

	types := make(map[string]bool)
	for _, e := range cls.Entities {
		types[e.Type] = true
	}
	typeList := make([]string, 0, len(types))
	for t := range types {
		typeList = append(typeList, t)
	}

	finding := ToolPIIFinding{
		Field:     field,
		Action:    string(action),
		PIITypes:  typeList,
		PIICount:  len(cls.Entities),
		Direction: direction,
	}

	log.Debug().
		Str("tool_field", field).
		Str("action", string(action)).
		Strs("pii_types", typeList).
		Int("pii_count", len(cls.Entities)).
		Msg("tool_pii_finding")

	return []ToolPIIFinding{finding}
}

// resolveToolPolicy returns the ToolPIIPolicy for a tool, checking tool_policies[toolName],
// then tool_policies["_default"], then returning nil if no tool policies are configured.
func resolveToolPolicy(toolName string, pol *policy.Policy) *policy.ToolPIIPolicy {
	if pol == nil || len(pol.ToolPolicies) == 0 {
		return nil
	}
	if tp, ok := pol.ToolPolicies[toolName]; ok {
		return &tp
	}
	if tp, ok := pol.ToolPolicies["_default"]; ok {
		return &tp
	}
	return nil
}
