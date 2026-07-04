package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

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
func applyToolArgumentPII(ctx context.Context, scanner classifier.Facade, toolName string, args json.RawMessage, pol *policy.Policy) *toolPIIResult {
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
		rawFindings, rawScanErr := applyPIIAction(ctx, scanner, "_raw", argStr, action, "argument")
		if rawScanErr != nil {
			result.Blocked = true
			result.BlockReason = scannerUnavailableMessage("tool arguments blocked")
			result.Findings = append(result.Findings, scannerUnavailableFinding("_raw", "argument"))
			return result
		}
		result.Findings = append(result.Findings, rawFindings...)
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
			redacted, redactErr := scanner.RedactText(ctx, argStr)
			if redactErr != nil {
				result.Blocked = true
				result.BlockReason = scannerUnavailableMessage("tool arguments blocked")
				result.Findings = append(result.Findings, scannerUnavailableFinding("_raw", "argument"))
				return result
			}
			if verifyErr := scanner.VerifyEgress(ctx, redacted); verifyErr != nil {
				result.Blocked = true
				result.BlockReason = residualPIIMessage("tool arguments blocked: recognized PII remains after redaction", classifier.ResidualTypes(verifyErr))
				result.Findings = append(result.Findings, ToolPIIFinding{
					Field:     "_raw",
					Action:    string(policy.PIIActionBlock),
					PIITypes:  classifier.ResidualTypes(verifyErr),
					PIICount:  len(classifier.ResidualTypes(verifyErr)),
					Direction: "argument",
				})
				return result
			}
			if redacted != argStr {
				if redactionBreaksJSON(argStr, redacted) {
					result.Blocked = true
					result.BlockReason = invalidJSONAfterRedactionMessage("tool arguments blocked")
					result.Findings = append(result.Findings, ToolPIIFinding{
						Field:     "_raw",
						Action:    string(policy.PIIActionBlock),
						Direction: "argument",
					})
					return result
				}
				if json.Valid([]byte(redacted)) {
					result.ModifiedArgs = json.RawMessage(redacted)
				} else {
					redactedJSON, _ := json.Marshal(redacted)
					result.ModifiedArgs = redactedJSON
				}
			}
		}
		return result
	}

	modified := false
	fields := make([]string, 0, len(argsMap))
	for field := range argsMap {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	for _, field := range fields {
		val := argsMap[field]
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

		findings, fieldScanErr := applyPIIAction(ctx, scanner, field, valStr, action, "argument")
		if fieldScanErr != nil {
			if !result.Blocked {
				result.Blocked = true
				result.BlockReason = scannerUnavailableMessage("tool arguments blocked")
			}
			result.Findings = append(result.Findings, scannerUnavailableFinding(field, "argument"))
			continue
		}
		result.Findings = append(result.Findings, findings...)

		for _, f := range findings {
			if f.PIICount > 0 && action == policy.PIIActionBlock {
				if !result.Blocked {
					result.Blocked = true
					result.BlockReason = fmt.Sprintf("PII detected in field %q (types: %v)", field, f.PIITypes)
				}
			}
		}

		if action == policy.PIIActionRedact {
			redacted, redactErr := scanner.RedactText(ctx, valStr)
			if redactErr != nil {
				if !result.Blocked {
					result.Blocked = true
					result.BlockReason = scannerUnavailableMessage("tool arguments blocked")
				}
				result.Findings = append(result.Findings, scannerUnavailableFinding(field, "argument"))
				continue
			}
			if verifyErr := scanner.VerifyEgress(ctx, redacted); verifyErr != nil {
				if !result.Blocked {
					result.Blocked = true
					result.BlockReason = residualPIIMessage("tool arguments blocked: recognized PII remains after redaction", classifier.ResidualTypes(verifyErr))
				}
				result.Findings = append(result.Findings, ToolPIIFinding{
					Field:     field,
					Action:    string(policy.PIIActionBlock),
					PIITypes:  classifier.ResidualTypes(verifyErr),
					PIICount:  len(classifier.ResidualTypes(verifyErr)),
					Direction: "argument",
				})
				continue
			}
			if redacted != valStr {
				if redactionBreaksJSON(valStr, redacted) {
					if !result.Blocked {
						result.Blocked = true
						result.BlockReason = invalidJSONAfterRedactionMessage("tool arguments blocked")
					}
					result.Findings = append(result.Findings, ToolPIIFinding{
						Field:     field,
						Action:    string(policy.PIIActionBlock),
						Direction: "argument",
					})
					continue
				}
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
func applyToolResultPII(ctx context.Context, scanner classifier.Facade, toolName string, resultContent string, pol *policy.Policy) (string, []ToolPIIFinding) {
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

	findings, resultScanErr := applyPIIAction(ctx, scanner, "_result", resultContent, action, "result")
	if resultScanErr != nil {
		findings = append(findings, scannerUnavailableFinding("_result", "result"))
		return fmt.Sprintf(`{"error":"%s"}`, scannerUnavailableMessage("tool result blocked")), findings
	}

	if action == policy.PIIActionRedact {
		redacted, redactErr := scanner.RedactText(ctx, resultContent)
		if redactErr != nil {
			findings = append(findings, scannerUnavailableFinding("_result", "result"))
			return fmt.Sprintf(`{"error":"%s"}`, scannerUnavailableMessage("tool result blocked")), findings
		}
		if verifyErr := scanner.VerifyEgress(ctx, redacted); verifyErr != nil {
			types := classifier.ResidualTypes(verifyErr)
			findings = append(findings, ToolPIIFinding{
				Field:     "_result",
				Action:    string(policy.PIIActionBlock),
				PIITypes:  types,
				PIICount:  len(types),
				Direction: "result",
			})
			return fmt.Sprintf(`{"error":"%s"}`, residualPIIMessage("tool result blocked: recognized PII remains after redaction", types)), findings
		}
		if redactionBreaksJSON(resultContent, redacted) {
			findings = append(findings, ToolPIIFinding{
				Field:     "_result",
				Action:    string(policy.PIIActionBlock),
				Direction: "result",
			})
			return fmt.Sprintf(`{"error":"%s"}`, invalidJSONAfterRedactionMessage("tool result blocked")), findings
		}
		return redacted, findings
	}

	return resultContent, findings
}

func applyPIIAction(ctx context.Context, scanner classifier.Facade, field, text string, action policy.PIIAction, direction string) ([]ToolPIIFinding, error) {
	cls, err := scanner.Analyze(ctx, text)
	if err != nil {
		return nil, err
	}
	if cls == nil || !cls.HasPII {
		return nil, nil
	}

	types := make(map[string]bool)
	for _, e := range cls.Entities {
		types[e.Type] = true
	}
	typeList := make([]string, 0, len(types))
	for t := range types {
		typeList = append(typeList, t)
	}
	sort.Strings(typeList)

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

	return []ToolPIIFinding{finding}, nil
}

// scannerUnavailableFinding is the blocking finding recorded when the scan
// engine itself failed (fail-closed).
func scannerUnavailableFinding(field, direction string) ToolPIIFinding {
	return ToolPIIFinding{
		Field:     field,
		Action:    string(policy.PIIActionBlock),
		PIITypes:  []string{"scanner_unavailable"},
		PIICount:  1,
		Direction: direction,
	}
}

func scannerUnavailableMessage(prefix string) string {
	return prefix + ": PII scanner unavailable (fail-closed)"
}

func residualPIIMessage(prefix string, types []string) string {
	remediation := " Remediation required: use approval workflow to adjust policy or content, re-run redaction, then re-scan."
	if len(types) == 0 {
		return prefix + "." + remediation
	}
	return prefix + " (types: " + strings.Join(types, ", ") + ")." + remediation
}

func redactionBreaksJSON(original, redacted string) bool {
	return redacted != original && json.Valid([]byte(original)) && !json.Valid([]byte(redacted))
}

func invalidJSONAfterRedactionMessage(prefix string) string {
	return prefix + ": PII redaction produced invalid JSON (fail-closed)"
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
