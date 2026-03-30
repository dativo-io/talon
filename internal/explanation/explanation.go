package explanation

import (
	"sort"
	"strings"
)

const (
	CodePolicyAllowed          = "POLICY_ALLOWED"
	CodePolicyDenied           = "POLICY_DENIED"
	CodePolicyDeniedPIIInput   = "POLICY_DENIED_PII_INPUT"
	CodePolicyDeniedPIIOutput  = "POLICY_DENIED_PII_OUTPUT"
	CodePolicyDeniedCost       = "POLICY_DENIED_COST"
	CodePolicyDeniedRouting    = "POLICY_DENIED_ROUTING"
	CodePolicyDeniedTool       = "POLICY_DENIED_TOOL"
	CodePolicyDeniedHook       = "POLICY_DENIED_HOOK"
	CodePolicyDeniedCircuit    = "POLICY_DENIED_CIRCUIT_BREAKER"
	CodePolicyDeniedEarlyTerm  = "POLICY_DENIED_EARLY_TERMINATION"
	CodePolicyModified         = "POLICY_MODIFIED"
	CodePolicyFiltered         = "POLICY_FILTERED"
	CodeExecutionFailed        = "EXECUTION_FAILED"
	CodeLegacyReasonUnmigrated = "LEGACY_REASON_UNMIGRATED"
)

const (
	DecisionAllow    = "allow"
	DecisionDeny     = "deny"
	DecisionModify   = "modify"
	DecisionFilter   = "filter"
	DecisionFailure  = "failure"
	defaultStageName = "policy_evaluation"
)

// Fact is the source-of-truth structured explanation fact.
type Fact struct {
	Code            string
	Decision        string
	Stage           string
	Trigger         string
	Fix             string
	PolicyRef       string
	VersionIdentity string
}

// Item is the deterministic, human-readable explanation payload.
type Item struct {
	Code            string `json:"code"`
	Decision        string `json:"decision"`
	Stage           string `json:"stage"`
	Reason          string `json:"reason"`
	Trigger         string `json:"trigger,omitempty"`
	Fix             string `json:"fix,omitempty"`
	PolicyRef       string `json:"policy_ref,omitempty"`
	VersionIdentity string `json:"version_identity,omitempty"`
}

// BuildFromFacts renders deterministic explanation items from structured facts.
func BuildFromFacts(facts []Fact) []Item {
	if len(facts) == 0 {
		return nil
	}

	normalized := normalizeFacts(facts)
	dedup := make(map[string]Item, len(normalized))
	for i := range normalized {
		f := normalized[i]
		item := Item{
			Code:            f.Code,
			Decision:        f.Decision,
			Stage:           f.Stage,
			Reason:          renderReason(f),
			Trigger:         f.Trigger,
			Fix:             f.Fix,
			PolicyRef:       f.PolicyRef,
			VersionIdentity: f.VersionIdentity,
		}
		key := item.Code + "|" + item.Decision + "|" + item.Stage + "|" + item.Trigger + "|" + item.PolicyRef + "|" + item.VersionIdentity + "|" + item.Reason + "|" + item.Fix
		dedup[key] = item
	}

	out := make([]Item, 0, len(dedup))
	for key := range dedup {
		out = append(out, dedup[key])
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Stage != out[j].Stage {
			return out[i].Stage < out[j].Stage
		}
		if out[i].Code != out[j].Code {
			return out[i].Code < out[j].Code
		}
		if out[i].Trigger != out[j].Trigger {
			return out[i].Trigger < out[j].Trigger
		}
		if out[i].PolicyRef != out[j].PolicyRef {
			return out[i].PolicyRef < out[j].PolicyRef
		}
		return out[i].VersionIdentity < out[j].VersionIdentity
	})
	return out
}

// Primary returns the stable primary explanation item.
func Primary(items []Item) (Item, bool) {
	if len(items) == 0 {
		return Item{}, false
	}
	return items[0], true
}

// BuildLegacyFacts is a compatibility bridge that maps free-text reasons[] to facts.
func BuildLegacyFacts(allowed bool, action string, reasons []string, stage string, policyRef string, versionIdentity string) []Fact {
	stage = normalizeStage(stage)
	decision := decisionFromAction(allowed, action)
	base := Fact{
		Decision:        decision,
		Stage:           stage,
		PolicyRef:       policyRef,
		VersionIdentity: versionIdentity,
	}

	if len(reasons) == 0 {
		base.Code = defaultCodeForDecision(decision)
		base.Fix = defaultFix(base.Code)
		return []Fact{base}
	}

	sortedReasons := append([]string(nil), reasons...)
	sort.Strings(sortedReasons)
	out := make([]Fact, 0, len(sortedReasons))
	for i := range sortedReasons {
		r := strings.TrimSpace(sortedReasons[i])
		if r == "" {
			continue
		}
		f := base
		f.Code = codeFromReason(r, decision)
		f.Trigger = r
		f.Fix = defaultFix(f.Code)
		out = append(out, f)
	}
	if len(out) == 0 {
		base.Code = defaultCodeForDecision(decision)
		base.Fix = defaultFix(base.Code)
		return []Fact{base}
	}
	return out
}

func normalizeFacts(facts []Fact) []Fact {
	out := make([]Fact, 0, len(facts))
	for i := range facts {
		f := facts[i]
		f.Code = strings.TrimSpace(f.Code)
		f.Decision = strings.TrimSpace(f.Decision)
		f.Stage = normalizeStage(f.Stage)
		f.Trigger = strings.TrimSpace(f.Trigger)
		f.Fix = strings.TrimSpace(f.Fix)
		f.PolicyRef = strings.TrimSpace(f.PolicyRef)
		f.VersionIdentity = strings.TrimSpace(f.VersionIdentity)

		if f.Decision == "" {
			f.Decision = decisionFromCode(f.Code)
		}
		if f.Code == "" {
			f.Code = defaultCodeForDecision(f.Decision)
		}
		if f.Fix == "" {
			f.Fix = defaultFix(f.Code)
		}
		out = append(out, f)
	}
	return out
}

func renderReason(f Fact) string {
	switch f.Code {
	case CodePolicyAllowed:
		return "Request allowed by policy."
	case CodePolicyDeniedPIIInput:
		return "Request blocked because input PII was detected."
	case CodePolicyDeniedPIIOutput:
		return "Request blocked because output PII was detected."
	case CodePolicyDeniedCost:
		return "Request blocked by cost policy limits."
	case CodePolicyDeniedRouting:
		return "Request blocked by model routing policy."
	case CodePolicyDeniedTool:
		return "Request blocked by tool access policy."
	case CodePolicyDeniedHook:
		return "Request blocked by a governance hook."
	case CodePolicyDeniedCircuit:
		return "Request blocked because the circuit breaker is open."
	case CodePolicyDeniedEarlyTerm:
		return "Request terminated early by governance controls."
	case CodePolicyModified:
		return "Request was modified by policy before execution."
	case CodePolicyFiltered:
		return "Request output was filtered by policy."
	case CodeExecutionFailed:
		return "Request failed during execution."
	case CodePolicyDenied:
		return "Request blocked by policy."
	default:
		return "Request processed with legacy policy explanation mapping."
	}
}

func normalizeStage(stage string) string {
	s := strings.TrimSpace(stage)
	if s == "" {
		return defaultStageName
	}
	return s
}

func decisionFromCode(code string) string {
	switch code {
	case CodePolicyAllowed:
		return DecisionAllow
	case CodePolicyModified:
		return DecisionModify
	case CodePolicyFiltered:
		return DecisionFilter
	case CodeExecutionFailed:
		return DecisionFailure
	default:
		return DecisionDeny
	}
}

func defaultCodeForDecision(decision string) string {
	switch decision {
	case DecisionAllow:
		return CodePolicyAllowed
	case DecisionModify:
		return CodePolicyModified
	case DecisionFilter:
		return CodePolicyFiltered
	case DecisionFailure:
		return CodeExecutionFailed
	default:
		return CodePolicyDenied
	}
}

func decisionFromAction(allowed bool, action string) string {
	if allowed {
		return DecisionAllow
	}
	a := strings.ToLower(strings.TrimSpace(action))
	switch {
	case strings.Contains(a, "modify"):
		return DecisionModify
	case strings.Contains(a, "filter"):
		return DecisionFilter
	case strings.Contains(a, "fail"), strings.Contains(a, "error"):
		return DecisionFailure
	default:
		return DecisionDeny
	}
}

func codeFromReason(reason string, decision string) string {
	r := strings.ToLower(strings.TrimSpace(reason))
	switch {
	case strings.Contains(r, "input contains pii"), strings.Contains(r, "block_on_pii"):
		return CodePolicyDeniedPIIInput
	case strings.Contains(r, "output contains pii"), strings.Contains(r, "block_on_output_pii"):
		return CodePolicyDeniedPIIOutput
	case strings.Contains(r, "cost"), strings.Contains(r, "budget"):
		return CodePolicyDeniedCost
	case strings.Contains(r, "routing"):
		return CodePolicyDeniedRouting
	case strings.Contains(r, "tool"), strings.Contains(r, "forbidden"):
		return CodePolicyDeniedTool
	case strings.Contains(r, "hook"):
		return CodePolicyDeniedHook
	case strings.Contains(r, "circuit_breaker"), strings.Contains(r, "circuit breaker"):
		return CodePolicyDeniedCircuit
	case strings.Contains(r, "early_termination"):
		return CodePolicyDeniedEarlyTerm
	default:
		if decision == DecisionAllow {
			return CodePolicyAllowed
		}
		return CodeLegacyReasonUnmigrated
	}
}

func defaultFix(code string) string {
	switch code {
	case CodePolicyDeniedPIIInput, CodePolicyDeniedPIIOutput:
		return "Remove or mask sensitive data before retrying the request."
	case CodePolicyDeniedCost:
		return "Reduce expected token usage or increase cost limits in policy."
	case CodePolicyDeniedRouting:
		return "Select a model/provider allowed by routing policy and data tier."
	case CodePolicyDeniedTool:
		return "Use an allowed tool or update tool policy allowlist."
	case CodePolicyDeniedHook:
		return "Review hook configuration and approval requirements."
	case CodePolicyDeniedCircuit:
		return "Wait for cooldown or resolve repeated denials before retrying."
	case CodeExecutionFailed:
		return "Inspect execution error details and retry when the dependency is healthy."
	default:
		return ""
	}
}
