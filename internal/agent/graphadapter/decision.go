package graphadapter

// Action is the control decision Talon returns to the external runtime
// after evaluating a governance event.
type Action string

const (
	ActionAllow         Action = "allow"
	ActionDeny          Action = "deny"
	ActionAbort         Action = "abort"
	ActionOverrideModel Action = "override_model"
	ActionMutateArgs    Action = "mutate_args"
	ActionRequireReview Action = "require_review"
	ActionRetry         Action = "retry"
)

// Decision is the control response returned for every governance event.
// External runtimes MUST respect deny/abort decisions. Override and mutate
// decisions carry replacement values the runtime should apply.
type Decision struct {
	Action  Action `json:"action"`
	Allowed bool   `json:"allowed"`

	Reasons []string `json:"reasons,omitempty"`

	OverrideModel string                 `json:"override_model,omitempty"`
	MutatedArgs   map[string]interface{} `json:"mutated_args,omitempty"`

	MaxRetries   int     `json:"max_retries,omitempty"`
	BudgetLeft   float64 `json:"budget_left,omitempty"`
	ReviewPlanID string  `json:"review_plan_id,omitempty"`

	EvidenceID string `json:"evidence_id,omitempty"`
}
