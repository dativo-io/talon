package action

import (
	"encoding/json"
	"time"
)

// Operator inspection (#427). ONE safe projection of the compiled catalog
// shared by every operator surface (CLI list/show/validate today, API
// later), so no surface can invent its own view. It carries identities,
// digests, classifications and safe references only: never credentials,
// sealed payloads or protected data.

// CatalogView is the safe projection of one compiled catalog.
type CatalogView struct {
	Digest  string           `json:"catalog_digest"`
	Sources []SourceView     `json:"sources"`
	Actions []DefinitionView `json:"actions"`
}

// SourceView is the safe projection of one trusted source.
type SourceView struct {
	ID                 string             `json:"id"`
	Type               string             `json:"type"`
	URL                string             `json:"url"`
	ConfigDigest       string             `json:"config_digest"`
	Generation         string             `json:"generation"`
	ServerInfo         SourceServerInfo   `json:"server_info"`
	SupportedVersions  []string           `json:"supported_versions,omitempty"`
	Capabilities       SourceCapabilities `json:"capabilities"`
	CapabilitiesDigest string             `json:"capabilities_digest"`
	TTLMs              json.Number        `json:"ttl_ms"`
	CacheScope         string             `json:"cache_scope"`
	DiscoveredAt       time.Time          `json:"discovered_at"`
	RefreshAt          time.Time          `json:"refresh_at"`
	ToolCount          int                `json:"tool_count"`
	Excluded           []ExcludedTool     `json:"excluded,omitempty"`
}

// SourceRef is the source identity a definition carries.
type SourceRef struct {
	Type         string `json:"type"`
	ID           string `json:"id,omitempty"`
	ConfigDigest string `json:"config_digest,omitempty"`
	Generation   string `json:"generation,omitempty"`
}

// ReviewView is the reviewer classification of a definition.
type ReviewView struct {
	Fields      []string `json:"fields"`
	NonMaterial []string `json:"non_material,omitempty"`
}

// DestinationView is the safe destination reference of a definition.
type DestinationView struct {
	Type               string `json:"type"`
	URL                string `json:"url"`
	Method             string `json:"method,omitempty"`
	SuccessStatusCodes []int  `json:"success_status_codes,omitempty"`
}

// ApprovalRuleView is one approval rule that matches a definition.
type ApprovalRuleView struct {
	ID string `json:"id"`
	// Source is the layer that declared the rule: company | use_case (#425).
	Source         string   `json:"source"`
	ApproverGroups []string `json:"approver_groups"`
}

// ArgumentRuleView is one argument rule (#205) that applies to a definition:
// the condition, its restrictive effect and the layer that declared it.
type ArgumentRuleView struct {
	ID string `json:"id"`
	// Source is the layer that declared the rule: company | use_case.
	Source   string `json:"source"`
	Argument string `json:"argument"`
	Type     string `json:"type"`
	Operator string `json:"operator"`
	// Value is the operand in its normalized text form.
	Value string `json:"value"`
	// Condition is "<argument> <operator> <value>".
	Condition string `json:"condition"`
	// Effect is require_approval | deny.
	Effect         string   `json:"effect"`
	ApproverGroups []string `json:"approver_groups,omitempty"`
}

// Decision bases of a definition's verdict.
const (
	// DecisionByName: the verdict is the same for every call of the action.
	DecisionByName = "name"
	// DecisionByArguments: argument rules apply; the verdict of a call
	// depends on its arguments and can be stricter than Verdict.
	DecisionByArguments = "arguments"
)

// DefinitionView is the safe projection of one definition.
type DefinitionView struct {
	Name             string          `json:"name"`
	Description      string          `json:"description,omitempty"`
	Source           SourceRef       `json:"source"`
	UpstreamName     string          `json:"upstream_name,omitempty"`
	SchemaDigest     string          `json:"schema_digest"`
	Schema           json.RawMessage `json:"schema"`
	Properties       []string        `json:"properties"`
	Review           ReviewView      `json:"review"`
	ProjectionDigest string          `json:"projection_digest"`
	MirroredParams   []MirroredParam `json:"mirrored_params,omitempty"`
	Title            string          `json:"title,omitempty"`
	Hints            *ToolHints      `json:"hints,omitempty"`
	OutputSchema     json.RawMessage `json:"output_schema,omitempty"`
	BindingProfile   string          `json:"binding_profile"`
	ExecutionProfile string          `json:"execution_profile"`
	Destination      DestinationView `json:"destination"`
	DestinationID    string          `json:"destination_id"`
	DefinitionDigest string          `json:"definition_digest"`
	MetadataDigest   string          `json:"metadata_digest"`
	Verdict          string          `json:"verdict,omitempty"`
	// VerdictSource names the layer whose rule produced a DENY or
	// REQUIRE_APPROVAL verdict (company | use_case); absent for ALLOW.
	VerdictSource string             `json:"verdict_source,omitempty"`
	ApprovalRules []ApprovalRuleView `json:"approval_rules,omitempty"`
	// DecisionBasis says whether Verdict is the verdict of every call
	// ("name") or only the baseline before argument rules ("arguments"):
	// with argument rules a call can be stricter than Verdict, never looser.
	// A consumer must not read a name-only ALLOW as unconditional.
	DecisionBasis string `json:"decision_basis"`
	// ArgumentRules are the argument rules that apply to this action.
	ArgumentRules []ArgumentRuleView `json:"argument_rules,omitempty"`
}

// View projects the whole catalog. ap may be nil (no approval policy
// context); then verdicts and rules are omitted.
func (c *Catalog) View(ap *ApprovalPolicy) CatalogView {
	v := CatalogView{Sources: []SourceView{}, Actions: []DefinitionView{}}
	if c == nil {
		return v
	}
	v.Digest = c.Digest
	for i := range c.sources {
		v.Sources = append(v.Sources, SourceView(c.sources[i]))
	}
	for _, n := range c.names {
		dv, _ := c.DefinitionView(n, ap)
		v.Actions = append(v.Actions, dv)
	}
	return v
}

// DefinitionView projects one definition by canonical name.
func (c *Catalog) DefinitionView(name string, ap *ApprovalPolicy) (DefinitionView, bool) {
	d, ok := c.Lookup(name)
	if !ok {
		return DefinitionView{}, false
	}
	dv := DefinitionView{
		Name:        d.Name,
		Description: d.Description,
		Source: SourceRef{
			Type: d.Source.Type, ID: d.Source.ID, ConfigDigest: d.Source.ConfigDigest, Generation: d.Source.Generation,
		},
		UpstreamName:     d.UpstreamName,
		SchemaDigest:     d.SchemaDigest,
		Schema:           append(json.RawMessage(nil), d.Schema...),
		Properties:       append([]string{}, d.Properties...),
		Review:           ReviewView{Fields: append([]string{}, d.Review.Shown...), NonMaterial: append([]string(nil), d.Review.NonMaterial...)},
		ProjectionDigest: d.ProjectionDigest,
		MirroredParams:   append([]MirroredParam(nil), d.MirroredParams...),
		Title:            d.Title,
		Hints:            cloneHints(d.Hints),
		OutputSchema:     append(json.RawMessage(nil), d.OutputSchema...),
		BindingProfile:   d.BindingProfile,
		ExecutionProfile: d.ExecutionProfile,
		Destination: DestinationView{
			Type: d.Destination.Type, URL: d.Destination.URL, Method: d.Destination.Method,
			SuccessStatusCodes: append([]int(nil), d.Destination.SuccessStatusCodes...),
		},
		DestinationID:    d.DestinationID,
		DefinitionDigest: d.DefinitionDigest,
		MetadataDigest:   d.MetadataDigest,
	}
	if ap != nil {
		dec := ap.Decision(d.Name)
		dv.Verdict, dv.VerdictSource, dv.DecisionBasis = dec.Verdict, dec.VerdictSource, dec.DecisionBasis
		dv.ApprovalRules, dv.ArgumentRules = dec.ApprovalRules, dec.ArgumentRules
	}
	return dv, true
}

// DecisionView is the policy's answer for one action NAME: the baseline
// verdict, whether a call's arguments can make it stricter, and every rule
// that applies with the layer that declared it. It is the one projection
// behind `talon actions`, `talon agents show --effective` and the console.
type DecisionView struct {
	Action        string             `json:"action"`
	Verdict       string             `json:"verdict"`
	VerdictSource string             `json:"verdict_source,omitempty"`
	DecisionBasis string             `json:"decision_basis"`
	ApprovalRules []ApprovalRuleView `json:"approval_rules,omitempty"`
	ArgumentRules []ArgumentRuleView `json:"argument_rules,omitempty"`
}

// Decision projects the policy for one action name.
func (ap *ApprovalPolicy) Decision(name string) DecisionView {
	v := ap.Evaluate(name)
	out := DecisionView{Action: name, Verdict: v.Outcome, VerdictSource: v.Source, DecisionBasis: DecisionByName}
	for _, r := range ap.MatchingRules(name) {
		out.ApprovalRules = append(out.ApprovalRules, ApprovalRuleView{ID: r.ID, Source: r.Source, ApproverGroups: append([]string(nil), r.ApproverGroups...)})
	}
	argRules := ap.MatchingArgumentRules(name)
	for i := range argRules {
		out.ArgumentRules = append(out.ArgumentRules, argRules[i].view())
	}
	if len(argRules) > 0 && v.Outcome != VerdictDeny {
		out.DecisionBasis = DecisionByArguments
	}
	return out
}

func (r *ArgumentRule) view() ArgumentRuleView {
	return ArgumentRuleView{
		ID: r.ID, Source: r.Source, Argument: r.Argument, Type: r.Type, Operator: r.Operator, Value: r.Value,
		Condition: r.Condition(), Effect: r.Effect, ApproverGroups: append([]string(nil), r.ApproverGroups...),
	}
}

// ArgumentRuleWithActions is one argument rule and the action patterns it
// applies to.
type ArgumentRuleWithActions struct {
	ArgumentRuleView
	Actions []string
}

// ArgumentRuleViews projects every argument rule of the policy, company
// rules first.
func (ap *ApprovalPolicy) ArgumentRuleViews() []ArgumentRuleWithActions {
	out := make([]ArgumentRuleWithActions, 0, len(ap.ArgumentRules))
	for i := range ap.ArgumentRules {
		r := &ap.ArgumentRules[i]
		out = append(out, ArgumentRuleWithActions{ArgumentRuleView: r.view(), Actions: append([]string(nil), r.Actions...)})
	}
	return out
}
