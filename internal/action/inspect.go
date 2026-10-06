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
	ID                string           `json:"id"`
	Type              string           `json:"type"`
	URL               string           `json:"url"`
	ConfigDigest      string           `json:"config_digest"`
	Generation        string           `json:"generation"`
	ServerInfo        SourceServerInfo `json:"server_info"`
	SupportedVersions []string         `json:"supported_versions,omitempty"`
	TTLMs             json.Number      `json:"ttl_ms"`
	CacheScope        string           `json:"cache_scope"`
	DiscoveredAt      time.Time        `json:"discovered_at"`
	RefreshAt         time.Time        `json:"refresh_at"`
	ToolCount         int              `json:"tool_count"`
	Excluded          []ExcludedTool   `json:"excluded,omitempty"`
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
	ID             string   `json:"id"`
	ApproverGroups []string `json:"approver_groups"`
}

// DefinitionView is the safe projection of one definition.
type DefinitionView struct {
	Name             string             `json:"name"`
	Description      string             `json:"description,omitempty"`
	Source           SourceRef          `json:"source"`
	UpstreamName     string             `json:"upstream_name,omitempty"`
	SchemaDigest     string             `json:"schema_digest"`
	Schema           json.RawMessage    `json:"schema"`
	Properties       []string           `json:"properties"`
	Review           ReviewView         `json:"review"`
	ProjectionDigest string             `json:"projection_digest"`
	MirroredParams   []MirroredParam    `json:"mirrored_params,omitempty"`
	BindingProfile   string             `json:"binding_profile"`
	ExecutionProfile string             `json:"execution_profile"`
	Destination      DestinationView    `json:"destination"`
	DestinationID    string             `json:"destination_id"`
	DefinitionDigest string             `json:"definition_digest"`
	MetadataDigest   string             `json:"metadata_digest"`
	Verdict          string             `json:"verdict,omitempty"`
	ApprovalRules    []ApprovalRuleView `json:"approval_rules,omitempty"`
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
		dv.Verdict = ap.Evaluate(d.Name).Outcome
		for _, r := range ap.MatchingRules(d.Name) {
			dv.ApprovalRules = append(dv.ApprovalRules, ApprovalRuleView{ID: r.ID, ApproverGroups: append([]string(nil), r.ApproverGroups...)})
		}
	}
	return dv, true
}
