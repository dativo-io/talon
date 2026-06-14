// Package entity provides a detector-agnostic canonical representation of PII
// entities for use by the semantic enricher and placeholder renderer. This
// abstraction allows the enrichment pipeline to work with either the current
// custom detector or a future Presidio adapter.
package entity

// Source identifies the detector that produced the entity.
const (
	SourceCustom   = "custom"
	SourcePresidio = "presidio"
)

// CanonicalEntity is a detector-agnostic PII entity used by the enrichment
// pipeline and renderer. Attributes are filled by the semantic enricher and
// governed by Rego policy before rendering.
type CanonicalEntity struct {
	Id          int               `json:"id"`
	Type        string            `json:"type"`
	Raw         string            `json:"raw"`
	Start       int               `json:"start"`
	End         int               `json:"end"`
	RuneStart   *int              `json:"rune_start,omitempty"`
	RuneEnd     *int              `json:"rune_end,omitempty"`
	FieldPath   string            `json:"field_path,omitempty"`
	Source      string            `json:"source"`
	Confidence  float64           `json:"confidence"`
	Sensitivity int               `json:"sensitivity"` // 1-3 from recognizer; used for overlap resolution
	Attributes  map[string]string `json:"attributes,omitempty"`
}
