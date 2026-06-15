package presidio

import (
	"fmt"
)

const (
	// OffsetEncodingByte marks byte-based offsets.
	OffsetEncodingByte = "byte"
	// OffsetEncodingRune marks rune/character-based offsets.
	OffsetEncodingRune = "rune"
)

// RecognizerResult is a Presidio-compatible analyzer result shape used at Talon's
// external scanner boundary.
//
// Required fields:
//   - EntityType
//   - Start
//   - End
//   - Score
//
// Optional fields are normalized into canonical attributes.
type RecognizerResult struct {
	EntityType string  `json:"entity_type"`
	Start      int     `json:"start"`
	End        int     `json:"end"`
	Score      float64 `json:"score"`

	// OffsetEncoding controls how Start/End should be interpreted.
	// Defaults to byte offsets.
	OffsetEncoding string `json:"offset_encoding,omitempty"`

	// Optional explanation and metadata emitted by external analyzers.
	Explanation          string                 `json:"explanation,omitempty"`
	RecognitionMetadata  map[string]interface{} `json:"recognition_metadata,omitempty"`
	AnalysisExplanation  map[string]interface{} `json:"analysis_explanation,omitempty"`
	DetectorMetadata     map[string]interface{} `json:"detector_metadata,omitempty"`
	ProviderMetadata     map[string]interface{} `json:"provider_metadata,omitempty"`
	ExpectedSubstring    string                 `json:"expected_substring,omitempty"`
	ExpectedSensitivity  int                    `json:"expected_sensitivity,omitempty"`
	ExpectedConfidence   *float64               `json:"expected_confidence,omitempty"`
	OptionalRuneStart    *int                   `json:"rune_start,omitempty"`
	OptionalRuneEnd      *int                   `json:"rune_end,omitempty"`
	OptionalFieldPath    string                 `json:"field_path,omitempty"`
	OptionalSourceString string                 `json:"source,omitempty"`
}

// ValidateRequired validates required fields and supported offset encoding.
func (r RecognizerResult) ValidateRequired() error {
	if r.EntityType == "" {
		return fmt.Errorf("entity_type is required")
	}
	if r.Score < 0 || r.Score > 1 {
		return fmt.Errorf("score must be within [0,1], got %f", r.Score)
	}
	enc := r.OffsetEncoding
	if enc == "" {
		enc = OffsetEncodingByte
	}
	if enc != OffsetEncodingByte && enc != OffsetEncodingRune {
		return fmt.Errorf("offset_encoding must be %q or %q, got %q", OffsetEncodingByte, OffsetEncodingRune, enc)
	}
	return nil
}
