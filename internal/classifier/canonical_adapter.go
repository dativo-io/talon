package classifier

import (
	"github.com/dativo-io/talon/internal/classifier/entity"
)

// PIIEntitiesToCanonical converts a slice of PIIEntity from the scanner to
// detector-agnostic canonical entities for the enrichment pipeline. Ids are
// assigned sequentially (1-based). Source is set to entity.SourceCustom.
func PIIEntitiesToCanonical(entities []PIIEntity) []*entity.CanonicalEntity {
	if len(entities) == 0 {
		return nil
	}
	out := make([]*entity.CanonicalEntity, 0, len(entities))
	for i := range entities {
		e := &entities[i]
		out = append(out, &entity.CanonicalEntity{
			Id:          i + 1,
			Type:        e.Type,
			Raw:         e.Value,
			Start:       e.Position,
			End:         e.Position + len(e.Value),
			Source:      entity.SourceCustom,
			Confidence:  e.Confidence,
			Sensitivity: e.Sensitivity,
			Attributes:  nil,
		})
	}
	return out
}

// PresidioAnalyzerResult represents a single detection result from Microsoft Presidio.
type PresidioAnalyzerResult struct {
	Start      int     `json:"start"`
	End        int     `json:"end"`
	Score      float64 `json:"score"`
	EntityType string  `json:"entity_type"`
}

// PresidioAnalyzerResultsToCanonical converts Presidio analyzer results to detector-agnostic
// canonical entities. Ids are assigned sequentially (1-based). Source is set to entity.SourcePresidio.
func PresidioAnalyzerResultsToCanonical(text string, results []PresidioAnalyzerResult) []*entity.CanonicalEntity {
	if len(results) == 0 {
		return nil
	}
	out := make([]*entity.CanonicalEntity, 0, len(results))
	for i := range results {
		r := &results[i]
		raw := ""
		if r.Start >= 0 && r.End <= len(text) && r.Start <= r.End {
			raw = text[r.Start:r.End]
		}
		out = append(out, &entity.CanonicalEntity{
			Id:          i + 1,
			Type:        r.EntityType,
			Raw:         raw,
			Start:       r.Start,
			End:         r.End,
			Source:      entity.SourcePresidio,
			Confidence:  r.Score,
			Sensitivity: 1, // Presidio results default to sensitivity 1
			Attributes:  nil,
		})
	}
	return out
}
