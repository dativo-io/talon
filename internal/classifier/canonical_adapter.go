package classifier

import (
	"github.com/dativo-io/talon/internal/classifier/entity"
)

// TODO(Presidio): Replaceable with Presidio — (1) Detection: swap the regex-based
// Scanner.Scan (pii.go + patterns/pii_eu.yaml + registry) for a Presidio analyzer
// call; (2) Adapter: add PresidioAnalyzerResultToCanonical(presidioResult) that
// maps Presidio spans to []*entity.CanonicalEntity (Id, Type, Raw, Start, End,
// Source=SourcePresidio, Confidence). The enricher, Rego policy, and placeholder
// renderer consume only canonical entities and require no changes.
//

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
