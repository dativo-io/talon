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
			FieldPath:   e.FieldPath,
			Source:      entity.SourceCustom,
			Confidence:  e.Confidence,
			Sensitivity: e.Sensitivity,
			Attributes:  nil,
		})
	}
	return out
}

// CanonicalToPIIEntities converts canonical entities back to scanner entities.
func CanonicalToPIIEntities(canonical []*entity.CanonicalEntity) []PIIEntity {
	if len(canonical) == 0 {
		return nil
	}
	out := make([]PIIEntity, 0, len(canonical))
	for _, c := range canonical {
		if c == nil {
			continue
		}
		out = append(out, PIIEntity{
			Type:        c.Type,
			Value:       c.Raw,
			Position:    c.Start,
			FieldPath:   c.FieldPath,
			Confidence:  c.Confidence,
			Sensitivity: c.Sensitivity,
		})
	}
	return out
}
