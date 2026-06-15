package presidio

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/dativo-io/talon/internal/classifier/entity"
)

// NormalizeResults converts Presidio-compatible recognizer results into Talon's
// canonical entities.
//
// Canonical semantics:
//   - Start/End in CanonicalEntity are byte offsets.
//   - Rune offsets are accepted only at this boundary and converted before
//     canonicalization.
//   - Invalid offsets fail fast.
func NormalizeResults(text string, results []RecognizerResult) ([]*entity.CanonicalEntity, error) {
	if len(results) == 0 {
		return nil, nil
	}

	out := make([]*entity.CanonicalEntity, 0, len(results))
	for i := range results {
		r := results[i]
		if err := r.ValidateRequired(); err != nil {
			return nil, fmt.Errorf("result[%d]: %w", i, err)
		}

		start, end, runeStart, runeEnd, err := normalizeOffsets(text, r)
		if err != nil {
			return nil, fmt.Errorf("result[%d]: %w", i, err)
		}
		if start < 0 {
			return nil, fmt.Errorf("result[%d]: start < 0", i)
		}
		if end > len(text) {
			return nil, fmt.Errorf("result[%d]: end > len(text)", i)
		}
		if start > end {
			return nil, fmt.Errorf("result[%d]: start > end", i)
		}

		raw := text[start:end]
		if r.ExpectedSubstring != "" && raw != r.ExpectedSubstring {
			return nil, fmt.Errorf("result[%d]: offset range does not map expected substring", i)
		}

		sensitivity := 1
		if r.ExpectedSensitivity >= 1 && r.ExpectedSensitivity <= 3 {
			sensitivity = r.ExpectedSensitivity
		}

		confidence := r.Score
		if r.ExpectedConfidence != nil {
			confidence = *r.ExpectedConfidence
		}

		out = append(out, &entity.CanonicalEntity{
			Id:          i + 1,
			Type:        EntityToCanonicalType(r.EntityType),
			Raw:         raw,
			Start:       start,
			End:         end,
			RuneStart:   runeStart,
			RuneEnd:     runeEnd,
			Source:      sourceForResult(r),
			Confidence:  confidence,
			Sensitivity: sensitivity,
			FieldPath:   r.OptionalFieldPath,
			Attributes:  normalizeAttributes(r),
		})
	}
	return out, nil
}

func normalizeOffsets(text string, r RecognizerResult) (start int, end int, runeStart *int, runeEnd *int, err error) {
	enc := r.OffsetEncoding
	if enc == "" {
		enc = OffsetEncodingByte
	}
	switch enc {
	case OffsetEncodingByte:
		start = r.Start
		end = r.End
		if r.OptionalRuneStart != nil {
			v := *r.OptionalRuneStart
			runeStart = &v
		}
		if r.OptionalRuneEnd != nil {
			v := *r.OptionalRuneEnd
			runeEnd = &v
		}
		return start, end, runeStart, runeEnd, nil

	case OffsetEncodingRune:
		if boundarySplitsCombiningSequence(text, r.Start) {
			return 0, 0, nil, nil, fmt.Errorf("rune start splits combining sequence")
		}
		if boundarySplitsCombiningSequence(text, r.End) {
			return 0, 0, nil, nil, fmt.Errorf("rune end splits combining sequence")
		}

		startByte, convErr := runeIndexToByteOffset(text, r.Start)
		if convErr != nil {
			return 0, 0, nil, nil, fmt.Errorf("converting rune start: %w", convErr)
		}
		endByte, convErr := runeIndexToByteOffset(text, r.End)
		if convErr != nil {
			return 0, 0, nil, nil, fmt.Errorf("converting rune end: %w", convErr)
		}

		rs := r.Start
		re := r.End
		return startByte, endByte, &rs, &re, nil
	default:
		return 0, 0, nil, nil, fmt.Errorf("unsupported offset encoding: %s", enc)
	}
}

func boundarySplitsCombiningSequence(text string, runeBoundary int) bool {
	if runeBoundary <= 0 {
		return false
	}
	runes := []rune(text)
	if runeBoundary >= len(runes) {
		return false
	}
	r := runes[runeBoundary]
	return unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Mc, r) || unicode.Is(unicode.Me, r)
}

func runeIndexToByteOffset(text string, idx int) (int, error) {
	if idx < 0 {
		return 0, fmt.Errorf("start < 0")
	}
	if idx == 0 {
		return 0, nil
	}
	runes := 0
	for i := range text {
		if runes == idx {
			return i, nil
		}
		runes++
	}
	if runes == idx {
		return len(text), nil
	}
	return 0, fmt.Errorf("end > len(text)")
}

func normalizeAttributes(r RecognizerResult) map[string]string {
	attrs := map[string]string{}
	if r.Explanation != "" {
		attrs["explanation"] = r.Explanation
	}
	addMapAttributes(attrs, "recognition_metadata", r.RecognitionMetadata)
	addMapAttributes(attrs, "analysis_explanation", r.AnalysisExplanation)
	addMapAttributes(attrs, "detector_metadata", r.DetectorMetadata)
	addMapAttributes(attrs, "provider_metadata", r.ProviderMetadata)
	if len(attrs) == 0 {
		return nil
	}
	return attrs
}

func addMapAttributes(attrs map[string]string, prefix string, m map[string]interface{}) {
	if len(m) == 0 {
		return
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		attrs[prefix+"."+k] = stringifyMetadataValue(m[k])
	}
}

func stringifyMetadataValue(v interface{}) string {
	if v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case []byte:
		return string(t)
	}
	b, err := json.Marshal(v)
	if err == nil {
		return string(b)
	}
	return fmt.Sprintf("%v", v)
}

func sourceForResult(r RecognizerResult) string {
	if s := strings.TrimSpace(r.OptionalSourceString); s != "" {
		return s
	}
	return entity.SourcePresidio
}

var presidioEntityTypeMap = map[string]string{
	"EMAIL_ADDRESS":   "email",
	"PHONE_NUMBER":    "phone",
	"IBAN_CODE":       "iban",
	"CREDIT_CARD":     "credit_card",
	"EU_VAT_ID":       "vat_id",
	"DE_SSN":          "ssn",
	"UK_NINO":         "ssn",
	"FR_SSN":          "ssn",
	"IP_ADDRESS":      "ip_address",
	"PASSPORT":        "passport",
	"DE_ID_CARD":      "national_id",
	"DE_TAX_ID":       "tax_id",
	"FR_NIR":          "ssn",
	"FR_ID_CARD":      "national_id",
	"NL_BSN":          "national_id",
	"PL_PESEL":        "national_id",
	"PL_NIP":          "tax_id",
	"ES_DNI":          "national_id",
	"ES_NIE":          "national_id",
	"BE_NATIONAL_ID":  "national_id",
	"AT_SVN":          "national_id",
	"SE_PERSONNUMMER": "national_id",
	"DK_CPR":          "national_id",
	"IE_PPS":          "national_id",
	"PT_NIF":          "tax_id",
	"IMSI":            "imsi",
	"ICCID":           "iccid",
	"EID":             "eid",
	"PERSON":          "person",
	"LOCATION":        "location",
}

// EntityToCanonicalType maps a Presidio entity_type label to Talon's internal type string.
func EntityToCanonicalType(entityName string) string {
	if mapped, ok := presidioEntityTypeMap[entityName]; ok {
		return mapped
	}
	return toLowerSnake(entityName)
}

func toLowerSnake(s string) string {
	if s == "" {
		return s
	}
	var out strings.Builder
	out.Grow(len(s))
	lastUnderscore := false
	for s != "" {
		r, size := utf8.DecodeRuneInString(s)
		s = s[size:]
		switch {
		case r == ' ' || r == '-' || r == '.':
			if !lastUnderscore {
				out.WriteRune('_')
				lastUnderscore = true
			}
		case r >= 'A' && r <= 'Z':
			out.WriteRune(r + ('a' - 'A'))
			lastUnderscore = false
		default:
			out.WriteRune(unicode.ToLower(r))
			lastUnderscore = false
		}
	}
	return strings.Trim(out.String(), "_")
}
