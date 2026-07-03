package llm

import (
	"encoding/json"
	"errors"
	"strings"
)

// Detection is one entity the model reported: a type label and the verbatim
// value it claims appears in the text. Offsets are never accepted from the
// model — relocation computes them.
type Detection struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type nerResponse struct {
	Entities []Detection `json:"entities"`
}

// maxDetections bounds how many reported entities are processed per scan —
// a runaway/adversarial model must not amplify work (untrusted input).
const maxDetections = 256

var errNotNERJSON = errors.New("model response is not the expected entities JSON object")

// ParseDetections extracts the model's detections from its reply. The prompt
// demands {"entities":[...]}, but small models under JSON mode degenerate in
// known structured ways that are still unambiguous detections — a bare
// top-level array ([] or [{"type":...}], observed deterministically from
// llama3.2:1b on placeholder-only verify re-scans) — so both shapes are
// accepted. Code fences and surrounding prose are tolerated. Anything without
// a parseable JSON value is an error — fail-closed, never "no PII found".
func ParseDetections(content string) ([]Detection, error) {
	payload := extractJSONValue(content)
	if payload == "" {
		return nil, errNotNERJSON
	}
	var dets []Detection
	if strings.HasPrefix(payload, "[") {
		if err := json.Unmarshal([]byte(payload), &dets); err != nil {
			return nil, errNotNERJSON
		}
	} else {
		var resp nerResponse
		if err := json.Unmarshal([]byte(payload), &resp); err != nil {
			return nil, errNotNERJSON
		}
		dets = resp.Entities
	}
	if len(dets) > maxDetections {
		dets = dets[:maxDetections]
	}
	return dets, nil
}

// extractJSONValue returns the first top-level {...} object or [...] array in
// s, stripping markdown code fences.
func extractJSONValue(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "```") {
		s = strings.TrimPrefix(s, "```json")
		s = strings.TrimPrefix(s, "```")
		if idx := strings.LastIndex(s, "```"); idx >= 0 {
			s = s[:idx]
		}
		s = strings.TrimSpace(s)
	}
	start := strings.IndexAny(s, "{[")
	if start < 0 {
		return ""
	}
	open, closing := byte('{'), byte('}')
	if s[start] == '[' {
		open, closing = '[', ']'
	}
	depth := 0
	inString := false
	escaped := false
	for i := start; i < len(s); i++ {
		c := s[i]
		switch {
		case escaped:
			escaped = false
		case inString && c == '\\':
			escaped = true
		case c == '"':
			inString = !inString
		case inString:
		case c == open:
			depth++
		case c == closing:
			depth--
			if depth == 0 {
				return s[start : i+1]
			}
		}
	}
	return ""
}
