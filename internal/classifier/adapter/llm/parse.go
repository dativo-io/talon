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

// ParseDetections extracts the {"entities":[...]} object from a model reply.
// Code fences and surrounding prose are tolerated (small local models often
// add them despite instructions); anything without a parseable entities
// object is an error — fail-closed, never "no PII found".
func ParseDetections(content string) ([]Detection, error) {
	payload := extractJSONObject(content)
	if payload == "" {
		return nil, errNotNERJSON
	}
	var resp nerResponse
	if err := json.Unmarshal([]byte(payload), &resp); err != nil {
		return nil, errNotNERJSON
	}
	if len(resp.Entities) > maxDetections {
		resp.Entities = resp.Entities[:maxDetections]
	}
	return resp.Entities, nil
}

// extractJSONObject returns the first top-level {...} object in s, stripping
// markdown code fences.
func extractJSONObject(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "```") {
		s = strings.TrimPrefix(s, "```json")
		s = strings.TrimPrefix(s, "```")
		if idx := strings.LastIndex(s, "```"); idx >= 0 {
			s = s[:idx]
		}
		s = strings.TrimSpace(s)
	}
	start := strings.Index(s, "{")
	if start < 0 {
		return ""
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
		case c == '{':
			depth++
		case c == '}':
			depth--
			if depth == 0 {
				return s[start : i+1]
			}
		}
	}
	return ""
}
